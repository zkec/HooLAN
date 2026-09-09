// Package logstream holds a bounded, redacted feed for dashboard SSE clients.
package logstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxEntries       = 512
	maxSubscribers   = 32
	subscriberBuffer = 64
	maxMessageBytes  = 4096
)

// Entry is the stable wire format used by the live log viewer.
type Entry struct {
	ID      uint64    `json:"id"`
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
}

var ErrUnavailable = errors.New("log stream capacity reached or service shutting down")

type Hub struct {
	mu      sync.Mutex
	entries []Entry
	next    uint64
	subs    map[chan Entry]struct{}
	secrets []string
	closed  bool
}

func New(secrets ...string) *Hub {
	filtered := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			filtered = append(filtered, secret)
		}
	}
	return &Hub{entries: make([]Entry, 0, maxEntries), subs: make(map[chan Entry]struct{}), secrets: filtered}
}

var (
	uriPattern        = regexp.MustCompile(`(?i)\b(?:https?|vless|vmess|ss|ssr|trojan|hysteria2?|hy2|tuic|socks5?)://[^\s<>"']+`)
	credentialPattern = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|uuid|authorization)(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
	bearerPattern     = regexp.MustCompile(`(?i)\bBearer\s+[^\s,;]+`)
	uuidPattern       = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	ansiPattern       = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")
)

func (h *Hub) redact(s string) string {
	for _, secret := range h.secrets {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	s = ansiPattern.ReplaceAllString(s, "")
	s = uriPattern.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err == nil && (strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")) && u.Host != "" {
			// Subscription credentials may appear in userinfo, query OR path.
			return u.Scheme + "://" + u.Host + "/[redacted]"
		}
		return "[redacted node URI]"
	})
	s = credentialPattern.ReplaceAllString(s, "$1$2[redacted]")
	s = bearerPattern.ReplaceAllString(s, "Bearer [redacted]")
	s = uuidPattern.ReplaceAllString(s, "[redacted UUID]")
	if len(s) > maxMessageBytes {
		s = s[:maxMessageBytes]
		for !utf8.ValidString(s) && len(s) > 0 {
			s = s[:len(s)-1]
		}
		s += "…"
	}
	return s
}

func (h *Hub) Publish(level, source, message string) {
	entry := Entry{Time: time.Now().UTC(), Level: h.redact(level), Source: h.redact(source), Message: h.redact(message)}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.next++
	entry.ID = h.next
	if len(h.entries) == maxEntries {
		copy(h.entries, h.entries[1:])
		h.entries[len(h.entries)-1] = entry
	} else {
		h.entries = append(h.entries, entry)
	}
	for ch := range h.subs {
		select {
		case ch <- entry:
		default:
			// A slow browser must never block Go service or engine log writers.
			delete(h.subs, ch)
			close(ch)
		}
	}
}

// Subscribe snapshots replay and attaches a subscriber under the same lock, so
// no event can disappear between history replay and live delivery. Old cursors
// replay the retained window. A cursor beyond this process's ID resets to zero.
func (h *Hub) Subscribe(after uint64) ([]Entry, <-chan Entry, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || len(h.subs) >= maxSubscribers {
		return nil, nil, nil, ErrUnavailable
	}
	if after > h.next {
		after = 0
	}
	history := make([]Entry, 0, len(h.entries))
	for _, entry := range h.entries {
		if entry.ID > after {
			history = append(history, entry)
		}
	}
	ch := make(chan Entry, subscriberBuffer)
	h.subs[ch] = struct{}{}
	cancel := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
	}
	return history, ch, cancel, nil
}

func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for ch := range h.subs {
		delete(h.subs, ch)
		close(ch)
	}
}

// TeeHandler preserves the configured journald handler and mirrors records to
// the redacted browser feed. Existing engine stdout/stderr slog forwarding is
// captured automatically, including src=sing-box.
type TeeHandler struct {
	base   slog.Handler
	hub    *Hub
	attrs  []slog.Attr
	groups []string
}

func NewTeeHandler(base slog.Handler, hub *Hub) *TeeHandler { return &TeeHandler{base: base, hub: hub} }
func (h *TeeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}
func (h *TeeHandler) Handle(ctx context.Context, record slog.Record) error {
	source := "service"
	message := record.Message
	var appendAttr func(string, slog.Attr)
	appendAttr = func(prefix string, attr slog.Attr) {
		value := attr.Value.Resolve()
		if value.Kind() == slog.KindGroup {
			if attr.Key != "" {
				prefix += attr.Key + "."
			}
			for _, child := range value.Group() {
				appendAttr(prefix, child)
			}
			return
		}
		if attr.Key == "src" {
			source = value.String()
			return
		}
		key := strings.ToLower(attr.Key)
		if strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "token") || key == "authorization" || key == "uuid" {
			message += " " + prefix + attr.Key + "=[redacted]"
		} else {
			message += fmt.Sprintf(" %s%s=%v", prefix, attr.Key, value.Any())
		}
	}
	for _, attr := range h.attrs {
		appendAttr("", attr)
	}
	prefix := ""
	if len(h.groups) > 0 {
		prefix = strings.Join(h.groups, ".") + "."
	}
	record.Attrs(func(attr slog.Attr) bool { appendAttr(prefix, attr); return true })
	h.hub.Publish(record.Level.String(), source, message)
	return h.base.Handle(ctx, record)
}

func (h *TeeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copyHandler := *h
	copyHandler.base = h.base.WithAttrs(attrs)
	wrapped := append([]slog.Attr(nil), attrs...)
	for i := len(h.groups) - 1; i >= 0; i-- {
		wrapped = []slog.Attr{{Key: h.groups[i], Value: slog.GroupValue(wrapped...)}}
	}
	copyHandler.attrs = append(append([]slog.Attr(nil), h.attrs...), wrapped...)
	return &copyHandler
}
func (h *TeeHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	copyHandler := *h
	copyHandler.base = h.base.WithGroup(name)
	copyHandler.groups = append(append([]string(nil), h.groups...), name)
	return &copyHandler
}
