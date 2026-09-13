package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"proxy-manager/internal/store"
	"proxy-manager/internal/subscription"
	"regexp"
	"time"
)

type TelegramSettings struct {
	Enabled  bool   `json:"enabled"`
	UseProxy bool   `json:"use_proxy"`
	Token    string `json:"token"`
	ChatID   string `json:"chat_id"`
}

var botTokenPattern = regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{20,100}$`)
var chatIDPattern = regexp.MustCompile(`^(?:-?[0-9]{1,20}|@[A-Za-z0-9_]{5,64})$`)

func validateTelegram(v TelegramSettings) error {
	if v.Token != "" && !botTokenPattern.MatchString(v.Token) {
		return fmt.Errorf("%w: invalid Telegram bot token", ErrInvalidInput)
	}
	if v.ChatID != "" && !chatIDPattern.MatchString(v.ChatID) {
		return fmt.Errorf("%w: invalid Telegram chat ID", ErrInvalidInput)
	}
	if v.Enabled && (v.Token == "" || v.ChatID == "") {
		return fmt.Errorf("%w: Telegram token and chat ID are required", ErrInvalidInput)
	}
	return nil
}
func sendTelegram(ctx context.Context, client *http.Client, cfg TelegramSettings, message string) error {
	body, _ := json.Marshal(map[string]any{"chat_id": cfg.ChatID, "text": message, "link_preview_options": map[string]bool{"is_disabled": true}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+cfg.Token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid Telegram request")
	}
	req.Header.Set("Content-Type", "application/json")
	safe := *client
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := safe.Do(req)
	if err != nil {
		return errors.New("Telegram delivery failed (network or timeout)")
	} // never log URL/token
	defer resp.Body.Close()
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return errors.New("invalid Telegram response")
	}
	if resp.StatusCode != 200 || !result.OK {
		return fmt.Errorf("Telegram rejected notification (HTTP %d)", resp.StatusCode)
	}
	return nil
}
func (s *Service) telegram(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		defer s.mu.RUnlock()
		v := s.state.Telegram
		writeJSON(w, 200, map[string]any{"enabled": v.Enabled, "use_proxy": v.UseProxy, "chat_id": v.ChatID, "token_set": v.Token != "", "last_error": s.telegramError})
	case http.MethodPut:
		var req struct {
			Enabled  bool    `json:"enabled"`
			UseProxy *bool   `json:"use_proxy"`
			Token    *string `json:"token"`
			ChatID   string  `json:"chat_id"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		s.opMu.Lock()
		defer s.opMu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		old := s.state.Telegram
		next := TelegramSettings{Enabled: req.Enabled, ChatID: req.ChatID, Token: old.Token, UseProxy: old.UseProxy}
		if req.UseProxy != nil {
			next.UseProxy = *req.UseProxy
		}
		if req.Token != nil {
			next.Token = *req.Token
		}
		if err := validateTelegram(next); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		s.state.Telegram = next
		if err := s.saveState(); err != nil {
			s.state.Telegram = old
			writeError(w, 500, "could not save notification settings")
			return
		}
		s.telegramError = ""
		writeJSON(w, 200, map[string]string{"message": "Notification settings saved"})
	default:
		methodsNotAllowed(w, "GET, PUT")
	}
}

// Notifications are best-effort and never hold up engine or firewall operations.
func (s *Service) notify(message string) {
	s.mu.RLock()
	enabled := s.state.Telegram.Enabled && !s.closing
	s.mu.RUnlock()
	if !enabled {
		return
	}
	select {
	case s.notifications <- message:
	default:
		s.log.Warn("notification queue full; alert dropped")
	}
}
func (s *Service) startNotifications() {
	s.mu.Lock()
	if s.notificationsStarted || s.closing {
		s.mu.Unlock()
		return
	}
	s.notificationsStarted = true
	s.jobs.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.jobs.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.jobCtx.Done():
				return
			case msg := <-s.notifications:
				s.mu.RLock()
				cfg := s.state.Telegram
				s.mu.RUnlock()
				if !cfg.Enabled {
					continue
				}
				ctx, cancel := context.WithTimeout(s.jobCtx, 30*time.Second)
				err := s.deliverTelegram(ctx, cfg, msg)
				cancel()
				s.recordTelegramResult(err)
			case <-ticker.C:
				s.checkActiveNode()
			}
		}
	}()
}
func (s *Service) activeNodeID(ctx context.Context) string {
	choice := s.selection(ctx)
	if !choice.Auto {
		return choice.NodeID
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, tag := range s.tagByID {
		if tag == choice.AutoPick {
			return id
		}
	}
	return ""
}
func (s *Service) checkActiveNode() {
	s.mu.RLock()
	enabled := s.state.Telegram.Enabled && s.proxyEnabled && !s.refreshing
	s.mu.RUnlock()
	if !enabled || s.cfg.Tester == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.jobCtx, 3*time.Second)
	id := s.activeNodeID(ctx)
	cancel()
	if id == "" {
		return
	}
	_, _ = s.startJob(JobStatus{Kind: "health", NodeID: id}, func(ctx context.Context) error {
		err := s.testSelectedNodes(ctx, map[string]bool{id: true})
		if err != nil {
			return err
		}
		rec, err := s.cfg.Store.Get(id)
		if err != nil {
			return err
		}
		if ctx.Err() != nil || s.activeNodeID(ctx) != id {
			return nil
		}
		s.mu.Lock()
		previous := s.failedActive
		s.failedActive = ""
		failed := !rec.Healthy()
		if failed {
			s.failedActive = id
		}
		s.mu.Unlock()
		if failed && previous != id {
			s.notify(fmt.Sprintf("Active node failed its background latency check: %s", rec.Node.Tag))
		}
		return nil
	})
}

// Shutdown has already cancelled the worker; make one bounded final attempt.
func (s *Service) notifyShutdown(ctx context.Context) {
	s.mu.RLock()
	cfg := s.state.Telegram
	s.mu.RUnlock()
	if !cfg.Enabled {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.deliverTelegram(ctx, cfg, "Proxy engine stopped during service shutdown."); err != nil {
		s.log.Warn("shutdown notification was not delivered", "err", err)
	}
}

func (s *Service) recordTelegramResult(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telegramError = ""
	if err != nil {
		s.telegramError = err.Error()
	}
}

// Direct means no application proxy, including HTTP(S)_PROXY environment
// variables. Proxy delivery has no direct fallback and uses a separate engine,
// so it remains possible after the production engine is stopped.
func (s *Service) deliverTelegram(ctx context.Context, cfg TelegramSettings, message string) error {
	if !cfg.UseProxy {
		client := s.cfg.NotificationClient
		if client == nil {
			transport := directTelegramTransport()
			defer transport.CloseIdleConnections()
			client = &http.Client{Transport: transport}
		}
		return sendTelegram(ctx, client, cfg, message)
	}
	proxy, ok := s.cfg.Tester.(interface {
		WithProxyClient(context.Context, subscription.Node, []subscription.Node, func(*http.Client) error) error
	})
	if !ok {
		return errors.New("Telegram proxy transport is unavailable")
	}
	choice := s.selection(ctx)
	targetID := choice.NodeID
	if choice.Auto {
		targetID = ""
		s.mu.RLock()
		for id, tag := range s.tagByID {
			if tag == choice.AutoPick && choice.AutoPick != "" {
				targetID = id
				break
			}
		}
		s.mu.RUnlock()
	}
	all := s.cfg.Store.EnabledNodes()
	var target *subscription.Node
	for i := range all {
		if all[i].ChainInternal {
			continue
		}
		if targetID != "" && store.NodeID(all[i]) == targetID {
			target = &all[i]
			break
		}
	}
	// Offline automatic selection has no live URL-test choice. Use its best
	// saved healthy candidate (the inventory is ordered by measured latency).
	if target == nil && choice.Auto && choice.AutoPick == "" {
		for i := range all {
			rec, err := s.cfg.Store.Get(store.NodeID(all[i]))
			if err == nil && !all[i].ChainInternal && rec.Healthy() {
				target = &all[i]
				break
			}
		}
	}
	if target == nil {
		return errors.New("No Telegram proxy node available; select an enabled configuration or run a latency check")
	}
	var deliveryErr error
	err := proxy.WithProxyClient(ctx, *target, all, func(client *http.Client) error {
		deliveryErr = sendTelegram(ctx, client, cfg, message)
		return deliveryErr
	})
	if deliveryErr != nil {
		return deliveryErr
	}
	// Engine startup/config errors may contain node credentials: do not return
	// them to the notification status, response, or logs.
	if err != nil {
		return errors.New("Telegram proxy connection failed (engine startup or timeout)")
	}
	return nil
}

func directTelegramTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return transport
}

// Explicit test works even when automatic alerts are disabled. It uses saved
// credentials/settings, the usual single-job guard and shutdown cancellation.
func (h *handlers) testTelegram(w http.ResponseWriter, r *http.Request) {
	h.svc.mu.RLock()
	cfg := h.svc.state.Telegram
	h.svc.mu.RUnlock()
	check := cfg
	check.Enabled = true
	if err := validateTelegram(check); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	job, err := h.svc.startJob(JobStatus{Kind: "telegram"}, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		route := "direct"
		if cfg.UseProxy {
			route = "proxy"
		}
		err := h.svc.deliverTelegram(ctx, cfg, "Proxy Manager test message: Telegram delivery is working via "+route+".")
		h.svc.recordTelegramResult(err)
		return err
	})
	h.writeJob(w, job, err)
}
