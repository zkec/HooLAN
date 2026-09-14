// Package api serves the control plane over HTTP: node inventory, subscription
// refresh, proxy on/off, and node selection.
//
// Handlers here do request decoding, validation and status-code mapping only.
// Everything that touches the engine, firewall or store goes through Service, so
// the ordering guarantees documented there hold no matter which route is hit.
//
// SECURITY: these endpoints control root-level operations -- they load nftables
// rules and start a process that holds every proxy credential in the store. The
// server is unauthenticated unless a token is configured; see NewRouter and the
// warning main.go prints when binding a non-loopback address without one.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"hoolan/internal/logstream"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
)

// RouterOptions configures the HTTP surface.
type RouterOptions struct {
	// Token enables bearer API authentication and browser session login.
	// Empty preserves the explicitly unauthenticated deployment mode.
	Token string
	// SecureCookies requires HTTPS cookies when TLS terminates at a trusted
	// reverse proxy. Forwarded headers are never trusted automatically.
	SecureCookies bool
	Logs          *logstream.Hub
	// ExposeCredentials includes UUIDs and passwords in node responses. Off by
	// default: the store file is 0600 for exactly this reason, and a UI does not
	// need them to render a node list.
	ExposeCredentials bool
	Logger            *slog.Logger
}

// NewRouter builds the HTTP handler for the API.
func NewRouter(svc *Service, opts RouterOptions) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	h := &handlers{svc: svc, opts: opts, log: opts.Logger, auth: newSessionStore()}

	mux := http.NewServeMux()
	// Explicit method guards rather than Go 1.22 method patterns: go.mod targets
	// 1.21 so the Pi can build with the distro toolchain.
	mux.Handle("/api/nodes", http.HandlerFunc(h.nodes))
	mux.Handle("/api/nodes/refresh", only(http.MethodPost, h.refreshNodes))
	mux.Handle("/api/proxy/toggle", only(http.MethodPost, h.toggleProxy))
	mux.Handle("/api/proxy/select", only(http.MethodPost, h.selectProxy))
	mux.Handle("/api/status", only(http.MethodGet, h.status))
	mux.Handle("/api/auth/session", only(http.MethodGet, h.authSession))
	mux.Handle("/api/auth/login", only(http.MethodPost, h.login))
	mux.Handle("/api/auth/logout", only(http.MethodPost, h.logout))
	mux.Handle("/api/logs", only(http.MethodGet, h.logs))
	h.registerDashboardRoutes(mux)
	// Unauthenticated liveness probe: systemd and monitoring need it, and it
	// exposes nothing.
	mux.Handle("/healthz", only(http.MethodGet, h.health))
	// The dashboard, from the embedded FS. Registered last as the catch-all: the
	// patterns above are more specific, so ServeMux still routes /api to them.
	mux.Handle("/", h.staticHandler())

	var handler http.Handler = mux
	handler = h.authenticate(handler)
	handler = h.recoverPanic(handler)
	handler = h.logRequests(handler)
	return handler
}

type handlers struct {
	svc  *Service
	opts RouterOptions
	log  *slog.Logger
	auth *sessionStore
}

// --- middleware -------------------------------------------------------------

// only restricts a handler to one method, answering 405 with the required Allow
// header rather than falling through to a confusing 404.
func only(method string, fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed,
				fmt.Sprintf("method %s not allowed; use %s", r.Method, method))
			return
		}
		fn(w, r)
	})
}

// recoverPanic keeps one bad request from taking down the gateway's control
// plane, which would leave no way to turn interception off.
func (h *handlers) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				h.log.Error("panic in handler", "path", r.URL.Path,
					"panic", v, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (h *handlers) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		h.log.Info("http", "method", r.Method, "path", r.URL.Path,
			"status", rec.status, "dur", time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(p)
}

// Unwrap lets ResponseController reach the real connection for SSE deadlines.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) FlushError() error {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(r.ResponseWriter).Flush()
}

func (r *statusRecorder) Flush() { _ = r.FlushError() }

// --- GET /api/nodes ---------------------------------------------------------

// NodeView is one node as the API presents it. Credentials are omitted unless
// RouterOptions.ExposeCredentials is set.
type NodeView struct {
	BalanceStrategy string   `json:"balance_strategy,omitempty"`
	MemberCount     int      `json:"member_count,omitempty"`
	ChainID         string   `json:"chain_id,omitempty"`
	SubscriptionIDs []string `json:"subscription_ids"`
	Manual          bool     `json:"manual"`
	ID              string   `json:"id"`
	Tag             string   `json:"tag"`
	Protocol        string   `json:"protocol"`
	Server          string   `json:"server"`
	Port            int      `json:"port"`

	Transport string `json:"transport,omitempty"`
	Security  string `json:"security,omitempty"`
	SNI       string `json:"sni,omitempty"`
	DetourID  string `json:"detour_id,omitempty"`
	Detour    string `json:"detour,omitempty"`

	Enabled bool `json:"enabled"`
	// LatencyMS is -1 when never measured or the last probe failed, which is
	// distinct from 0. See store.LatencyUnmeasured.
	LatencyMS     int       `json:"latency_ms"`
	Healthy       bool      `json:"healthy"`
	LastCheckedAt time.Time `json:"last_checked_at"`
	LastError     string    `json:"last_error,omitempty"`
	Failures      int       `json:"consecutive_failures"`

	// Selected marks the operator's pinned node.
	Selected bool `json:"selected,omitempty"`
	// InConfig reports whether this node is in the running engine config and so
	// can be selected right now.
	InConfig bool `json:"in_config"`
	// EffectiveTag is the tag the node was actually rendered under, which
	// differs from Tag when the provider sent duplicates (DedupeTags).
	EffectiveTag string `json:"effective_tag,omitempty"`

	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`
}

type nodesResponse struct {
	Nodes     []NodeView `json:"nodes"`
	Count     int        `json:"count"`
	Selection Selection  `json:"selection"`
}

func (h *handlers) listNodes(w http.ResponseWriter, r *http.Request) {
	records := h.svc.cfg.Store.All()

	h.svc.mu.RLock()
	tagByID := make(map[string]string, len(h.svc.tagByID))
	for k, v := range h.svc.tagByID {
		tagByID[k] = v
	}
	selectedID := h.svc.state.SelectedNodeID
	origins := make(map[string][]string)
	for _, sub := range h.svc.state.Subscriptions {
		seen := make(map[string]bool, len(sub.NodeIDs))
		for _, id := range sub.NodeIDs {
			if !seen[id] {
				origins[id] = append(origins[id], sub.ID)
				seen[id] = true
			}
		}
	}
	manual := make(map[string]bool, len(h.svc.state.ManualNodeIDs))
	for id, value := range h.svc.state.ManualNodeIDs {
		manual[id] = value
	}
	h.svc.mu.RUnlock()

	views := make([]NodeView, 0, len(records))
	for _, rec := range records {
		if !rec.Node.ChainInternal {
			view := h.viewOf(rec, tagByID, selectedID)
			view.SubscriptionIDs = origins[rec.ID]
			if view.SubscriptionIDs == nil {
				view.SubscriptionIDs = []string{}
			}
			view.Manual = manual[rec.ID] || len(view.SubscriptionIDs) == 0
			views = append(views, view)
		}
	}
	// Fastest first, unmeasured last -- the same order EnabledNodes uses, so the
	// UI list matches the urltest group's preference.
	sort.SliceStable(views, func(i, j int) bool {
		li, lj := views[i].LatencyMS, views[j].LatencyMS
		switch {
		case li < 0 && lj < 0:
			return views[i].Tag < views[j].Tag
		case li < 0:
			return false
		case lj < 0:
			return true
		case li != lj:
			return li < lj
		default:
			return views[i].Tag < views[j].Tag
		}
	})

	writeJSON(w, http.StatusOK, nodesResponse{
		Nodes:     views,
		Count:     len(views),
		Selection: h.svc.selection(r.Context()),
	})
}

func (h *handlers) viewOf(rec store.Record, tagByID map[string]string, selectedID string) NodeView {
	n := rec.Node
	effective := tagByID[rec.ID]
	v := NodeView{
		ID:              rec.ID,
		MemberCount:     len(n.BalanceMembers),
		BalanceStrategy: n.BalanceStrategy,
		ChainID:         rec.ChainID,
		Tag:             displayTag(n),
		Protocol:        string(n.Protocol),
		Server:          n.Server,
		Port:            n.Port,
		Transport:       string(n.Transport),
		Security:        string(n.Security),
		SNI:             n.SNI,
		Detour:          n.Detour,
		DetourID:        rec.DetourID,
		Enabled:         rec.Enabled,
		LatencyMS:       rec.LastLatencyMS,
		Healthy:         rec.Healthy(),
		LastCheckedAt:   rec.LastCheckedAt,
		LastError:       rec.LastError,
		Failures:        rec.ConsecutiveFailures,
		Selected:        rec.ID == selectedID,
		InConfig:        effective != "",
		EffectiveTag:    effective,
	}
	if h.opts.ExposeCredentials {
		v.UUID, v.Password, v.Method = n.UUID, n.Password, n.Method
	}
	return v
}

// displayTag mirrors the fallback DedupeTags uses, so a node whose provider sent
// no name still renders as something identifiable instead of an empty string.
func displayTag(n subscription.Node) string {
	if t := strings.TrimSpace(n.Tag); t != "" {
		return t
	}
	return fmt.Sprintf("%s-%s", n.Protocol, n.Server)
}

// --- POST /api/nodes/refresh ------------------------------------------------

func (h *handlers) refreshNodes(w http.ResponseWriter, r *http.Request) {
	// Every successful source refresh is authoritative; the legacy prune query
	// parameter no longer changes synchronization semantics.
	job, err := h.svc.StartRefresh(true)
	switch {
	case errors.Is(err, ErrRefreshInProgress):
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "refresh already in progress", "refresh": job,
		})
		return
	case errors.Is(err, ErrNoSubscriptions):
		// 503, not 400: the request is well formed, the server is unconfigured.
		// Retrying the same request verbatim works once -sub is set.
		writeError(w, http.StatusServiceUnavailable,
			"no subscription URLs configured; start the server with -sub")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 202: the sweep starts one engine per node and runs for minutes. Poll
	// GET /api/status for the outcome.
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":  "started",
		"refresh": job,
		"poll":    "/api/status",
	})
}

// --- POST /api/proxy/toggle -------------------------------------------------

type toggleRequest struct {
	// Enabled is a pointer so an absent field means "flip", distinct from an
	// explicit false.
	Enabled *bool `json:"enabled"`
}

type toggleResponse struct {
	ProxyEnabled  bool   `json:"proxy_enabled"`
	EngineRunning bool   `json:"engine_running"`
	EnginePid     int    `json:"engine_pid,omitempty"`
	RulesLoaded   bool   `json:"tproxy_rules_loaded"`
	Message       string `json:"message,omitempty"`
}

func (h *handlers) toggleProxy(w http.ResponseWriter, r *http.Request) {
	var req toggleRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.svc.mu.RLock()
	current := h.svc.proxyEnabled
	h.svc.mu.RUnlock()

	want := !current
	if req.Enabled != nil {
		want = *req.Enabled
	}

	if err := h.svc.SetProxyEnabled(r.Context(), want); err != nil {
		switch {
		case errors.Is(err, ErrNoNodes):
			// 409, not 400: the request is well-formed, the system just has no
			// nodes yet.
			writeError(w, http.StatusConflict, err.Error())
		default:
			h.log.Error("toggle failed", "want", want, "err", err)
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	loaded, _ := h.svc.cfg.Firewall.Status(r.Context())
	msg := "proxy stopped; LAN traffic is no longer intercepted"
	if want {
		msg = "proxy started; LAN traffic is intercepted via TPROXY"
	}
	writeJSON(w, http.StatusOK, toggleResponse{
		ProxyEnabled:  want,
		EngineRunning: h.svc.cfg.Engine.Running(),
		EnginePid:     h.svc.cfg.Engine.Pid(),
		RulesLoaded:   loaded,
		Message:       msg,
	})
}

// --- POST /api/proxy/select -------------------------------------------------

type selectRequest struct {
	// Auto hands the choice to the urltest group.
	Auto bool `json:"auto"`
	// NodeID is a store record ID. Preferred over Tag: IDs are stable across
	// subscription refreshes, tags are not.
	NodeID string `json:"node_id"`
	// Tag selects by display name, resolved to an ID. A convenience for humans
	// with curl; ambiguous tags are rejected.
	Tag string `json:"tag"`
}

type selectResponse struct {
	Selection Selection `json:"selection"`
	// Applied is false when the choice was saved but the engine is not running,
	// in which case it takes effect at the next start.
	Applied bool   `json:"applied"`
	Message string `json:"message,omitempty"`
}

func (h *handlers) selectProxy(w http.ResponseWriter, r *http.Request) {
	var req selectRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	switch {
	case req.Auto && (req.NodeID != "" || req.Tag != ""):
		writeError(w, http.StatusBadRequest,
			"auto cannot be combined with node_id or tag")
		return
	case req.NodeID != "" && req.Tag != "":
		writeError(w, http.StatusBadRequest, "give node_id or tag, not both")
		return
	case !req.Auto && req.NodeID == "" && req.Tag == "":
		writeError(w, http.StatusBadRequest,
			`specify {"auto":true} or {"node_id":"..."} or {"tag":"..."}`)
		return
	}

	nodeID := req.NodeID
	if req.Tag != "" {
		id, err := h.resolveTag(req.Tag)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		nodeID = id
	}

	applied, err := h.svc.Select(r.Context(), req.Auto, nodeID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, ErrNoSelector):
			// The engine is running but has no control channel, so the choice
			// cannot take effect without a restart.
			writeError(w, http.StatusServiceUnavailable,
				"no control API configured; restart the server with -clash-api to switch nodes live")
		case errors.Is(err, ErrClashUnavailable):
			writeError(w, http.StatusBadGateway,
				"engine control API unreachable: "+err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	msg := "selection applied to the running engine"
	if !applied {
		msg = "selection saved; it takes effect when the proxy starts"
	}
	writeJSON(w, http.StatusOK, selectResponse{
		Selection: h.svc.selection(r.Context()),
		Applied:   applied,
		Message:   msg,
	})
}

// resolveTag maps a display tag to a record ID, rejecting ambiguity rather than
// silently picking one of several nodes sharing a name.
func (h *handlers) resolveTag(tag string) (string, error) {
	want := strings.TrimSpace(tag)
	var matches []string
	h.svc.mu.RLock()
	for id, effective := range h.svc.tagByID {
		if effective == want {
			matches = append(matches, id)
		}
	}
	h.svc.mu.RUnlock()

	if len(matches) == 0 {
		for _, rec := range h.svc.cfg.Store.All() {
			if displayTag(rec.Node) == want {
				matches = append(matches, rec.ID)
			}
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no node with tag %q", tag)
	case 1:
		return matches[0], nil
	default:
		sort.Strings(matches)
		return "", fmt.Errorf("tag %q matches %d nodes; select by node_id instead (%s)",
			tag, len(matches), strings.Join(matches, ", "))
	}
}

// --- GET /api/status, /healthz ----------------------------------------------

func (h *handlers) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.svc.Status(r.Context()))
}

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- helpers ----------------------------------------------------------------

// decodeBody reads an optional JSON body into dst. An empty body is not an
// error: POST /api/proxy/toggle with no body means "flip".
func decodeBody(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	// Bounded: these are small control messages, and an unbounded decode on a
	// root-privileged service is a free memory-exhaustion vector.
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain exactly one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	buf, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		// Marshal after WriteHeader would emit a broken body under a 200; encode
		// first so a failure can still become a clean 500.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"could not encode response"}` + "\n"))
		return
	}
	buf = append(buf, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(buf)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func isTruthyParam(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// jsonUnmarshal / jsonMarshalIndent keep encoding/json out of service.go's
// import list, which otherwise reads as if it did its own wire formatting.
func jsonUnmarshal(buf []byte, dst any) error { return json.Unmarshal(buf, dst) }

func jsonMarshalIndent(v any) ([]byte, error) {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(buf, '\n'), nil
}
