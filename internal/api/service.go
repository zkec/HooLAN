package api

// Service is the orchestration layer between HTTP handlers and the engine,
// store, tester and netfilter packages. Handlers do request decoding and status
// codes; everything that touches the system lives here.
//
// Ordering rules enforced in this file, both learned from the failure mode they
// prevent:
//
//   - Starting: engine up and confirmed listening BEFORE nftables rules load.
//     Rules loaded with nothing on TPROXY_PORT blackholes the whole LAN.
//   - Stopping: nftables rules removed BEFORE the engine stops, for the same
//     reason in reverse.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxy-manager/internal/engine"
	"proxy-manager/internal/store"
	"proxy-manager/internal/subscription"
	"proxy-manager/internal/tester"
)

// ProxyEngine is the slice of engine.Manager the API depends on. An interface so
// handler tests can run without a sing-box binary on PATH.
type ProxyEngine interface {
	Apply(ctx context.Context, nodes []subscription.Node) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Running() bool
	Pid() int
	TProxyPort() int
	ConfigPath() string
}

// Firewall is the slice of netfilter.Manager the API depends on.
type Firewall interface {
	Apply(ctx context.Context) error
	Remove(ctx context.Context) error
	Status(ctx context.Context) (bool, error)
}

// LatencyTester is the slice of tester.Tester the API depends on.
type LatencyTester interface {
	TestNodes(ctx context.Context, nodes []subscription.Node) []tester.Result
}

// Selector abstracts the live control channel. *ClashClient implements it; nil
// means no control API is configured.
type Selector interface {
	Group(ctx context.Context, name string) (ClashProxy, error)
	Select(ctx context.Context, group, member string) error
	WaitReady(ctx context.Context, group string) error
}

// Config wires the service's dependencies.
type Config struct {
	Store    *store.Store
	Engine   ProxyEngine
	Firewall Firewall
	Tester   LatencyTester
	// Selector is optional. Without it, selection changes are persisted but
	// cannot be applied to a running engine without a restart.
	Selector Selector

	// SubscriptionURLs are fetched by Refresh, in order. http(s):// URLs and
	// local paths (bare or file://) are both accepted.
	SubscriptionURLs []string
	// StatePath persists operator intent (proxy on/off, selected node) so a
	// systemd restart does not silently change the gateway's behaviour.
	StatePath string
	// RefreshTimeout bounds one whole refresh job: fetch, parse, latency sweep,
	// engine reload. The sweep dominates; it starts one engine per node bounded
	// by the tester's own concurrency.
	RefreshTimeout time.Duration
	// HTTPClient fetches subscriptions. Defaults to a 30s-timeout client.
	HTTPClient *http.Client
	// UserAgent is sent on subscription fetches. Some providers serve a
	// different (or empty) payload to unknown agents.
	UserAgent string

	Logger *slog.Logger
}

// Service holds runtime state for the API.
type Service struct {
	cfg Config
	log *slog.Logger

	// jobCtx bounds background work. Cancelled by Shutdown so an in-flight
	// latency sweep does not outlive the process; deliberately NOT derived from
	// a request context, which dies when the handler returns.
	jobCtx    context.Context
	jobCancel context.CancelFunc
	jobs      sync.WaitGroup

	// opMu serialises engine/firewall transitions. Toggling the proxy while a
	// refresh is reloading config would interleave Stop/Start pairs.
	opMu sync.Mutex

	mu    sync.RWMutex
	state State
	// tagByID maps a store record ID to the tag that node was actually rendered
	// under in the live config. Needed because BuildConfig calls DedupeTags,
	// which rewrites tags in place: a provider repeating "US" three times yields
	// "US", "US-2", "US-3", and selecting by the store's copy of the tag would
	// target the wrong outbound or a nonexistent one.
	tagByID map[string]string
	// proxyEnabled is observed reality, not intent: set once the engine is up
	// and rules are loaded.
	proxyEnabled bool
	// intentionalStop suppresses the crash handler during a deliberate
	// Stop/Apply, so a planned restart is not mistaken for the engine dying.
	intentionalStop bool

	job JobStatus
	// refreshing guards against concurrent refreshes; a second request gets 409
	// rather than a second latency sweep competing for the same CPU and ports.
	refreshing bool
	closing    bool
}

// State is the persisted operator intent.
type State struct {
	Subscriptions []Subscription  `json:"subscriptions,omitempty"`
	ManualNodeIDs map[string]bool `json:"manual_node_ids,omitempty"`
	DNSServer     string          `json:"dns_server,omitempty"`
	IranBypass    *bool           `json:"iran_bypass,omitempty"`
	ProxyEnabled  bool            `json:"proxy_enabled"`
	// AutoSelect true means the urltest group drives the choice.
	AutoSelect bool `json:"auto_select"`
	// SelectedNodeID is a store record ID, not a tag: tags are
	// provider-controlled and change between refreshes, which would silently
	// repoint the selection at another node. Empty when AutoSelect is true.
	SelectedNodeID string    `json:"selected_node_id,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// JobStatus reports on a refresh job.
type JobStatus struct {
	Kind           string `json:"kind,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
	NodeID         string `json:"node_id,omitempty"`
	ID             string `json:"id,omitempty"`
	State          string `json:"state"` // "idle" | "running" | "succeeded" | "failed"

	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`

	SourcesTotal int `json:"sources_total"`
	SourcesOK    int `json:"sources_ok"`
	NodesParsed  int `json:"nodes_parsed"`
	NodesAdded   int `json:"nodes_added"`
	NodesUpdated int `json:"nodes_updated"`
	NodesPruned  int `json:"nodes_pruned"`
	Tested       int `json:"tested"`
	Reachable    int `json:"reachable"`
	// EngineReloaded is true when a running engine picked up the new node set.
	EngineReloaded bool `json:"engine_reloaded"`

	Error string `json:"error,omitempty"`
	// Warnings carries per-node parse and probe failures: one bad link in a
	// hundred must not fail the batch, but it should still be visible.
	Warnings []string `json:"warnings,omitempty"`
}

const maxWarnings = 20

// New builds a Service and loads persisted state. It does not start anything;
// call Restore for that.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("api: Store is required")
	}
	if cfg.Engine == nil {
		return nil, errors.New("api: Engine is required")
	}
	if cfg.Firewall == nil {
		return nil, errors.New("api: Firewall is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RefreshTimeout == 0 {
		cfg.RefreshTimeout = 10 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "proxy-manager/1.0 (sing-box)"
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{
		cfg:       cfg,
		log:       cfg.Logger,
		jobCtx:    ctx,
		jobCancel: cancel,
		tagByID:   make(map[string]string),
		job:       JobStatus{State: "idle"},
	}
	st, err := s.loadState()
	if err != nil {
		// A corrupt state file must not stop the control plane from coming up --
		// that would leave no way to fix it except by hand.
		s.log.Warn("could not load state; starting with defaults", "err", err)
		st = State{AutoSelect: true}
	}
	s.state = st
	s.seedSubscriptions()
	if err := s.configureEngineRouting(); err != nil {
		cancel()
		return nil, fmt.Errorf("api: load routing settings: %w", err)
	}
	return s, nil
}

// --- state persistence ------------------------------------------------------

func (s *Service) loadState() (State, error) {
	if s.cfg.StatePath == "" {
		return State{AutoSelect: true}, nil
	}
	buf, err := os.ReadFile(s.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(buf) == 0) {
		// Fresh install: auto-switch on, proxy off until asked.
		return State{AutoSelect: true}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("api: read state %s: %w", s.cfg.StatePath, err)
	}
	var st State
	if err := jsonUnmarshal(buf, &st); err != nil {
		return State{}, fmt.Errorf("api: parse state %s: %w", s.cfg.StatePath, err)
	}
	return st, nil
}

// saveState persists intent atomically. Caller must hold s.mu.
func (s *Service) saveState() error {
	if s.cfg.StatePath == "" {
		return nil
	}
	s.state.UpdatedAt = time.Now()
	buf, err := jsonMarshalIndent(s.state)
	if err != nil {
		return fmt.Errorf("api: marshal state: %w", err)
	}
	dir := filepath.Dir(s.cfg.StatePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("api: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return fmt.Errorf("api: temp state: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once renamed

	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return fmt.Errorf("api: write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("api: sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("api: close state: %w", err)
	}
	if err := os.Rename(name, s.cfg.StatePath); err != nil {
		return fmt.Errorf("api: rename state: %w", err)
	}
	return nil
}

// --- lifecycle --------------------------------------------------------------

// Restore brings the gateway back to its persisted state. Called once at
// startup, before the HTTP server begins serving.
//
// Errors are returned for logging but must not be fatal: if restoring the proxy
// fails, the API still needs to come up so an operator can diagnose it.
func (s *Service) Restore(ctx context.Context) error {
	s.mu.RLock()
	want := s.state.ProxyEnabled
	s.mu.RUnlock()
	if !want {
		// Rules could still be loaded from an unclean shutdown (SIGKILL, power
		// loss). Removing them is idempotent and prevents a boot where traffic
		// is intercepted with no engine to receive it.
		if loaded, err := s.cfg.Firewall.Status(ctx); err == nil && loaded {
			s.log.Warn("tproxy rules loaded but proxy is off; removing stale ruleset")
			if err := s.cfg.Firewall.Remove(ctx); err != nil {
				return fmt.Errorf("remove stale ruleset: %w", err)
			}
		}
		return nil
	}
	s.log.Info("restoring proxy to enabled state")
	return s.enable(ctx)
}

// Shutdown stops background jobs and tears the gateway down cleanly.
//
// ctx should be a fresh context, not the cancelled root: teardown still has to
// run when the process is on its way out.
func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	s.jobCancel()
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.jobs.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.log.Warn("background jobs did not finish before shutdown deadline")
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	wasEnabled := s.proxyEnabled
	s.mu.Unlock()

	// Rules first, then the engine: the reverse order leaves a window where the
	// LAN is intercepted with nothing listening.
	//
	// Remove runs unconditionally, even when we never enabled: it is idempotent,
	// and a previous unclean exit can leave rules behind that would blackhole the
	// LAN after we are gone. But only escalate the failure when interception was
	// actually live -- on a never-enabled server (or a box without nft) this is a
	// no-op sweep, and returning an error there trains operators to ignore the
	// one message that means the LAN is still intercepted.
	var errs []error
	if err := s.cfg.Firewall.Remove(ctx); err != nil {
		if wasEnabled {
			errs = append(errs, fmt.Errorf("remove tproxy rules: %w", err))
		} else {
			s.log.Debug("shutdown rule sweep failed; nothing was enabled", "err", err)
		}
	}
	s.setIntentionalStop(true)
	defer s.setIntentionalStop(false)
	if err := s.cfg.Engine.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("stop engine: %w", err))
	}

	s.mu.Lock()
	s.proxyEnabled = false
	s.mu.Unlock()
	return errors.Join(errs...)
}

// HandleEngineExit is wired to engine Options.OnExit. If sing-box dies while
// interception is live, every LAN client is blackholed, so the rules come down
// and the gateway fails open.
//
// Must not block or call back into the engine synchronously (see OnExit's
// contract), hence the goroutine.
func (s *Service) HandleEngineExit(exitErr error) {
	s.mu.RLock()
	planned, enabled := s.intentionalStop, s.proxyEnabled
	s.mu.RUnlock()
	if planned || !enabled {
		return
	}
	s.log.Error("engine exited unexpectedly while proxy was enabled; "+
		"removing tproxy rules to fail open", "err", exitErr)
	go func() {
		s.opMu.Lock()
		defer s.opMu.Unlock()
		// A completed reload can replace the process before this goroutine
		// obtains the lifecycle lock. Never tear down its healthy replacement.
		if s.cfg.Engine.Running() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.cfg.Firewall.Remove(ctx); err != nil {
			s.log.Error("failed to remove tproxy rules after engine crash; "+
				"LAN traffic may be blackholed", "err", err)
		}
		s.mu.Lock()
		s.proxyEnabled = false
		s.mu.Unlock()
	}()
}

func (s *Service) setIntentionalStop(v bool) {
	s.mu.Lock()
	s.intentionalStop = v
	s.mu.Unlock()
}

// --- proxy toggle -----------------------------------------------------------

// SetProxyEnabled starts or stops interception. Idempotent.
func (s *Service) SetProxyEnabled(ctx context.Context, enabled bool) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	closing := s.closing
	s.mu.RUnlock()
	if closing {
		return errors.New("api: shutting down")
	}

	if enabled {
		if err := s.enable(ctx); err != nil {
			return err
		}
	} else if err := s.disable(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	s.state.ProxyEnabled = enabled
	err := s.saveState()
	s.mu.Unlock()
	return err
}

// ErrNoNodes means there is nothing to build a config from.
var ErrNoNodes = errors.New("api: no enabled nodes; refresh a subscription first")

// enable renders config, starts the engine, confirms it listens, then installs
// the ruleset. Caller must hold opMu.
func (s *Service) enable(ctx context.Context) error {
	s.mu.RLock()
	enabled := s.proxyEnabled
	s.mu.RUnlock()
	if enabled {
		if s.cfg.Engine.Running() {
			return nil
		}
		s.mu.Lock()
		s.proxyEnabled = false
		s.mu.Unlock()
	}
	// Clear stale rules before rendering/starting, including startup failures.
	if err := s.cfg.Firewall.Remove(ctx); err != nil {
		return fmt.Errorf("api: remove stale interception before startup: %w", err)
	}
	if v, ok := s.cfg.Firewall.(interface{ ValidatePort(int) error }); ok {
		if err := v.ValidatePort(s.cfg.Engine.TProxyPort()); err != nil {
			return err
		}
	}
	nodes := s.cfg.Store.EnabledNodes()
	if len(nodes) == 0 {
		return ErrNoNodes
	}
	if err := s.applyEngine(ctx, nodes); err != nil {
		s.cleanupFailedEnable()
		return err
	}
	// The engine binds TPROXY_PORT asynchronously after Start returns. Loading
	// rules before it does means intercepted packets hit a closed port.
	if err := s.waitEngineListening(ctx); err != nil {
		s.cleanupFailedEnable()
		return fmt.Errorf("api: engine did not open tproxy port: %w", err)
	}
	// Best-effort: a failed reselect leaves the engine on its config default
	// (the urltest group), which still carries traffic.
	if err := s.applySelection(ctx); err != nil {
		s.log.Warn("could not apply saved selection", "err", err)
	}

	if err := s.cfg.Firewall.Apply(ctx); err != nil {
		// Roll back rather than leave a running engine with no interception and
		// a half-loaded ruleset.
		s.cleanupFailedEnable()
		return fmt.Errorf("api: apply tproxy rules: %w", err)
	}

	s.mu.Lock()
	s.proxyEnabled = true
	s.mu.Unlock()
	// Publishing enabled first makes a concurrent exit visible to OnExit;
	// the explicit check covers exits that happened just before publication.
	if !s.cfg.Engine.Running() {
		s.cleanupFailedEnable()
		return errors.New("sing-box exited while installing interception")
	}
	s.log.Info("proxy enabled", "pid", s.cfg.Engine.Pid(), "nodes", len(nodes))
	return nil
}

// disable removes the ruleset, then stops the engine. Caller must hold opMu.
func (s *Service) disable(ctx context.Context) error {
	// Rules first. Stopping the engine while they are loaded blackholes the LAN
	// for as long as it takes to unload them.
	if err := s.cfg.Firewall.Remove(ctx); err != nil {
		return fmt.Errorf("api: remove tproxy rules: %w", err)
	}
	s.setIntentionalStop(true)
	defer s.setIntentionalStop(false)
	if err := s.cfg.Engine.Stop(ctx); err != nil {
		return fmt.Errorf("api: stop engine: %w", err)
	}
	s.mu.Lock()
	s.proxyEnabled = false
	s.mu.Unlock()
	s.log.Info("proxy disabled")
	return nil
}

// applyEngine renders and (re)starts the engine, recording the tags each node
// was rendered under. Caller must hold opMu.
func (s *Service) applyEngine(ctx context.Context, nodes []subscription.Node) error {
	// Apply stops a running engine as part of its reconciliation, which would
	// otherwise trip the crash handler.
	s.setIntentionalStop(true)
	defer s.setIntentionalStop(false)
	if err := s.configureEngineRouting(); err != nil {
		return err
	}

	// Apply mutates nodes in place via DedupeTags, so the ID->tag index is built
	// from the same slice afterwards, not before.
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = store.NodeID(n)
	}
	if err := s.cfg.Engine.Apply(ctx, nodes); err != nil {
		return fmt.Errorf("api: apply engine config: %w", err)
	}
	index := make(map[string]string, len(nodes))
	for i, n := range nodes {
		index[ids[i]] = n.Tag
	}
	s.mu.Lock()
	s.tagByID = index
	s.mu.Unlock()
	return nil
}

// waitEngineListening polls until the engine has bound its tproxy port.
//
// This deliberately does NOT dial the port. A dial to 127.0.0.1:TPROXY_PORT is
// accepted by the tproxy inbound as an ordinary client connection, and the
// engine then routes it -- which, before the routing reject rule in
// internal/engine existed, sent it to `direct`, dialling the same port again
// and seeding an unbounded self-connection loop that saturated the Pi. Probing
// readiness by manufacturing the exact connection that must never exist is the
// wrong contract even now that the reject rule makes it survivable. Reading the
// kernel's socket table proves the listener is bound and creates no traffic.
func (s *Service) waitEngineListening(ctx context.Context) error {
	port := s.cfg.Engine.TProxyPort()
	if port <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !s.cfg.Engine.Running() {
			return errors.New("sing-box exited before its TPROXY listeners became ready")
		}
		listening, err := tproxySocketsReady(s.cfg.Engine.Pid(), port)
		if err != nil {
			return err
		}
		if listening {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("api: sing-box PID %d did not own both IPv4 TCP and UDP wildcard listeners on port %d: %w", s.cfg.Engine.Pid(), port, ctx.Err())
		case <-ticker.C:
		}
	}
}

// procTCPFiles are the kernel socket tables consulted by tcpPortIsListening.
// tcp6 is absent on kernels booted with ipv6.disable=1, which is not an error.
var procTCPFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// tcpPortIsListening reports whether any local TCP socket is in LISTEN state on
// port, bound to any address.
//
// Both files share one format: a header line, then whitespace-separated columns
//
//	sl  local_address rem_address st ...
//	0:  0100007F:1ED4 00000000:0000 0A ...   <- 127.0.0.1:7892, TCP_LISTEN
//
// local_address is HEX_ADDR:HEX_PORT (address little-endian) and state 0A is
// TCP_LISTEN. The address half is ignored on purpose: "::", 0.0.0.0 and
// 127.0.0.1 all mean "bound and ready", and the engine's default listen of "::"
// appears here as sixteen zeroes in tcp6 rather than as a loopback address.
func tcpPortIsListening(port int) (bool, error) {
	const tcpListen = "0A"
	want := fmt.Sprintf("%04X", port)
	for _, path := range procTCPFiles {
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // tcp6 on an ipv6-disabled kernel
			}
			return false, fmt.Errorf("api: open %s: %w", path, err)
		}
		found, err := scanProcTCPListen(f, want, tcpListen)
		f.Close()
		if err != nil {
			return false, fmt.Errorf("api: parse %s: %w", path, err)
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

func scanProcTCPListen(r io.Reader, wantPort, wantState string) (bool, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// The header line has "st" in this column, so it never matches.
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != wantState {
			continue
		}
		local := fields[1]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		if strings.EqualFold(local[i+1:], wantPort) {
			return true, nil
		}
	}
	return false, sc.Err()
}

// --- selection --------------------------------------------------------------

// ErrNoSelector means no control API is configured, so a live selection change
// is impossible.
var ErrNoSelector = errors.New("api: no control API configured")

// Select sets the active node, or hands control to the urltest group when
// auto is true. The choice is persisted either way.
//
// applied reports whether it reached the running engine: with the engine
// stopped there is nothing to change yet, and the selection takes effect at the
// next start.
func (s *Service) Select(ctx context.Context, auto bool, nodeID string) (applied bool, err error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !auto && nodeID == "" {
		return false, errors.New("api: node id required when auto is false")
	}
	if !auto {
		if _, err := s.cfg.Store.Get(nodeID); err != nil {
			return false, err // store.ErrNotFound, mapped to 404 by the handler
		}
	}

	s.mu.Lock()
	oldAuto, oldNodeID := s.state.AutoSelect, s.state.SelectedNodeID
	s.state.AutoSelect = auto
	s.state.SelectedNodeID = ""
	if !auto {
		s.state.SelectedNodeID = nodeID
	}
	saveErr := s.saveState()
	if saveErr != nil {
		s.state.AutoSelect, s.state.SelectedNodeID = oldAuto, oldNodeID
	}
	s.mu.Unlock()
	if saveErr != nil {
		return false, saveErr
	}

	if !s.cfg.Engine.Running() {
		return false, nil
	}
	if _, configurable := s.cfg.Engine.(interface{ ConfigureAutoSelection(bool) }); configurable && oldAuto != auto {
		// URLTest starts probing even when the selector points elsewhere.
		// Rebuild with interception removed before stopping the listener.
		if err := s.reloadRunningLocked(ctx); err != nil {
			return false, err
		}
	}
	if err := s.applySelection(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// applySelection pushes the persisted choice to the running engine.
func (s *Service) applySelection(ctx context.Context) error {
	if s.cfg.Selector == nil {
		return ErrNoSelector
	}
	s.mu.RLock()
	auto, nodeID := s.state.AutoSelect, s.state.SelectedNodeID
	tag := s.tagByID[nodeID]
	s.mu.RUnlock()

	member := engine.DefaultURLTest
	if !auto {
		if tag == "" {
			// The node exists in the store but was not rendered into the live
			// config: disabled, an unsupported protocol, or added since the last
			// engine reload.
			return fmt.Errorf("api: node %s is not in the running config; refresh or restart the proxy", nodeID)
		}
		member = tag
	}
	return s.cfg.Selector.Select(ctx, engine.DefaultSelector, member)
}

// Selection describes the current choice for API responses.
type Selection struct {
	Auto   bool   `json:"auto"`
	NodeID string `json:"node_id,omitempty"`
	Tag    string `json:"tag,omitempty"`
	// Active is what the engine reports as the selector's current pick. Empty
	// when the engine is stopped or has no control API. It can differ from Tag:
	// under auto the selector reads "auto" while urltest picks the real node.
	Active string `json:"active,omitempty"`
	// AutoPick is the node urltest currently favours, when running under auto.
	AutoPick string `json:"auto_pick,omitempty"`
}

// --- status -----------------------------------------------------------------

// Status is the GET /api/status payload.
type Status struct {
	ProxyEnabled  bool      `json:"proxy_enabled"`
	EngineRunning bool      `json:"engine_running"`
	EnginePid     int       `json:"engine_pid,omitempty"`
	RulesLoaded   bool      `json:"tproxy_rules_loaded"`
	RulesError    string    `json:"tproxy_rules_error,omitempty"`
	Selection     Selection `json:"selection"`
	NodesTotal    int       `json:"nodes_total"`
	NodesEnabled  int       `json:"nodes_enabled"`
	NodesHealthy  int       `json:"nodes_healthy"`
	ConfigPath    string    `json:"config_path,omitempty"`
	Refresh       JobStatus `json:"refresh"`
}

// Status reports current state. Never fails: an unreadable nft status is
// reported in the payload rather than as an error, since the rest is still
// useful.
func (s *Service) Status(ctx context.Context) Status {
	st := Status{
		EngineRunning: s.cfg.Engine.Running(),
		EnginePid:     s.cfg.Engine.Pid(),
		ConfigPath:    s.cfg.Engine.ConfigPath(),
		Selection:     s.selection(ctx),
		Refresh:       s.JobStatus(),
	}
	s.mu.RLock()
	st.ProxyEnabled = s.proxyEnabled
	s.mu.RUnlock()

	loaded, err := s.cfg.Firewall.Status(ctx)
	st.RulesLoaded = loaded
	if err != nil {
		st.RulesError = err.Error()
	}

	for _, r := range s.cfg.Store.All() {
		st.NodesTotal++
		if r.Enabled {
			st.NodesEnabled++
		}
		if r.Healthy() {
			st.NodesHealthy++
		}
	}
	return st
}

// selection builds the current selection view, consulting the engine when it is
// reachable.
func (s *Service) selection(ctx context.Context) Selection {
	s.mu.RLock()
	sel := Selection{Auto: s.state.AutoSelect, NodeID: s.state.SelectedNodeID}
	sel.Tag = s.tagByID[s.state.SelectedNodeID]
	s.mu.RUnlock()

	if s.cfg.Selector == nil || !s.cfg.Engine.Running() {
		return sel
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	group, err := s.cfg.Selector.Group(ctx, engine.DefaultSelector)
	if err != nil {
		// Engine may be mid-restart, or built without with_clash_api. The
		// persisted intent above is still the useful answer.
		return sel
	}
	sel.Active = group.Now
	if group.Now == engine.DefaultURLTest {
		if auto, err := s.cfg.Selector.Group(ctx, engine.DefaultURLTest); err == nil {
			sel.AutoPick = auto.Now
		}
	}
	return sel
}

// JobStatus returns a copy of the last refresh job's status.
func (s *Service) JobStatus() JobStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j := s.job
	j.Warnings = append([]string(nil), s.job.Warnings...)
	return j
}

// --- refresh ----------------------------------------------------------------

// ErrRefreshInProgress means a refresh is already running.
var ErrRefreshInProgress = errors.New("api: refresh already in progress")

// ErrNoSubscriptions means no subscription URL is configured.
var ErrNoSubscriptions = errors.New("api: no subscription URLs configured")

// StartRefresh kicks off a subscription fetch and latency sweep in the
// background, returning the job's initial status.
//
// Asynchronous on purpose: a sweep over a hundred nodes starts a short-lived
// engine per node and can run for minutes. Holding an HTTP request open for
// that invites client timeouts and gives no way to observe progress; callers
// poll GET /api/status instead.
func (s *Service) StartRefresh(prune bool) (JobStatus, error) {
	sources := s.subscriptionSnapshot()
	if len(sources) == 0 {
		return JobStatus{}, ErrNoSubscriptions
	}
	return s.startJob(JobStatus{Kind: "refresh", SourcesTotal: len(sources)}, func(ctx context.Context) error {
		return s.refreshSources(ctx, sources, prune)
	})
}

func (s *Service) refresh(ctx context.Context, prune bool) error {
	return s.refreshSources(ctx, s.subscriptionSnapshot(), prune)
}

// sweepLatency probes every enabled node and records the results.
func (s *Service) sweepLatency(ctx context.Context) error {
	if s.cfg.Tester == nil {
		s.warn("no latency tester configured; skipping probe")
		return nil
	}
	nodes := s.cfg.Store.EnabledNodes()
	if len(nodes) == 0 {
		return nil
	}
	// Dedupe before probing, for the same reason BuildConfig does: chained nodes
	// are resolved by tag, and duplicate tags would make a chain hop ambiguous.
	// IDs are captured first because DedupeTags rewrites the tags in place and
	// the store is keyed by ID.
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = store.NodeID(n)
	}
	subscription.DedupeTags(nodes)

	results := s.cfg.Tester.TestNodes(ctx, nodes)
	reachable := 0
	for i, res := range results {
		if i >= len(ids) {
			break
		}
		if res.OK() {
			reachable++
			if err := s.cfg.Store.RecordLatency(ids[i], res.Latency); err != nil {
				s.warn(fmt.Sprintf("record latency for %s: %v", nodes[i].Tag, err))
			}
			continue
		}
		if err := s.cfg.Store.RecordFailure(ids[i], res.Err); err != nil {
			s.warn(fmt.Sprintf("record failure for %s: %v", nodes[i].Tag, err))
		}
	}
	s.mu.Lock()
	s.job.Tested = len(results)
	s.job.Reachable = reachable
	s.mu.Unlock()

	// A sweep where nothing answered is reported, not failed: the records are
	// already marked and the operator needs to see them.
	if reachable == 0 {
		s.warn("no node answered the latency probe")
	}
	return ctx.Err()
}

// fetchSubscription reads one source. http(s) URLs are fetched; anything else is
// treated as a local path, so a file-backed subscription works without a server.
func (s *Service) fetchSubscription(ctx context.Context, src string) (string, error) {
	if path, ok := localPath(src); ok {
		buf, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		return string(buf), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	// Providers commonly gate on User-Agent, serving an empty body or a
	// different format to clients they do not recognise.
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	// Cap the read: a misconfigured URL pointing at something huge must not
	// exhaust memory on a Pi.
	const maxBody = 4 << 20
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if len(buf) > maxBody {
		return "", fmt.Errorf("payload exceeds %d bytes", maxBody)
	}
	return string(buf), nil
}

// localPath reports whether src names a local file, and its path.
func localPath(src string) (string, bool) {
	if strings.HasPrefix(src, "file://") {
		return strings.TrimPrefix(src, "file://"), true
	}
	if strings.Contains(src, "://") {
		return "", false
	}
	return src, true
}

// warn appends a bounded warning to the current job.
func (s *Service) warn(msg string) {
	s.log.Warn(msg)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.job.Warnings) >= maxWarnings {
		return
	}
	s.job.Warnings = append(s.job.Warnings, msg)
}
