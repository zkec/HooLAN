package api

// Handler and service tests run against fakes for the engine, firewall and
// tester: the real ones need a sing-box binary, CAP_NET_ADMIN and a live nft
// table, none of which belong in a unit test. The fakes record call ORDER,
// because the ordering guarantees in service.go (engine up before rules load,
// rules down before engine stops) are the properties most worth protecting --
// getting them backwards blackholes the LAN, and nothing else in the test suite
// would notice.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy-manager/internal/engine"
	"proxy-manager/internal/store"
	"proxy-manager/internal/subscription"
	"proxy-manager/internal/tester"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- fakes ------------------------------------------------------------------

// callLog records the interleaving of engine and firewall operations.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (c *callLog) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, s)
}

func (c *callLog) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func (c *callLog) indexOf(s string) int {
	for i, v := range c.snapshot() {
		if v == s {
			return i
		}
	}
	return -1
}

type fakeEngine struct {
	log *callLog

	mu       sync.Mutex
	running  bool
	applied  [][]subscription.Node
	listener net.Listener // stands in for the tproxy inbound
	udp      net.PacketConn

	applyErr error
	startErr error
	stopErr  error
}

func (f *fakeEngine) Apply(ctx context.Context, nodes []subscription.Node) error {
	f.log.add("engine.Apply")
	if f.applyErr != nil {
		return f.applyErr
	}
	// The real Apply dedupes tags in place; mirror that so tests exercise the
	// ID->tag indexing that depends on it.
	subscription.DedupeTags(nodes)
	f.mu.Lock()
	f.applied = append(f.applied, append([]subscription.Node(nil), nodes...))
	f.mu.Unlock()
	return f.Start(ctx)
}

func (f *fakeEngine) Start(context.Context) error {
	f.log.add("engine.Start")
	if f.startErr != nil {
		return f.startErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener == nil {
		ln, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			return err
		}
		f.listener = ln
		udp, err := net.ListenPacket("udp4", ln.Addr().String())
		if err != nil {
			ln.Close()
			f.listener = nil
			return err
		}
		f.udp = udp
	}
	f.running = true
	return nil
}

func (f *fakeEngine) Stop(context.Context) error {
	f.log.add("engine.Stop")
	if f.stopErr != nil {
		return f.stopErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = false
	return nil
}

func (f *fakeEngine) Running() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakeEngine) Pid() int {
	if f.Running() {
		return os.Getpid()
	}
	return 0
}

func (f *fakeEngine) TProxyPort() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener == nil {
		return 0
	}
	return f.listener.Addr().(*net.TCPAddr).Port
}

func (f *fakeEngine) ConfigPath() string { return "/tmp/fake/config.json" }

func (f *fakeEngine) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener != nil {
		f.listener.Close()
	}
	if f.udp != nil {
		f.udp.Close()
	}
}

type fakeFirewall struct {
	log *callLog

	mu       sync.Mutex
	loaded   bool
	applyErr error
	rmErr    error
}

func (f *fakeFirewall) Apply(context.Context) error {
	f.log.add("fw.Apply")
	if f.applyErr != nil {
		return f.applyErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loaded = true
	return nil
}

func (f *fakeFirewall) Remove(context.Context) error {
	f.log.add("fw.Remove")
	if f.rmErr != nil {
		return f.rmErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loaded = false
	return nil
}

func (f *fakeFirewall) Status(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loaded, nil
}

type fakeSelector struct {
	mu       sync.Mutex
	now      string
	picks    []string
	selErr   error
	groupErr error
}

func (f *fakeSelector) Group(_ context.Context, name string) (ClashProxy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.groupErr != nil {
		return ClashProxy{}, f.groupErr
	}
	if name == engine.DefaultURLTest {
		return ClashProxy{Type: "URLTest", Name: name, Now: "fast-node"}, nil
	}
	return ClashProxy{Type: "Selector", Name: name, Now: f.now}, nil
}

func (f *fakeSelector) Select(_ context.Context, _, member string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.selErr != nil {
		return f.selErr
	}
	f.now = member
	f.picks = append(f.picks, member)
	return nil
}

func (f *fakeSelector) WaitReady(context.Context, string) error { return nil }

func (f *fakeSelector) selected() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.picks...)
}

type fakeTester struct {
	results func([]subscription.Node) []tester.Result
}

func (f *fakeTester) TestNodes(_ context.Context, nodes []subscription.Node) []tester.Result {
	if f.results != nil {
		return f.results(nodes)
	}
	out := make([]tester.Result, len(nodes))
	for i, n := range nodes {
		out[i] = tester.Result{Tag: n.Tag, Latency: time.Duration(i+1) * 10 * time.Millisecond}
	}
	return out
}

// --- harness ----------------------------------------------------------------

type harness struct {
	t   *testing.T
	svc *Service
	srv *httptest.Server

	store *store.Store
	eng   *fakeEngine
	fw    *fakeFirewall
	sel   *fakeSelector
	calls *callLog
	dir   string
}

func newHarness(t *testing.T, nodes []subscription.Node, mutate func(*Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "nodes.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if len(nodes) > 0 {
		if _, _, err := st.UpsertNodes(nodes); err != nil {
			t.Fatalf("seed nodes: %v", err)
		}
	}

	calls := &callLog{}
	h := &harness{
		t:     t,
		store: st,
		eng:   &fakeEngine{log: calls},
		fw:    &fakeFirewall{log: calls},
		sel:   &fakeSelector{},
		calls: calls,
		dir:   dir,
	}

	cfg := Config{
		Store:     st,
		Engine:    h.eng,
		Firewall:  h.fw,
		Tester:    &fakeTester{},
		Selector:  h.sel,
		StatePath: filepath.Join(dir, "state.json"),
		Logger:    quietLogger(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	h.svc = svc
	h.srv = httptest.NewServer(NewRouter(svc, RouterOptions{Logger: quietLogger()}))

	t.Cleanup(func() {
		h.srv.Close()
		h.eng.close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = svc.Shutdown(ctx)
	})
	return h
}

// do issues a request and decodes the JSON body.
func (h *harness) do(method, path, body string) (int, map[string]any) {
	h.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, rdr)
	if err != nil {
		h.t.Fatalf("build request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(buf) > 0 {
		if err := json.Unmarshal(buf, &out); err != nil {
			h.t.Fatalf("decode %s %s response %q: %v", method, path, buf, err)
		}
	}
	return resp.StatusCode, out
}

func testNodes() []subscription.Node {
	return []subscription.Node{
		{Protocol: subscription.ProtoVLESS, Tag: "alpha", Server: "a.example.com",
			Port: 443, UUID: "11111111-1111-1111-1111-111111111111",
			Security: subscription.SecTLS, Transport: subscription.TransportTCP},
		{Protocol: subscription.ProtoTrojan, Tag: "beta", Server: "b.example.com",
			Port: 8443, Password: "pw", Security: subscription.SecTLS,
			Transport: subscription.TransportTCP},
	}
}

// --- GET /api/nodes ---------------------------------------------------------

func TestListNodesReportsLatency(t *testing.T) {
	h := newHarness(t, testNodes(), nil)

	recs := h.store.All()
	if err := h.store.RecordLatency(recs[0].ID, 250*time.Millisecond); err != nil {
		t.Fatalf("record latency: %v", err)
	}
	if err := h.store.RecordFailure(recs[1].ID, errors.New("timeout")); err != nil {
		t.Fatalf("record failure: %v", err)
	}

	code, body := h.do(http.MethodGet, "/api/nodes", "")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", code, body)
	}
	if got := body["count"].(float64); got != 2 {
		t.Errorf("count = %v, want 2", got)
	}

	list := body["nodes"].([]any)
	// Measured nodes sort ahead of failed ones.
	first := list[0].(map[string]any)
	if first["latency_ms"].(float64) != 250 {
		t.Errorf("first latency_ms = %v, want 250", first["latency_ms"])
	}
	if first["healthy"] != true {
		t.Errorf("measured node should be healthy, got %v", first["healthy"])
	}

	second := list[1].(map[string]any)
	// -1, not 0: a failed probe must be distinguishable from an instant one.
	if second["latency_ms"].(float64) != store.LatencyUnmeasured {
		t.Errorf("failed node latency_ms = %v, want -1", second["latency_ms"])
	}
	if second["healthy"] != false {
		t.Errorf("failed node should not be healthy")
	}
	if !strings.Contains(second["last_error"].(string), "timeout") {
		t.Errorf("last_error = %v, want it to mention timeout", second["last_error"])
	}
}

func TestListNodesHidesCredentialsByDefault(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	code, body := h.do(http.MethodGet, "/api/nodes", "")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for _, raw := range body["nodes"].([]any) {
		n := raw.(map[string]any)
		for _, secret := range []string{"uuid", "password", "method"} {
			if v, ok := n[secret]; ok && v != "" {
				t.Errorf("node %v leaked %s = %v", n["tag"], secret, v)
			}
		}
	}

	// Opt in and the credentials appear.
	srv := httptest.NewServer(NewRouter(h.svc, RouterOptions{
		ExposeCredentials: true, Logger: quietLogger()}))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/api/nodes")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(buf), "11111111-1111") {
		t.Error("ExposeCredentials did not include the uuid")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	code, _ := h.do(http.MethodGet, "/api/proxy/toggle", "")
	if code != http.StatusMethodNotAllowed {
		t.Errorf("GET on a POST route = %d, want 405", code)
	}
	code, _ = h.do(http.MethodDelete, "/api/nodes", "")
	if code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE on a GET/POST route = %d, want 405", code)
	}
}

// --- POST /api/proxy/toggle -------------------------------------------------

// TestToggleOrdersEngineBeforeRules is the important one: rules must never be
// loaded before the engine is listening, and must come down before it stops.
func TestToggleOrdersEngineBeforeRules(t *testing.T) {
	h := newHarness(t, testNodes(), nil)

	code, body := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`)
	if code != http.StatusOK {
		t.Fatalf("enable = %d, want 200 (%v)", code, body)
	}
	if body["proxy_enabled"] != true || body["tproxy_rules_loaded"] != true {
		t.Fatalf("unexpected enable response: %v", body)
	}

	apply, start := h.calls.indexOf("fw.Apply"), h.calls.indexOf("engine.Start")
	if start < 0 || apply < 0 {
		t.Fatalf("missing calls: %v", h.calls.snapshot())
	}
	if start > apply {
		t.Errorf("engine started AFTER rules loaded (%v): intercepted traffic would hit a closed port",
			h.calls.snapshot())
	}

	code, body = h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":false}`)
	if code != http.StatusOK {
		t.Fatalf("disable = %d (%v)", code, body)
	}
	if body["proxy_enabled"] != false {
		t.Errorf("proxy_enabled = %v after disable", body["proxy_enabled"])
	}

	calls := h.calls.snapshot()
	var lastRemove, lastStop int = -1, -1
	for i, c := range calls {
		switch c {
		case "fw.Remove":
			lastRemove = i
		case "engine.Stop":
			lastStop = i
		}
	}
	if lastRemove < 0 || lastStop < 0 {
		t.Fatalf("missing teardown calls: %v", calls)
	}
	if lastRemove > lastStop {
		t.Errorf("rules removed AFTER engine stopped (%v): the LAN would be blackholed in between", calls)
	}
}

func TestToggleWithoutBodyFlips(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	code, body := h.do(http.MethodPost, "/api/proxy/toggle", "")
	if code != http.StatusOK {
		t.Fatalf("flip on = %d (%v)", code, body)
	}
	if body["proxy_enabled"] != true {
		t.Fatalf("first flip should enable, got %v", body["proxy_enabled"])
	}
	code, body = h.do(http.MethodPost, "/api/proxy/toggle", "")
	if code != http.StatusOK {
		t.Fatalf("flip off = %d", code)
	}
	if body["proxy_enabled"] != false {
		t.Errorf("second flip should disable, got %v", body["proxy_enabled"])
	}
}

func TestToggleWithNoNodesConflicts(t *testing.T) {
	h := newHarness(t, nil, nil)
	code, body := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`)
	if code != http.StatusConflict {
		t.Fatalf("enable with no nodes = %d, want 409 (%v)", code, body)
	}
	if h.calls.indexOf("fw.Apply") >= 0 {
		t.Error("rules were loaded despite having no nodes to proxy through")
	}
}

// TestToggleRollsBackWhenRulesFail covers the window that would otherwise leave
// a running engine and no interception, with state claiming success.
func TestToggleRollsBackWhenRulesFail(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	h.fw.applyErr = errors.New("nft: permission denied")

	code, body := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`)
	if code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (%v)", code, body)
	}
	if h.eng.Running() {
		t.Error("engine left running after the ruleset failed to load")
	}
	if h.svc.Status(context.Background()).ProxyEnabled {
		t.Error("service reports proxy enabled after a failed enable")
	}
}

// TestEngineCrashRemovesRules covers the fail-open path: if sing-box dies while
// interception is live, every LAN client is blackholed until the rules come down.
func TestEngineCrashRemovesRules(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	if code, body := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatalf("enable = %d (%v)", code, body)
	}

	h.eng.mu.Lock()
	h.eng.running = false
	h.eng.mu.Unlock()
	h.svc.HandleEngineExit(errors.New("signal: killed"))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if loaded, _ := h.fw.Status(context.Background()); !loaded {
			return // rules came down: failed open as intended
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("tproxy rules still loaded after the engine crashed; LAN would stay blackholed")
}

// --- POST /api/proxy/select -------------------------------------------------

func TestSelectNodeByID(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	if code, body := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatalf("enable = %d (%v)", code, body)
	}

	target := h.store.All()[0]
	code, body := h.do(http.MethodPost, "/api/proxy/select",
		fmt.Sprintf(`{"node_id":%q}`, target.ID))
	if code != http.StatusOK {
		t.Fatalf("select = %d, want 200 (%v)", code, body)
	}
	if body["applied"] != true {
		t.Errorf("applied = %v, want true with a running engine", body["applied"])
	}

	picks := h.sel.selected()
	if len(picks) == 0 {
		t.Fatal("nothing was pushed to the selector")
	}
	want := target.Node.Tag
	if got := picks[len(picks)-1]; got != want {
		t.Errorf("selector got %q, want the node's rendered tag %q", got, want)
	}

	sel := body["selection"].(map[string]any)
	if sel["auto"] != false {
		t.Errorf("auto = %v after an explicit pick", sel["auto"])
	}
	if sel["node_id"] != target.ID {
		t.Errorf("node_id = %v, want %v", sel["node_id"], target.ID)
	}
}

func TestSelectAutoUsesURLTestGroup(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	if code, _ := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatal("enable failed")
	}
	code, body := h.do(http.MethodPost, "/api/proxy/select", `{"auto":true}`)
	if code != http.StatusOK {
		t.Fatalf("select auto = %d (%v)", code, body)
	}
	picks := h.sel.selected()
	if got := picks[len(picks)-1]; got != engine.DefaultURLTest {
		t.Errorf("selector got %q, want the urltest group %q", got, engine.DefaultURLTest)
	}
	sel := body["selection"].(map[string]any)
	if sel["auto"] != true {
		t.Errorf("auto = %v, want true", sel["auto"])
	}
	// Under auto the API surfaces which node urltest actually favours.
	if sel["auto_pick"] != "fast-node" {
		t.Errorf("auto_pick = %v, want the urltest group's current pick", sel["auto_pick"])
	}
}

func TestSelectByTag(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	if code, _ := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatal("enable failed")
	}
	code, body := h.do(http.MethodPost, "/api/proxy/select", `{"tag":"beta"}`)
	if code != http.StatusOK {
		t.Fatalf("select by tag = %d (%v)", code, body)
	}
	picks := h.sel.selected()
	if got := picks[len(picks)-1]; got != "beta" {
		t.Errorf("selector got %q, want %q", got, "beta")
	}
}

// TestSelectDuplicateTagIsRejected: providers repeat names constantly, and
// DedupeTags renames the copies. Guessing which one the operator meant would
// silently route through the wrong server.
func TestSelectDuplicateTagIsRejected(t *testing.T) {
	dupes := []subscription.Node{
		{Protocol: subscription.ProtoVLESS, Tag: "US", Server: "one.example.com",
			Port: 443, UUID: "11111111-1111-1111-1111-111111111111"},
		{Protocol: subscription.ProtoVLESS, Tag: "US", Server: "two.example.com",
			Port: 443, UUID: "22222222-2222-2222-2222-222222222222"},
	}
	h := newHarness(t, dupes, nil)
	code, body := h.do(http.MethodPost, "/api/proxy/select", `{"tag":"US"}`)
	if code != http.StatusNotFound {
		t.Fatalf("ambiguous tag = %d, want 404 (%v)", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "node_id") {
		t.Errorf("error should point at node_id, got %q", msg)
	}
}

// TestSelectUsesDedupedTag: the store keeps the provider's original tag, but the
// engine renders duplicates as "US", "US-2". Selecting must use the rendered
// tag, or the Clash API call targets a member that does not exist.
func TestSelectUsesDedupedTag(t *testing.T) {
	dupes := []subscription.Node{
		{Protocol: subscription.ProtoVLESS, Tag: "US", Server: "one.example.com",
			Port: 443, UUID: "11111111-1111-1111-1111-111111111111"},
		{Protocol: subscription.ProtoVLESS, Tag: "US", Server: "two.example.com",
			Port: 443, UUID: "22222222-2222-2222-2222-222222222222"},
	}
	h := newHarness(t, dupes, nil)
	if code, body := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatalf("enable = %d (%v)", code, body)
	}

	// Find the record that was rendered second; its live tag is "US-2".
	h.svc.mu.RLock()
	index := make(map[string]string, len(h.svc.tagByID))
	for k, v := range h.svc.tagByID {
		index[k] = v
	}
	h.svc.mu.RUnlock()

	var renamedID string
	for id, tag := range index {
		if tag == "US-2" {
			renamedID = id
		}
	}
	if renamedID == "" {
		t.Fatalf("no node rendered as US-2; index = %v", index)
	}

	code, body := h.do(http.MethodPost, "/api/proxy/select",
		fmt.Sprintf(`{"node_id":%q}`, renamedID))
	if code != http.StatusOK {
		t.Fatalf("select = %d (%v)", code, body)
	}
	picks := h.sel.selected()
	if got := picks[len(picks)-1]; got != "US-2" {
		t.Errorf("selector got %q, want the deduped tag %q", got, "US-2")
	}
}

func TestSelectPersistsWhileStopped(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	target := h.store.All()[1]

	code, body := h.do(http.MethodPost, "/api/proxy/select",
		fmt.Sprintf(`{"node_id":%q}`, target.ID))
	if code != http.StatusOK {
		t.Fatalf("select = %d (%v)", code, body)
	}
	// Nothing to apply to yet, and the response must say so rather than claim
	// the node is live.
	if body["applied"] != false {
		t.Errorf("applied = %v with a stopped engine, want false", body["applied"])
	}
	if len(h.sel.selected()) != 0 {
		t.Error("pushed a selection to a stopped engine")
	}

	buf, err := os.ReadFile(h.svc.cfg.StatePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var st State
	if err := json.Unmarshal(buf, &st); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if st.SelectedNodeID != target.ID {
		t.Errorf("persisted node id = %q, want %q", st.SelectedNodeID, target.ID)
	}
	if st.AutoSelect {
		t.Error("auto_select should be false after an explicit pick")
	}
}

func TestSelectUnknownNodeIs404(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	code, _ := h.do(http.MethodPost, "/api/proxy/select", `{"node_id":"deadbeef"}`)
	if code != http.StatusNotFound {
		t.Errorf("unknown node = %d, want 404", code)
	}
}

func TestSelectValidatesRequest(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	for _, tc := range []struct{ name, body string }{
		{"empty", `{}`},
		{"auto with node", `{"auto":true,"node_id":"x"}`},
		{"both id and tag", `{"node_id":"x","tag":"y"}`},
		{"unknown field", `{"nope":1}`},
		{"malformed", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := h.do(http.MethodPost, "/api/proxy/select", tc.body)
			if code != http.StatusBadRequest {
				t.Errorf("body %s = %d, want 400", tc.body, code)
			}
		})
	}
}

func TestSelectWithoutControlAPI(t *testing.T) {
	h := newHarness(t, testNodes(), func(c *Config) { c.Selector = nil })
	if code, body := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatalf("enable = %d (%v)", code, body)
	}
	target := h.store.All()[0]
	code, body := h.do(http.MethodPost, "/api/proxy/select",
		fmt.Sprintf(`{"node_id":%q}`, target.ID))
	if code != http.StatusServiceUnavailable {
		t.Fatalf("select without a control API = %d, want 503 (%v)", code, body)
	}
}

// --- POST /api/nodes/refresh ------------------------------------------------

func TestRefreshFetchesParsesAndProbes(t *testing.T) {
	// A subscription server serving two links, one of them malformed.
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("subscription fetched without a User-Agent")
		}
		io.WriteString(w, strings.Join([]string{
			"vless://33333333-3333-3333-3333-333333333333@fresh.example.com:443?security=tls#fresh",
			"not-a-link",
			"trojan://pw@second.example.com:8443?security=tls#second",
		}, "\n"))
	}))
	defer sub.Close()

	h := newHarness(t, nil, func(c *Config) {
		c.SubscriptionURLs = []string{sub.URL}
		c.Tester = &fakeTester{results: func(nodes []subscription.Node) []tester.Result {
			out := make([]tester.Result, len(nodes))
			for i, n := range nodes {
				if n.Tag == "second" {
					out[i] = tester.Result{Tag: n.Tag, Err: errors.New("handshake timeout")}
					continue
				}
				out[i] = tester.Result{Tag: n.Tag, Latency: 120 * time.Millisecond}
			}
			return out
		}}
	})

	code, body := h.do(http.MethodPost, "/api/nodes/refresh", "")
	// 202: the sweep is asynchronous because it can run for minutes.
	if code != http.StatusAccepted {
		t.Fatalf("refresh = %d, want 202 (%v)", code, body)
	}

	job := h.waitForJob(t, "succeeded")
	if job.NodesParsed != 2 {
		t.Errorf("NodesParsed = %d, want 2 (the malformed line is skipped)", job.NodesParsed)
	}
	if job.NodesAdded != 2 {
		t.Errorf("NodesAdded = %d, want 2", job.NodesAdded)
	}
	if job.Reachable != 1 {
		t.Errorf("Reachable = %d, want 1", job.Reachable)
	}
	if len(job.Warnings) == 0 {
		t.Error("the malformed link should have produced a warning")
	}

	// Latency landed on the right records.
	var fresh, second *store.Record
	for _, rec := range h.store.All() {
		switch rec.Node.Tag {
		case "fresh":
			r := rec
			fresh = &r
		case "second":
			r := rec
			second = &r
		}
	}
	if fresh == nil || second == nil {
		t.Fatalf("expected both nodes in the store, got %d", h.store.Len())
	}
	if fresh.LastLatencyMS != 120 {
		t.Errorf("fresh latency = %d, want 120", fresh.LastLatencyMS)
	}
	if second.LastLatencyMS != store.LatencyUnmeasured {
		t.Errorf("failed node latency = %d, want -1", second.LastLatencyMS)
	}
	if !strings.Contains(second.LastError, "handshake timeout") {
		t.Errorf("failed node LastError = %q", second.LastError)
	}
}

// TestRefreshReloadsRunningEngine: without this, new nodes sit in the store
// while the engine keeps serving the old set.
func TestRefreshReloadsRunningEngine(t *testing.T) {
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w,
			"vless://44444444-4444-4444-4444-444444444444@added.example.com:443?security=tls#added")
	}))
	defer sub.Close()

	h := newHarness(t, testNodes(), func(c *Config) { c.SubscriptionURLs = []string{sub.URL} })
	if code, body := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatalf("enable = %d (%v)", code, body)
	}
	before := len(h.eng.applied)

	if code, _ := h.do(http.MethodPost, "/api/nodes/refresh", ""); code != http.StatusAccepted {
		t.Fatal("refresh not accepted")
	}
	job := h.waitForJob(t, "succeeded")
	if !job.EngineReloaded {
		t.Error("EngineReloaded = false; the running engine kept the stale node set")
	}
	if len(h.eng.applied) <= before {
		t.Errorf("engine.Apply calls = %d, want more than %d", len(h.eng.applied), before)
	}
	last := h.eng.applied[len(h.eng.applied)-1]
	var found bool
	for _, n := range last {
		if n.Server == "added.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("the newly fetched node was not in the reloaded config")
	}
}

func TestRefreshRejectsConcurrentRuns(t *testing.T) {
	release := make(chan struct{})
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // hold the first job inside its fetch
		io.WriteString(w,
			"vless://55555555-5555-5555-5555-555555555555@slow.example.com:443?security=tls#slow")
	}))
	defer sub.Close()

	h := newHarness(t, nil, func(c *Config) { c.SubscriptionURLs = []string{sub.URL} })
	if code, _ := h.do(http.MethodPost, "/api/nodes/refresh", ""); code != http.StatusAccepted {
		t.Fatal("first refresh not accepted")
	}
	// Wait until the job is actually running before racing it.
	deadline := time.Now().Add(2 * time.Second)
	for h.svc.JobStatus().State != "running" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	code, body := h.do(http.MethodPost, "/api/nodes/refresh", "")
	if code != http.StatusConflict {
		t.Errorf("second refresh = %d, want 409 (%v)", code, body)
	}
	close(release)
	h.waitForJob(t, "succeeded")
}

func TestRefreshWithoutSubscriptions(t *testing.T) {
	h := newHarness(t, nil, nil)
	code, body := h.do(http.MethodPost, "/api/nodes/refresh", "")
	// 503 rather than 400: the request is valid, the server lacks -sub. A client
	// that retries this exact request succeeds once the operator configures one.
	if code != http.StatusServiceUnavailable {
		t.Errorf("refresh with no sources = %d, want 503 (%v)", code, body)
	}
}

func TestRefreshFailsWhenSourceIsDown(t *testing.T) {
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusInternalServerError)
	}))
	defer sub.Close()

	h := newHarness(t, nil, func(c *Config) { c.SubscriptionURLs = []string{sub.URL} })
	if code, _ := h.do(http.MethodPost, "/api/nodes/refresh", ""); code != http.StatusAccepted {
		t.Fatal("refresh not accepted")
	}
	job := h.waitForJob(t, "failed")
	if job.Error == "" {
		t.Error("failed job carries no error message")
	}
}

// TestRefreshFromLocalFile covers the file-backed subscription path, which lets
// the gateway run without a provider reachable.
func TestRefreshFromLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub.txt")
	if err := os.WriteFile(path,
		[]byte("vless://66666666-6666-6666-6666-666666666666@file.example.com:443?security=tls#fromfile"),
		0o600); err != nil {
		t.Fatalf("write sub: %v", err)
	}

	h := newHarness(t, nil, func(c *Config) { c.SubscriptionURLs = []string{path} })
	if code, _ := h.do(http.MethodPost, "/api/nodes/refresh", ""); code != http.StatusAccepted {
		t.Fatal("refresh not accepted")
	}
	job := h.waitForJob(t, "succeeded")
	if job.NodesAdded != 1 {
		t.Errorf("NodesAdded = %d, want 1", job.NodesAdded)
	}
}

// TestRefreshSkipsPruneWhenASourceFails guards the store against a provider
// serving a truncated list during an outage.
func TestRefreshSkipsPruneWhenASourceFails(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w,
			"vless://77777777-7777-7777-7777-777777777777@kept.example.com:443?security=tls#kept")
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer bad.Close()

	h := newHarness(t, testNodes(), func(c *Config) {
		c.SubscriptionURLs = []string{good.URL, bad.URL}
	})
	before := h.store.Len()

	if code, _ := h.do(http.MethodPost, "/api/nodes/refresh?prune=true", ""); code != http.StatusAccepted {
		t.Fatal("refresh not accepted")
	}
	job := h.waitForJob(t, "succeeded")
	if job.NodesPruned != 0 {
		t.Errorf("NodesPruned = %d; a partial fetch must not delete records", job.NodesPruned)
	}
	if h.store.Len() < before {
		t.Errorf("store shrank from %d to %d despite a failed source", before, h.store.Len())
	}
}

func (h *harness) waitForJob(t *testing.T, want string) JobStatus {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		job := h.svc.JobStatus()
		switch job.State {
		case want:
			return job
		case "succeeded", "failed":
			t.Fatalf("job state = %q, want %q (error: %s, warnings: %v)",
				job.State, want, job.Error, job.Warnings)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job did not reach %q in time; last = %+v", want, h.svc.JobStatus())
	return JobStatus{}
}

// --- auth, status, restore --------------------------------------------------

func TestTokenAuth(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	srv := httptest.NewServer(NewRouter(h.svc, RouterOptions{
		Token: "s3cret", Logger: quietLogger()}))
	defer srv.Close()

	get := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/nodes", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(""); code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", code)
	}
	if code := get("wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token = %d, want 401", code)
	}
	if code := get("s3cret"); code != http.StatusOK {
		t.Errorf("valid token = %d, want 200", code)
	}

	// Health checks stay open so systemd and monitoring work without the token.
	resp, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz with auth on = %d, want 200", resp.StatusCode)
	}
}

func TestStatusReportsEverything(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	recs := h.store.All()
	if err := h.store.RecordLatency(recs[0].ID, 90*time.Millisecond); err != nil {
		t.Fatalf("record latency: %v", err)
	}
	if code, _ := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatal("enable failed")
	}

	code, body := h.do(http.MethodGet, "/api/status", "")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for key, want := range map[string]any{
		"proxy_enabled":       true,
		"engine_running":      true,
		"tproxy_rules_loaded": true,
		"nodes_total":         float64(2),
		"nodes_enabled":       float64(2),
		"nodes_healthy":       float64(1),
	} {
		if body[key] != want {
			t.Errorf("%s = %v, want %v", key, body[key], want)
		}
	}
}

// TestRestoreReenablesProxy: a systemd restart must not silently leave the
// gateway in a different state than the operator set.
func TestRestoreReenablesProxy(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	if code, _ := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatal("enable failed")
	}

	// Second service over the same files, as if the process restarted.
	calls := &callLog{}
	eng := &fakeEngine{log: calls}
	fw := &fakeFirewall{log: calls}
	defer eng.close()

	svc2, err := New(Config{
		Store: h.store, Engine: eng, Firewall: fw,
		Tester: &fakeTester{}, Selector: &fakeSelector{},
		StatePath: h.svc.cfg.StatePath, Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := svc2.Restore(context.Background()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !eng.Running() {
		t.Error("engine not started by Restore despite persisted enabled state")
	}
	if loaded, _ := fw.Status(context.Background()); !loaded {
		t.Error("rules not loaded by Restore")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := svc2.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// TestRestoreClearsStaleRules covers an unclean previous exit (SIGKILL, power
// loss) that left interception rules with no engine behind them.
func TestRestoreClearsStaleRules(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	// Proxy is off in state, but rules are loaded: exactly the post-crash shape.
	h.fw.mu.Lock()
	h.fw.loaded = true
	h.fw.mu.Unlock()

	if err := h.svc.Restore(context.Background()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if loaded, _ := h.fw.Status(context.Background()); loaded {
		t.Error("stale ruleset left loaded with the proxy off; LAN would be blackholed")
	}
	if h.eng.Running() {
		t.Error("Restore started the engine even though the proxy was off")
	}
}

func TestShutdownTearsDownInSafeOrder(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	if code, _ := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatal("enable failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.svc.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	calls := h.calls.snapshot()
	var rm, stop = -1, -1
	for i, c := range calls {
		switch c {
		case "fw.Remove":
			rm = i
		case "engine.Stop":
			stop = i
		}
	}
	if rm < 0 || stop < 0 {
		t.Fatalf("teardown incomplete: %v", calls)
	}
	if rm > stop {
		t.Errorf("rules removed after engine stop: %v", calls)
	}
	if h.eng.Running() {
		t.Error("engine still running after Shutdown")
	}
	if loaded, _ := h.fw.Status(context.Background()); loaded {
		t.Error("rules still loaded after Shutdown")
	}
}

// A never-enabled server still sweeps for rules a previous unclean exit may have
// left behind, but a failing sweep is not an error there: on a box without nft
// that noise would drown out the one message that matters, which is a failed
// sweep while interception was actually live.
func TestShutdownSweepsButIgnoresFailureWhenNeverEnabled(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	h.fw.rmErr = errors.New("missing dependency: nft")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.svc.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown on never-enabled server = %v, want nil", err)
	}
	if h.calls.indexOf("fw.Remove") < 0 {
		t.Errorf("no rule sweep attempted: %v", h.calls.snapshot())
	}
}

// The mirror of the above: once interception is live, a sweep that fails means
// the LAN is still being intercepted with nothing to serve it, so it must surface.
func TestShutdownReportsSweepFailureWhenEnabled(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	if code, _ := h.do(http.MethodPost, "/api/proxy/toggle", `{"enabled":true}`); code != 200 {
		t.Fatal("enable failed")
	}
	h.fw.rmErr = errors.New("missing dependency: nft")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.svc.Shutdown(ctx); err == nil {
		t.Error("Shutdown hid a failed rule removal while interception was live")
	}
}
