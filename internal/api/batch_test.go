package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"hoolan/internal/engine"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
	"hoolan/internal/tester"
	"strings"
	"testing"
	"time"
)

type syncTransport struct{ feeds map[string]string }

func (f *syncTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, ok := f.feeds[r.URL.String()]
	if !ok {
		return nil, fmt.Errorf("fetch failed")
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}
func syncHarness(t *testing.T) (*harness, *syncTransport) {
	transport := &syncTransport{feeds: map[string]string{"https://first.test/sub": providerLink + "\n" + manualLink, "https://second.test/sub": manualLink}}
	h := newLocalHarness(t, nil, func(c *Config) {
		c.SubscriptionURLs = []string{"https://first.test/sub", "https://second.test/sub"}
		c.HTTPClient = &http.Client{Transport: transport}
	})
	return h, transport
}
func TestStrictSyncPerSourceAndEmptyFeed(t *testing.T) {
	h, transport := syncHarness(t)
	ctx := context.Background()
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	first := h.svc.subscriptionSnapshot()[0]
	transport.feeds[first.URL] = ""
	if _, err := h.svc.StartSubscriptionRefresh(first.ID); err != nil {
		t.Fatal(err)
	}
	h.waitForJob(t, "succeeded")
	if h.store.Len() != 1 {
		t.Fatalf("stale node retained: %d", h.store.Len())
	}
	if len(h.svc.subscriptionSnapshot()[0].NodeIDs) != 0 {
		t.Fatal("empty feed did not clear membership")
	}
	// A failed second source does not stop the first source from being synchronized.
	transport.feeds[first.URL] = providerLink
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	transport.feeds[first.URL] = ""
	delete(transport.feeds, "https://second.test/sub")
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	if h.store.Len() != 1 {
		t.Fatal("failed source prevented successful source pruning")
	}
	transport.feeds["https://second.test/sub"] = "not a subscription"
	if err := h.svc.refreshSources(ctx, []Subscription{h.svc.subscriptionSnapshot()[1]}, true); err == nil {
		t.Fatal("malformed feed accepted")
	}
	if h.store.Len() != 1 {
		t.Fatal("malformed feed pruned previous nodes")
	}
}
func TestStrictSyncKeepsExplicitManualOwnership(t *testing.T) {
	h, transport := syncHarness(t)
	ctx := context.Background()
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	id, err := h.svc.AddManualNode(ctx, providerLink)
	if err != nil {
		t.Fatal(err)
	}
	transport.feeds["https://first.test/sub"] = ""
	transport.feeds["https://second.test/sub"] = ""
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Get(id); err != nil || h.store.Len() != 1 {
		t.Fatalf("manual ownership lost: %v", err)
	}
}
func TestSavedChainIsIndependentAndBulkDeletedTogether(t *testing.T) {
	h, transport := syncHarness(t)
	ctx := context.Background()
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	original := h.store.All()
	ids := []string{original[0].ID, original[1].ID}
	exit, err := h.svc.CreateChain(ctx, "My chain", ids)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := h.store.Get(exit)
	if rec.DetourID == "" || rec.Node.ChainInternal || rec.ID == ids[1] {
		t.Fatal("exit is not an independent configuration")
	}
	for _, r := range original {
		current, _ := h.store.Get(r.ID)
		if current.DetourID != "" || current.Node.Detour != "" {
			t.Fatal("source config mutated")
		}
	}
	transport.feeds["https://first.test/sub"] = ""
	transport.feeds["https://second.test/sub"] = ""
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	if h.store.Len() != 2 {
		t.Fatalf("chain snapshots should survive pruning, got %d", h.store.Len())
	}
	live := h.store.EnabledNodes()
	if err := subscription.ValidateChains(live); err != nil {
		t.Fatal(err)
	}
	m := engine.NewManager(engine.Options{DisableIranBypass: true, Logger: quietLogger()})
	cfg, err := m.BuildConfig(live)
	if err != nil {
		t.Fatal(err)
	}
	for _, ob := range cfg.Outbounds {
		if sel, ok := ob.(*engine.SelectorOutbound); ok {
			if len(sel.Outbounds) != 1 || sel.Outbounds[0] != "My chain" {
				t.Fatalf("internal hops selectable: %+v", sel)
			}
		}
	}
	count, err := h.svc.DeleteNodes(ctx, []string{exit})
	if err != nil || count != 1 || h.store.Len() != 0 {
		t.Fatalf("delete chain: %d %v remaining=%d", count, err, h.store.Len())
	}
}
func TestBulkValidationAndLatencyScope(t *testing.T) {
	h := newLocalHarness(t, testNodes(), nil)
	records := h.store.All()
	id := records[0].ID
	if _, err := h.svc.DeleteNodes(context.Background(), []string{id, "missing"}); err == nil {
		t.Fatal("invalid batch accepted")
	}
	if h.store.Len() != len(records) {
		t.Fatal("partial batch deletion")
	}
	var tested []subscription.Node
	h.svc.cfg.Tester = &fakeTester{results: func(nodes []subscription.Node) []tester.Result {
		tested = nodes
		results := make([]tester.Result, len(nodes))
		for i := range nodes {
			results[i] = tester.Result{Latency: time.Millisecond}
		}
		return results
	}}
	if _, err := h.svc.StartBulkLatency([]string{id, id}); err != nil {
		t.Fatal(err)
	}
	h.waitForJob(t, "succeeded")
	if len(tested) != 1 || store.NodeID(tested[0]) != id {
		t.Fatal("bulk latency scope not honored")
	}
	router := NewRouter(h.svc, RouterOptions{Logger: quietLogger()})
	w := authRequest(router, http.MethodPost, "/api/nodes/delete", fmt.Sprintf(`{"node_ids":[%q]}`, id), nil, "")
	if w.Code != 200 {
		t.Fatalf("array delete %d: %s", w.Code, w.Body.String())
	}
	if _, err := h.svc.CreateChain(context.Background(), "loop", []string{records[1].ID, records[1].ID}); err == nil {
		t.Fatal("duplicate hop accepted")
	}
}

func TestThreeHopOrderAndHiddenCopiesPersist(t *testing.T) {
	nodes := testNodes()
	third := nodes[0]
	third.Server = "third.example"
	third.Tag = "third"
	nodes = append(nodes, third)
	h := newLocalHarness(t, nodes, nil)
	order := []string{store.NodeID(nodes[0]), store.NodeID(nodes[1]), store.NodeID(nodes[2])}
	exit, err := h.svc.CreateChain(context.Background(), "Three hops", order)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := 2, exit; i >= 0; i-- {
		r, err := h.store.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if r.Node.Server != nodes[i].Server {
			t.Fatalf("hop %d has %s", i, r.Node.Server)
		}
		id = r.DetourID
		if i == 0 && id != "" {
			t.Fatal("first hop has a detour")
		}
	}
	loaded, err := store.Open(h.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	r, err := loaded.Get(exit)
	if err != nil || r.ChainID == "" || r.DetourID == "" {
		t.Fatal("chain did not persist")
	}
	router := NewRouter(h.svc, RouterOptions{Logger: quietLogger()})
	result := authRequest(router, http.MethodGet, "/api/nodes", "", nil, "")
	if result.Code != 200 {
		t.Fatalf("inventory %d", result.Code)
	}
	// Only originals and one saved exit should be returned, never private hop rows.
	if strings.Contains(result.Body.String(), "Three hops · hop") {
		t.Fatal("internal hop leaked into visible inventory")
	}
	if len(h.store.All()) != 6 {
		t.Fatal("expected three independent copies")
	}
}

func TestEmptySyncStopsLastRunningConfiguration(t *testing.T) {
	h, transport := syncHarness(t)
	transport.feeds["https://first.test/sub"] = providerLink
	transport.feeds["https://second.test/sub"] = ""
	if err := h.svc.refresh(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	h.eng.mu.Lock()
	h.eng.running = true
	h.eng.mu.Unlock()
	h.svc.mu.Lock()
	h.svc.proxyEnabled = true
	h.svc.state.ProxyEnabled = true
	h.svc.mu.Unlock()
	start := len(h.calls.snapshot())
	transport.feeds["https://first.test/sub"] = ""
	if err := h.svc.refresh(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(h.calls.snapshot()[start:], ",")
	if calls != "fw.Remove,engine.Stop" {
		t.Fatalf("unsafe shutdown order: %s", calls)
	}
	if h.eng.Running() || h.svc.state.ProxyEnabled || h.store.Len() != 0 {
		t.Fatal("empty sync left proxy enabled")
	}
}
