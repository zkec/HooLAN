package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"proxy-manager/internal/store"
	"proxy-manager/internal/subscription"
	"proxy-manager/internal/tester"
)

const manualLink = "vless://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@manual.example:443?security=tls#Manual"
const providerLink = "vless://bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@provider.example:443?security=tls#Provider"

func addTestManual(t *testing.T, h *harness) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"link": manualLink})
	code, response := h.do(http.MethodPost, "/api/nodes", string(body))
	if code != 201 {
		t.Fatalf("add manual: %d %v", code, response)
	}
	return response["node_id"].(string)
}

func addTestSubscription(t *testing.T, h *harness, url string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": "Provider", "url": url})
	code, response := h.do(http.MethodPost, "/api/subscriptions", string(body))
	if code != 201 {
		t.Fatalf("add subscription: %d %v", code, response)
	}
	return response["id"].(string)
}

func TestDashboardSourcesPersistAndPrunePreservesManual(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, providerLink) }))
	defer provider.Close()
	h := newHarness(t, nil, nil)
	manual := addTestManual(t, h)
	subID := addTestSubscription(t, h, provider.URL)
	if _, err := h.svc.StartRefresh(true); err != nil {
		t.Fatal(err)
	}
	h.waitForJob(t, "succeeded")
	if _, err := h.store.Get(manual); err != nil {
		t.Fatal("prune deleted manual config:", err)
	}
	if h.store.Len() != 2 {
		t.Fatalf("want manual + provider, got %d", h.store.Len())
	}
	if subs := h.svc.Subscriptions(); len(subs) != 1 || subs[0].NodeCount != 1 {
		t.Fatalf("source membership: %+v", subs)
	}
	reloaded, err := New(h.svc.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.jobCancel()
	if len(reloaded.Subscriptions()) != 1 || reloaded.Subscriptions()[0].ID != subID {
		t.Fatal("subscription was not persisted")
	}
	if sources, manualFlag := reloaded.NodeOrigins(manual); !manualFlag || len(sources) != 0 {
		t.Fatalf("manual source lost: %v %v", sources, manualFlag)
	}
	info, err := os.Stat(h.svc.cfg.StatePath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("state stores subscription URLs and must be 0600: %v %v", info, err)
	}
}

func TestSharedNodeKeepsManualAndSubscriptionMembership(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, manualLink) }))
	defer provider.Close()
	h := newHarness(t, nil, nil)
	id := addTestManual(t, h)
	sub := addTestSubscription(t, h, provider.URL)
	if _, err := h.svc.StartSubscriptionRefresh(sub); err != nil {
		t.Fatal(err)
	}
	h.waitForJob(t, "succeeded")
	if h.store.Len() != 1 {
		t.Fatal("duplicate record created for shared config")
	}
	sources, manual := h.svc.NodeOrigins(id)
	if !manual || !reflect.DeepEqual(sources, []string{sub}) {
		t.Fatalf("origins: %v manual=%v", sources, manual)
	}
}

func TestManualLatencyAndSubscriptionLatencyAreScoped(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, providerLink) }))
	defer provider.Close()
	h := newHarness(t, nil, nil)
	manual := addTestManual(t, h)
	if _, err := h.svc.Select(context.Background(), false, manual); err != nil {
		t.Fatal(err)
	}
	sub := addTestSubscription(t, h, provider.URL)
	if _, err := h.svc.StartSubscriptionRefresh(sub); err != nil {
		t.Fatal(err)
	}
	h.waitForJob(t, "succeeded")
	var tested []string
	h.svc.cfg.Tester = &fakeTester{results: func(nodes []subscription.Node) []tester.Result {
		tested = nil
		results := make([]tester.Result, len(nodes))
		for i, node := range nodes {
			tested = append(tested, node.Server)
			results[i] = tester.Result{Tag: node.Tag, Latency: 42 * time.Millisecond}
		}
		return results
	}}
	code, response := h.do(http.MethodPost, "/api/nodes/test", `{"node_id":"`+manual+`"}`)
	if code != 202 {
		t.Fatalf("single test: %d %v", code, response)
	}
	h.waitForJob(t, "succeeded")
	if !reflect.DeepEqual(tested, []string{"manual.example"}) {
		t.Fatalf("single test scope: %v", tested)
	}
	code, response = h.do(http.MethodPost, "/api/subscriptions/test", `{"subscription_id":"`+sub+`"}`)
	if code != 202 {
		t.Fatalf("bulk test: %d %v", code, response)
	}
	job := h.waitForJob(t, "succeeded")
	if !reflect.DeepEqual(tested, []string{"provider.example"}) || job.Tested != 1 {
		t.Fatalf("subscription scope: %v %+v", tested, job)
	}
	rec, _ := h.store.Get(manual)
	if rec.LastLatencyMS != 42 {
		t.Fatalf("latency not recorded: %+v", rec)
	}
}

func TestManualRefreshSkipsAutomaticLatency(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, providerLink) }))
	defer provider.Close()
	probed := false
	h := newHarness(t, testNodes(), func(cfg *Config) {
		cfg.Tester = &fakeTester{results: func(nodes []subscription.Node) []tester.Result {
			probed = true
			return nil
		}}
	})
	if _, err := h.svc.Select(context.Background(), false, h.store.All()[0].ID); err != nil {
		t.Fatal(err)
	}
	addTestSubscription(t, h, provider.URL)
	if err := h.svc.refresh(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if probed {
		t.Fatal("manual refresh launched an automatic latency sweep")
	}
}

func TestDashboardRejectsInvalidInputs(t *testing.T) {
	h := newHarness(t, nil, nil)
	for _, tc := range []struct {
		path, body string
		code       int
	}{
		{"/api/nodes", `{"link":"vless://invalid"}`, 400},
		{"/api/subscriptions", `{"url":"file:///etc/passwd"}`, 400},
		{"/api/subscriptions", `{"url":"https://example.com/sub"} {}`, 400},
		{"/api/nodes/test", `{"node_id":"unknown"}`, 404},
		{"/api/subscriptions/test", `{"subscription_id":"unknown"}`, 404},
	} {
		if code, response := h.do(http.MethodPost, tc.path, tc.body); code != tc.code {
			t.Errorf("%s: %d %v", tc.path, code, response)
		}
	}
	if h.store.Len() != 0 || len(h.svc.Subscriptions()) != 0 {
		t.Fatal("invalid input mutated inventory")
	}
}

type configurableTestEngine struct {
	*fakeEngine
	settings Settings
}

func (f *configurableTestEngine) ConfigureRouting(dns string, iran bool) error {
	f.settings = Settings{DNSServer: dns, IranBypass: iran}
	return nil
}

func TestSettingsPersistAndReloadInSafeOrder(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	eng := &configurableTestEngine{fakeEngine: h.eng}
	h.svc.cfg.Engine = eng
	if err := h.svc.SetProxyEnabled(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	h.calls.mu.Lock()
	h.calls.calls = nil
	h.calls.mu.Unlock()
	code, response := h.do(http.MethodPut, "/api/settings", `{"dns_server":"9.9.9.9:5353","iran_bypass":false}`)
	if code != 200 {
		t.Fatalf("update settings: %d %v", code, response)
	}
	if eng.settings != (Settings{DNSServer: "9.9.9.9:5353", IranBypass: false}) {
		t.Fatalf("engine settings: %+v", eng.settings)
	}
	calls := h.calls.snapshot()
	if len(calls) < 4 || calls[0] != "fw.Remove" || h.calls.indexOf("engine.Apply") > h.calls.indexOf("fw.Apply") {
		t.Fatalf("unsafe reload order: %v", calls)
	}
	reloaded, err := New(h.svc.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.jobCancel()
	if reloaded.Settings() != h.svc.Settings() {
		t.Fatal("settings not persisted")
	}
	if code, _ := h.do(http.MethodPut, "/api/settings", `{"dns_server":"https://resolver.example/dns-query"}`); code != 400 {
		t.Fatalf("invalid DNS accepted: %d", code)
	}
}

func TestFailedSettingsReloadRemovesInterceptionAndRestoresSettings(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	h.svc.cfg.Engine = &configurableTestEngine{fakeEngine: h.eng}
	if err := h.svc.SetProxyEnabled(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	previous := h.svc.Settings()
	h.eng.applyErr = errors.New("engine config rejected")
	if _, err := h.svc.UpdateSettings(context.Background(), Settings{DNSServer: "8.8.8.8", IranBypass: false}); err == nil {
		t.Fatal("failed reload reported success")
	}
	if loaded, _ := h.fw.Status(context.Background()); loaded {
		t.Fatal("interception retained after failed restart")
	}
	if h.svc.Settings() != previous {
		t.Fatal("failed settings were retained")
	}
	if h.svc.Status(context.Background()).ProxyEnabled {
		t.Fatal("failed reload reports enabled")
	}
}

func TestTProxyReadinessRequiresOwnedIPv4TCPAndUDP(t *testing.T) {
	tcp, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	port := tcp.Addr().(*net.TCPAddr).Port
	if ready, err := tproxySocketsReady(os.Getpid(), port); err != nil || ready {
		t.Fatalf("TCP alone passed: %v %v", ready, err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if ready, err := tproxySocketsReady(os.Getpid(), port); err != nil || !ready {
		t.Fatalf("both listeners rejected: %v %v", ready, err)
	}
	if ready, err := tproxySocketsReady(2147483647, port); err != nil || ready {
		t.Fatalf("another PID passed: %v %v", ready, err)
	}
}

func TestReadinessRejectsLoopbackAndUnownedSockets(t *testing.T) {
	for _, tc := range []struct{ address, inode string }{{"0100007F", "123"}, {"00000000", "456"}, {"00000000000000000000000000000000", "123"}} {
		line := "0: " + tc.address + ":1ED4 00000000:0000 0A 0:0 00:0 0 0 0 " + tc.inode + " 1\n"
		if ready, err := scanOwnedIPv4Socket(strings.NewReader(line), 7892, "0A", map[string]bool{"123": true}); err != nil || ready {
			t.Fatalf("bad listener accepted: %+v %v", tc, err)
		}
	}
}

// An in-flight source fetch and a manual addition can overlap; ingestion must
// merge metadata rather than replace the manual node's identity.
func TestRefreshDoesNotPruneManualAddedDuringFetch(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		io.WriteString(w, providerLink)
	}))
	defer provider.Close()
	h := newHarness(t, nil, nil)
	addTestSubscription(t, h, provider.URL)
	if _, err := h.svc.StartRefresh(true); err != nil {
		t.Fatal(err)
	}
	<-entered
	id := addTestManual(t, h)
	close(release)
	h.waitForJob(t, "succeeded")
	if _, err := h.store.Get(id); errors.Is(err, store.ErrNotFound) {
		t.Fatal("concurrent manual addition pruned")
	}
}
