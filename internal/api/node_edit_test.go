package api

import (
	"context"
	"net/http"
	"path/filepath"
	"hoolan/internal/engine"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
	"testing"
	"time"
)

func TestDeleteAndChainRoutes(t *testing.T) {
	h := newLocalHarness(t, testNodes(), nil)
	all := h.store.All()
	a, b := all[0].ID, all[1].ID
	if err := h.svc.SetNodeDetour(context.Background(), a, b); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.SetNodeDetour(context.Background(), b, a); err == nil {
		t.Fatal("cycle accepted")
	}
	if err := h.svc.DeleteManual(context.Background(), b); err == nil {
		t.Fatal("dependent node deleted")
	}
	if err := h.svc.SetNodeDetour(context.Background(), a, ""); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.DeleteManual(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Get(b); err == nil {
		t.Fatal("node retained")
	}
}
func TestLoginDocumentRouting(t *testing.T) {
	router := NewRouter(nil, RouterOptions{Token: "secret", Logger: quietLogger()})
	for _, path := range []string{"/", "/index.html"} {
		w := authRequest(router, "GET", path, "", nil, "")
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login.html" {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/login", "/login/", "/login.html", "/login.js"} {
		if w := authRequest(router, "GET", path, "", nil, ""); w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	login := authRequest(router, "POST", "/api/auth/login", `{"token":"secret"}`, nil, "")
	if w := authRequest(router, "GET", "/", "", login.Result().Cookies()[0], ""); w.Code != 200 {
		t.Fatalf("authenticated dashboard %d", w.Code)
	}
}

type fakeRuleEngine struct {
	*fakeEngine
	policy engine.RulePolicy
}

func (f *fakeRuleEngine) ConfigureRulePolicy(p engine.RulePolicy, _ map[string]string) error {
	f.policy = engine.CloneRulePolicy(p)
	return nil
}
func (f *fakeRuleEngine) FetchRuleSets(context.Context, engine.RulePolicy) (map[string]string, error) {
	return map[string]string{f.policy.GeoIPURL: "/tmp/ip.srs", f.policy.GeositeURL: "/tmp/site.srs"}, nil
}
func TestRulesPersistAndUpdateWhileOff(t *testing.T) {
	h := newLocalHarness(t, testNodes(), func(c *Config) { c.Engine = &fakeRuleEngine{fakeEngine: c.Engine.(*fakeEngine)} })
	p := engine.DefaultRulePolicy()
	p.Schedule = "weekly"
	p.TimeOfDay = "04:00"
	p.Weekday = 5
	p.Timezone = "Asia/Tehran"
	if _, err := h.svc.UpdateRules(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	before := h.svc.Rules()
	if before.NextUpdate.IsZero() {
		t.Fatal("calendar missing")
	}
	if _, err := h.svc.StartRuleUpdate(); err != nil {
		t.Fatal(err)
	}
	h.waitForJob(t, "succeeded")
	status := h.svc.Rules()
	if len(status.Files) != 2 || time.Since(status.LastUpdate) > time.Minute {
		t.Fatalf("status %+v", status)
	}
	if h.eng.Running() {
		t.Fatal("updating rules enabled stopped proxy")
	}
}

// State-only harness: these tests exercise handlers/services without opening sockets.
func newLocalHarness(t *testing.T, nodes []subscription.Node, mutate func(*Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.UpsertNodes(nodes); err != nil {
		t.Fatal(err)
	}
	calls := &callLog{}
	eng := &fakeEngine{log: calls}
	fw := &fakeFirewall{log: calls}
	sel := &fakeSelector{}
	cfg := Config{Store: st, Engine: eng, Firewall: fw, Selector: sel, StatePath: filepath.Join(dir, "state.json"), Logger: quietLogger()}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.jobCancel(); svc.jobs.Wait() })
	return &harness{t: t, svc: svc, eng: eng, fw: fw, sel: sel, calls: calls, store: st, dir: dir}
}
