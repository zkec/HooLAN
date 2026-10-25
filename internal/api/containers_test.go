package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"hoolan/internal/docker"
	"hoolan/internal/netfilter"
)

type fakeDocker struct {
	mu    sync.Mutex
	items []docker.Container
	err   error
}

func (f *fakeDocker) List(context.Context) ([]docker.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := append([]docker.Container(nil), f.items...)
	for i := range items {
		items[i].Bindings = append([]docker.Binding(nil), items[i].Bindings...)
	}
	return items, f.err
}
func (f *fakeDocker) set(items []docker.Container, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items = items
	f.err = err
}

type containerFirewall struct {
	*distributionTestFirewall
	bindings []netfilter.ContainerBinding
}

func (f *containerFirewall) ConfigureContainers(b []netfilter.ContainerBinding) error {
	f.bindings = append([]netfilter.ContainerBinding(nil), b...)
	return nil
}
func containerSample() docker.Container {
	return docker.Container{ID: strings.Repeat("b", 64), Key: strings.Repeat("a", 64), Name: "app", Image: "app:latest", State: "running", Mode: "stack", Supported: true, Bindings: []docker.Binding{{IP: "172.18.0.3", Bridge: "br-stack", Network: "stack"}, {IP: "172.19.0.3", Bridge: "br-other", Network: "other"}}}
}
func containerHarness(t *testing.T) (*harness, *containerFirewall, *fakeDocker) {
	d := &fakeDocker{items: []docker.Container{containerSample()}}
	var fw *containerFirewall
	h := newLocalHarness(t, testNodes(), func(c *Config) {
		fw = &containerFirewall{distributionTestFirewall: &distributionTestFirewall{fakeFirewall: c.Firewall.(*fakeFirewall)}}
		c.Firewall = fw
		c.Docker = d
		c.Engine = &deviceEngine{fakeEngine: c.Engine.(*fakeEngine)}
	})
	return h, fw, d
}
func boolptr(v bool) *bool { return &v }
func TestContainerPoliciesPersistAcrossIPsAndRecreation(t *testing.T) {
	h, fw, d := containerHarness(t)
	ctx := context.Background()
	item := containerSample()
	id := h.store.All()[0].ID
	limits := netfilter.DeviceLimits{ProxyUpload: 1, ProxyDownload: 2, DirectUpload: 3, DirectDownload: 4}
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: item.Key, Proxy: boolptr(true), NodeID: &id, QoS: &limits}); err != nil {
		t.Fatal(err)
	}
	state, err := h.svc.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if state.ContainerSettings[item.Key].NodeID != id || state.ContainerSettings[item.Key].QoS != limits {
		t.Fatal("settings not persisted")
	}
	eng := h.svc.cfg.Engine.(*deviceEngine)
	if eng.routes["172.18.0.3"] != id || eng.routes["172.19.0.3"] != id || fw.installed["172.18.0.3"] != limits {
		t.Fatal("endpoints did not receive routes/limits")
	}
	item.ID = strings.Repeat("c", 64)
	item.Bindings[0].IP = "172.18.0.9"
	d.set([]docker.Container{item}, nil)
	if err := h.svc.RefreshContainers(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := eng.routes["172.18.0.3"]; ok {
		t.Fatal("orphaned IP still routed")
	}
	if _, ok := fw.installed["172.18.0.3"]; ok {
		t.Fatal("orphaned IP still rate limited")
	}
	if eng.routes["172.18.0.9"] != id || fw.installed["172.18.0.9"] != limits {
		t.Fatal("policy did not follow recreated container")
	}
	d.set(nil, errors.New("daemon unavailable"))
	if err := h.svc.RefreshContainers(ctx); err == nil {
		t.Fatal("Docker outage ignored")
	}
	if eng.routes["172.18.0.9"] != id {
		t.Fatal("Docker outage lost last good bindings")
	}
	d.set([]docker.Container{item}, nil)
	if err := h.svc.RefreshContainers(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: item.Key, Proxy: boolptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := eng.routes["172.18.0.9"]; ok {
		t.Fatal("direct container entered sing-box routing")
	}
	if fw.installed["172.18.0.9"] != limits {
		t.Fatal("direct mode lost limits")
	}
	d.set(nil, nil)
	if err := h.svc.RefreshContainers(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fw.installed) != 0 || len(fw.bindings) != 0 {
		t.Fatal("deleted container left policies behind")
	}
	if !h.svc.state.ContainerSettings[item.Key].Proxy && h.svc.state.ContainerSettings[item.Key].QoS != limits {
		t.Fatal("saved settings lost on container removal")
	}
}
func TestContainerValidationRollbackAndNodeDelete(t *testing.T) {
	h, fw, _ := containerHarness(t)
	ctx := context.Background()
	key := containerSample().Key
	id := h.store.All()[0].ID
	l := netfilter.UniformLimits(8)
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: key, Proxy: boolptr(true), NodeID: &id, QoS: &l}); err != nil {
		t.Fatal(err)
	}
	fw.failNext = true
	bad := netfilter.UniformLimits(12)
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: key, QoS: &bad}); err == nil {
		t.Fatal("firewall failure accepted")
	}
	if h.svc.state.ContainerSettings[key].QoS != l || fw.installed["172.18.0.3"] != l {
		t.Fatal("failed settings not rolled back")
	}
	for _, req := range []ContainerUpdate{{Key: key}, {Key: "bad", Proxy: boolptr(true)}, {Key: key, NodeID: strptr("direct"), Proxy: boolptr(true)}, {Key: key, NodeID: strptr(strings.Repeat("f", 32))}, {Key: key, QoS: &netfilter.DeviceLimits{ProxyUpload: -1}}} {
		if err := h.svc.UpdateContainer(ctx, req); err == nil {
			t.Fatalf("invalid update accepted: %+v", req)
		}
	}
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: "172.18.0.3", NodeID: strptr("direct")}); err == nil {
		t.Fatal("container IP configurable as LAN device")
	}
	if _, err := h.svc.DeleteNodes(ctx, []string{id}); err != nil {
		t.Fatal(err)
	}
	p := h.svc.state.ContainerSettings[key]
	if p.NodeID != "" || !p.Proxy || p.QoS != l {
		t.Fatal("deleted node did not reset pin and preserve limits/proxy")
	}
}
func TestContainerAPIAuthAndInventory(t *testing.T) {
	h, _, _ := containerHarness(t)
	router := NewRouter(h.svc, RouterOptions{Token: "secret", Logger: quietLogger()})
	for _, path := range []string{"/api/containers", "/api/containers/refresh"} {
		method := "GET"
		if strings.HasSuffix(path, "refresh") {
			method = "POST"
		}
		w := authRequest(router, method, path, "", nil, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("unprotected %s: %d", path, w.Code)
		}
	}
	login := authRequest(router, "POST", "/api/auth/login", `{"token":"secret"}`, nil, "")
	cookie := login.Result().Cookies()[0]
	w := authRequest(router, "GET", "/api/containers", "", cookie, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var response struct {
		Containers []struct {
			docker.Container
			Settings ContainerSettings
		}
		Enabled bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Containers) != 1 || response.Containers[0].Name != "app" || !response.Enabled {
		t.Fatal("inventory missing")
	}
	w = authRequest(router, "PUT", "/api/containers", `{"key":"`+containerSample().Key+`","proxy":true}`, cookie, "")
	if w.Code != http.StatusForbidden {
		t.Fatal("CSRF missing check")
	}
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	w = authRequest(router, "PUT", "/api/containers", `{"key":"`+containerSample().Key+`","proxy":true}`, cookie, session.CSRF)
	if w.Code != 200 {
		t.Fatalf("container update API: %d %s", w.Code, w.Body.String())
	}
}

func TestContainerDiscoveryAndEditsSerialize(t *testing.T) {
	h, fw, _ := containerHarness(t)
	key := containerSample().Key
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			l := netfilter.UniformLimits(float64(i + 1))
			errs <- h.svc.UpdateContainer(ctx, ContainerUpdate{Key: key, Proxy: boolptr(i%2 == 0), QoS: &l})
		}(i)
		go func() { defer wg.Done(); errs <- h.svc.RefreshContainers(ctx) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	policy := h.svc.state.ContainerSettings[key]
	if fw.installed["172.18.0.3"] != policy.QoS || fw.installed["172.19.0.3"] != policy.QoS {
		t.Fatal("concurrent discovery/edits lost applied limits")
	}
	if len(fw.bindings) != 2 || fw.bindings[0].Proxy != policy.Proxy {
		t.Fatal("concurrent discovery/edits lost proxy setting")
	}
}

func TestContainerAssignmentsReachGroupDistribution(t *testing.T) {
	h, fw, _ := containerHarness(t)
	ctx := context.Background()
	originals := h.store.All()
	chain, err := h.svc.CreateChain(ctx, "Chain", []string{originals[0].ID, originals[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	group, err := h.svc.CreateLoadBalancer(ctx, "Pool", []string{chain, originals[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	key := containerSample().Key
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: key, Proxy: boolptr(true), NodeID: &group}); err != nil {
		t.Fatal(err)
	}
	if fw.routes["172.18.0.3"] != group || fw.routes["172.19.0.3"] != group || len(fw.groups) != 1 {
		t.Fatal("container group missing from nft distribution")
	}
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: key, NodeID: &chain}); err != nil {
		t.Fatal(err)
	}
	if h.svc.cfg.Engine.(*deviceEngine).routes["172.18.0.3"] != chain {
		t.Fatal("container chain missing from source routing")
	}
}

func TestContainerStateWritePrecedesFirewallChanges(t *testing.T) {
	h, fw, _ := containerHarness(t)
	key := containerSample().Key
	id := h.store.All()[0].ID
	if err := h.svc.UpdateContainer(context.Background(), ContainerUpdate{Key: key, NodeID: &id}); err != nil {
		t.Fatal(err)
	}
	h.svc.cfg.StatePath = filepath.Join(h.svc.cfg.StatePath, "not-a-directory")
	before := fw.syncs
	if err := h.svc.UpdateContainer(context.Background(), ContainerUpdate{Key: key, Proxy: boolptr(false)}); err == nil {
		t.Fatal("state write failure accepted")
	}
	if fw.syncs != before || !h.svc.state.ContainerSettings[key].Proxy {
		t.Fatal("write failure changed policy")
	}
}

func TestContainerRouteSelectorDefaultsAndLegacyCompatibility(t *testing.T) {
	h, fw, _ := containerHarness(t)
	ctx := context.Background()
	key := containerSample().Key
	id := h.store.All()[0].ID
	if h.svc.state.ContainerSettings[key].Proxy {
		t.Fatal("new containers must default Direct")
	}
	limits := netfilter.UniformLimits(5)
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: key, NodeID: &id, QoS: &limits}); err != nil {
		t.Fatal(err)
	}
	if !h.svc.state.ContainerSettings[key].Proxy || fw.routes["172.18.0.3"] != id {
		t.Fatal("choosing a node did not activate its route")
	}
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: key, NodeID: strptr("direct")}); err != nil {
		t.Fatal(err)
	}
	policy := h.svc.state.ContainerSettings[key]
	if policy.Proxy || policy.NodeID != "" || fw.installed["172.18.0.3"] != limits {
		t.Fatal("Direct must bypass interception and retain limits")
	}
	if _, exists := fw.routes["172.18.0.3"]; exists {
		t.Fatal("Direct still has a proxy source rule")
	}
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: key, NodeID: strptr("")}); err != nil {
		t.Fatal(err)
	}
	if !h.svc.state.ContainerSettings[key].Proxy || h.svc.state.ContainerSettings[key].NodeID != "" {
		t.Fatal("empty node ID must use Global Default")
	}
	// Existing API clients can still save a pin with explicit proxy=false.
	if err := h.svc.UpdateContainer(ctx, ContainerUpdate{Key: key, NodeID: &id, Proxy: boolptr(false)}); err != nil {
		t.Fatal(err)
	}
	if h.svc.state.ContainerSettings[key].Proxy || h.svc.state.ContainerSettings[key].NodeID != id {
		t.Fatal("legacy proxy flag stopped working")
	}
}
