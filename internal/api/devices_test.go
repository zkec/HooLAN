package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
)

type deviceEngine struct {
	*fakeEngine
	routes map[string]string
}

func (e *deviceEngine) ConfigureDeviceRoutes(routes map[string]string) {
	e.routes = copyStrings(routes)
}
func deviceHarness(t *testing.T) *harness {
	return newLocalHarness(t, testNodes(), func(c *Config) { c.Engine = &deviceEngine{fakeEngine: c.Engine.(*fakeEngine)} })
}
func strptr(v string) *string { return &v }

func TestDeviceSettingsPersistClearAndValidate(t *testing.T) {
	h := deviceHarness(t)
	id := h.store.All()[0].ID
	router := NewRouter(h.svc, RouterOptions{Token: "secret", Logger: quietLogger()})
	if w := authRequest(router, "PUT", "/api/devices", `{"ip":"192.168.3.141","alias":"Phone"}`, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unprotected mutation: %d", w.Code)
	}
	login := authRequest(router, "POST", "/api/auth/login", `{"token":"secret"}`, nil, "")
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	// Exercise persistence while the engine is off.
	if err := h.svc.UpdateDevice(context.Background(), DeviceUpdate{IP: "192.168.3.141", Alias: strptr(" Phone "), NodeID: &id}); err != nil {
		t.Fatal(err)
	}
	persisted, err := h.svc.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.DeviceAliases["192.168.3.141"] != "Phone" || persisted.DeviceRoutes["192.168.3.141"] != id {
		t.Fatalf("not persisted: %+v", persisted)
	}
	if h.svc.cfg.Engine.(*deviceEngine).routes["192.168.3.141"] != id {
		t.Fatal("engine configuration not updated while off")
	}
	for _, req := range []DeviceUpdate{
		{IP: "127.0.0.1", Alias: strptr("bad")}, {IP: "8.8.8.8", Alias: strptr("bad")}, {IP: "192.168.3.0/24", NodeID: &id}, {IP: "192.168.3.141"}, {IP: "192.168.3.141", Alias: strptr("bad\nname")}, {IP: "192.168.3.141", NodeID: strptr("missing")},
	} {
		if err := h.svc.UpdateDevice(context.Background(), req); err == nil {
			t.Fatalf("invalid request accepted: %+v", req)
		}
	}
	// Clearing the route must preserve the separately editable alias.
	if err := h.svc.UpdateDevice(context.Background(), DeviceUpdate{IP: "192.168.3.141", NodeID: strptr("")}); err != nil {
		t.Fatal(err)
	}
	persisted, err = h.svc.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted.DeviceRoutes) != 0 || persisted.DeviceAliases["192.168.3.141"] != "Phone" {
		t.Fatal("clear lost alias or retained route")
	}
	cookie := login.Result().Cookies()[0]
	response := authRequest(router, "GET", "/api/auth/session", "", cookie, "")
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	response = authRequest(router, "PUT", "/api/devices", `{"ip":"192.168.3.141","alias":"Tablet"}`, cookie, session.CSRF)
	if response.Code != 200 {
		t.Fatalf("authenticated update: %d %s", response.Code, response.Body.String())
	}
}

func TestDeviceRouteRollbackAndRemoval(t *testing.T) {
	h := deviceHarness(t)
	ctx := context.Background()
	id := h.store.All()[0].ID
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: "192.168.3.141", Alias: strptr("Phone"), NodeID: &id}); err != nil {
		t.Fatal(err)
	}
	oldPath := h.svc.cfg.StatePath
	h.svc.cfg.StatePath = filepath.Join(oldPath, "not-a-directory")
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: "192.168.3.141", NodeID: strptr("")}); err == nil {
		t.Fatal("write failure accepted")
	}
	if h.svc.state.DeviceRoutes["192.168.3.141"] != id {
		t.Fatal("state not rolled back")
	}
	h.svc.cfg.StatePath = oldPath
	// Simulate a running engine failing to render/apply without opening sockets.
	h.eng.running = true
	h.eng.applyErr = errors.New("render failed")
	other := h.store.All()[1].ID
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: "192.168.3.141", NodeID: &other}); err == nil {
		t.Fatal("reload error lost")
	}
	if h.svc.state.DeviceRoutes["192.168.3.141"] != id || h.svc.cfg.Engine.(*deviceEngine).routes["192.168.3.141"] != id {
		t.Fatal("failed reload did not restore assignment")
	}
	h.eng.running = false
	h.eng.applyErr = nil
	if _, err := h.svc.DeleteNodes(ctx, []string{id}); err != nil {
		t.Fatal(err)
	}
	persisted, err := h.svc.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted.DeviceRoutes) != 0 || persisted.DeviceAliases["192.168.3.141"] != "Phone" {
		t.Fatal("delete did not reset routing while preserving alias")
	}
}

func TestDeviceRoutesPrunedWithSubscription(t *testing.T) {
	h, transport := syncHarness(t)
	ctx := context.Background()
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	first := h.svc.subscriptionSnapshot()[0]
	second := h.svc.subscriptionSnapshot()[1]
	retained := second.NodeIDs[0]
	removed := ""
	for _, id := range first.NodeIDs {
		if id != retained {
			removed = id
		}
	}
	if removed == "" {
		t.Fatal("no exclusive node")
	}
	h.svc.state.DeviceRoutes = map[string]string{"192.168.3.141": removed, "192.168.3.142": retained}
	transport.feeds[first.URL] = ""
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	persisted, err := h.svc.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.DeviceRoutes["192.168.3.141"] != "" || persisted.DeviceRoutes["192.168.3.142"] != retained {
		t.Fatal("pruning removed the wrong assignments")
	}
}

func TestDeviceUsageOriginalSourcesAndDeltas(t *testing.T) {
	selector := &trafficSelector{}
	h := newLocalHarness(t, testNodes(), func(c *Config) { c.Selector = selector })
	h.eng.running = true
	raw := `{"uploadTotal":100,"downloadTotal":500,"connections":[
 {"id":"proxy","upload":10,"download":100,"chains":["US","proxy"],"metadata":{"sourceIP":"192.168.3.141","type":"tproxy/tproxy-in"}},
 {"id":"direct","upload":20,"download":200,"chains":["direct"],"metadata":{"sourceIP":"192.168.3.141","type":"tproxy/tproxy-in"}},
 {"id":"second","upload":30,"download":150,"metadata":{"sourceIP":"192.168.3.142","type":"tproxy/tproxy-in"}},
 {"id":"local","upload":10,"download":10,"metadata":{"sourceIP":"127.0.0.1","type":"tproxy/tproxy-in"}},
 {"id":"probe","upload":10,"download":10,"metadata":{"sourceIP":"192.168.3.141","type":"mixed/test"}}
 ]}`
	if err := json.Unmarshal([]byte(raw), &selector.snapshot); err != nil {
		t.Fatal(err)
	}
	h.svc.sampleUsage(context.Background())
	h.svc.sampleUsage(context.Background())
	devices := h.svc.state.Usage.Devices
	if len(devices) != 2 || devices["192.168.3.141"] != (Bytes{30, 300}) || devices["192.168.3.142"] != (Bytes{30, 150}) {
		t.Fatalf("bad devices: %+v", devices)
	}
	selector.snapshot.Connections[0].Download = 140
	h.svc.sampleUsage(context.Background())
	if devices["192.168.3.141"].Download != 340 {
		t.Fatal("new delta missing")
	}
	persisted, err := h.svc.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Usage.Devices["192.168.3.141"].Download != 300 {
		t.Fatal("device usage not persisted")
	}
}
