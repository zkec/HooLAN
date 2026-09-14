package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
	"strings"
	"testing"
)

func TestEditManualRekeysReferencesAndRedactsSecrets(t *testing.T) {
	h := deviceHarness(t)
	ctx := context.Background()
	all := h.store.All()
	old := all[0]
	other := all[1]
	if err := h.store.SetDetour(other.ID, old.ID); err != nil {
		t.Fatal(err)
	}
	h.svc.state.SelectedNodeID = old.ID
	h.svc.state.AutoSelect = false
	h.svc.state.DeviceRoutes = map[string]string{"192.168.3.141": old.ID, "192.168.3.142": "direct"}
	id, err := h.svc.UpdateManualNode(ctx, NodePatch{ID: old.ID, Name: strptr("Edited"), Server: strptr("new.example")})
	if err != nil {
		t.Fatal(err)
	}
	if id == old.ID {
		t.Fatal("identity should change with endpoint")
	}
	edited, err := h.store.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if edited.Node.Tag != "Edited" || edited.Node.UUID != old.Node.UUID || edited.Node.Password != old.Node.Password {
		t.Fatal("edit lost credentials")
	}
	dep, _ := h.store.Get(other.ID)
	if dep.DetourID != id {
		t.Fatal("dependent detour not updated")
	}
	if h.svc.state.SelectedNodeID != id || h.svc.state.DeviceRoutes["192.168.3.141"] != id || h.svc.state.DeviceRoutes["192.168.3.142"] != "direct" {
		t.Fatal("references did not follow edit")
	}
	router := NewRouter(h.svc, RouterOptions{Logger: quietLogger()})
	response := authRequest(router, http.MethodGet, "/api/nodes/edit?node_id="+id, "", nil, "")
	if response.Code != 200 {
		t.Fatalf("editor read: %s", response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"uuid", "password", "LocalVariant"} {
		if _, ok := body[secret]; ok {
			t.Fatalf("exposed %s", secret)
		}
	}
	// Validation is atomic and does not damage the edited endpoint.
	port := 0
	if _, err := h.svc.UpdateManualNode(ctx, NodePatch{ID: id, Port: &port}); err == nil {
		t.Fatal("invalid port accepted")
	}
	current, _ := h.store.Get(id)
	if current.Node.Server != "new.example" {
		t.Fatal("invalid edit mutated inventory")
	}
}
func TestEditSharedManualSurvivesSubscriptionRefresh(t *testing.T) {
	h, _ := syncHarness(t)
	ctx := context.Background()
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	oldID, err := h.svc.AddManualNode(ctx, providerLink)
	if err != nil {
		t.Fatal(err)
	}
	newID, err := h.svc.UpdateManualNode(ctx, NodePatch{ID: oldID, Name: strptr("My independent name")})
	if err != nil {
		t.Fatal(err)
	}
	if newID == oldID {
		t.Fatal("shared edit did not fork")
	}
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	old, _ := h.store.Get(oldID)
	edited, err := h.store.Get(newID)
	if err != nil || edited.Node.Tag != "My independent name" || old.Node.Tag == edited.Node.Tag {
		t.Fatal("refresh overwrote manual edit")
	}
	if _, manual := h.svc.NodeOrigins(oldID); manual {
		t.Fatal("original is still manual")
	}
	if _, manual := h.svc.NodeOrigins(newID); !manual {
		t.Fatal("edited copy lost manual ownership")
	}
}
func TestEditChainRetainsCopiesAndAssignments(t *testing.T) {
	h := deviceHarness(t)
	ctx := context.Background()
	all := h.store.All()
	exit, err := h.svc.CreateChain(ctx, "Original", []string{all[0].ID, all[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	hops, err := h.svc.chainRecords(exit)
	if err != nil {
		t.Fatal(err)
	}
	h.svc.state.DeviceRoutes = map[string]string{"192.168.3.141": exit}
	h.svc.state.SelectedNodeID = exit
	h.svc.state.AutoSelect = false
	updated, err := h.svc.UpdateChain(ctx, exit, "Reversed", []string{hops[1].ID, hops[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	current, err := h.svc.chainRecords(updated)
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 2 || current[0].Node.Server != hops[1].Node.Server || current[1].Node.Server != hops[0].Node.Server {
		t.Fatal("hop order not changed")
	}
	if current[1].Node.Tag != "Reversed" || h.svc.state.DeviceRoutes["192.168.3.141"] != updated || h.svc.state.SelectedNodeID != updated {
		t.Fatal("name or assignment lost")
	}
	if h.store.Len() != 4 {
		t.Fatal("old copies leaked")
	}
	// Retain existing snapshots, then add an original endpoint and remove a hop.
	updated, err = h.svc.UpdateChain(ctx, updated, "Three", []string{current[0].ID, all[0].ID, current[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	current, _ = h.svc.chainRecords(updated)
	if len(current) != 3 || h.store.Len() != 5 {
		t.Fatal("add hop failed")
	}
	updated, err = h.svc.UpdateChain(ctx, updated, "Two", []string{current[0].ID, current[2].ID})
	if err != nil {
		t.Fatal(err)
	}
	if h.store.Len() != 4 {
		t.Fatal("removed hop retained")
	}
	if err := subscription.ValidateChains(h.store.EnabledNodes()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.UpdateChain(ctx, updated, "bad", []string{all[0].ID, all[0].ID}); err == nil {
		t.Fatal("duplicate hops accepted")
	}
}
func TestEditRollbackOnPersistenceFailure(t *testing.T) {
	h := deviceHarness(t)
	old := h.store.All()[0]
	ctx := context.Background()
	h.svc.mu.Lock()
	err := h.svc.saveState()
	h.svc.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	h.svc.cfg.StatePath = filepath.Join(h.svc.cfg.StatePath, "bad")
	if _, err := h.svc.UpdateManualNode(ctx, NodePatch{ID: old.ID, Server: strptr("new.example")}); err == nil {
		t.Fatal("write failure accepted")
	}
	rec, err := h.store.Get(old.ID)
	if err != nil || rec.Node.Server != old.Node.Server || h.store.Len() != 2 {
		t.Fatal("rollback did not restore inventory")
	}
}
func TestDeviceDirectAssignment(t *testing.T) {
	h := deviceHarness(t)
	ctx := context.Background()
	if err := h.svc.UpdateDevice(ctx, DeviceUpdate{IP: "192.168.3.141", NodeID: strptr("direct")}); err != nil {
		t.Fatal(err)
	}
	persisted, err := h.svc.loadState()
	if err != nil || persisted.DeviceRoutes["192.168.3.141"] != "direct" {
		t.Fatal("direct not saved")
	}
	if strings.Contains(h.svc.cfg.Engine.(*deviceEngine).routes["192.168.3.141"], "node") {
		t.Fatal("direct resolved as node")
	}
	if _, err := h.svc.DeleteNodes(ctx, []string{store.NodeID(testNodes()[0])}); err != nil {
		t.Fatal(err)
	}
	if h.svc.state.DeviceRoutes["192.168.3.141"] != "direct" {
		t.Fatal("delete removed direct route")
	}
}

func TestEditingHTTPRoutes(t *testing.T) {
	h := deviceHarness(t)
	router := NewRouter(h.svc, RouterOptions{Token: "secret", Logger: quietLogger()})
	all := h.store.All()
	for _, path := range []string{"/api/nodes/edit?node_id=" + all[0].ID, "/api/chains?node_id=" + all[0].ID} {
		if w := authRequest(router, "GET", path, "", nil, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("unprotected route: %s", path)
		}
	}
	login := authRequest(router, "POST", "/api/auth/login", `{"token":"secret"}`, nil, "")
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	response := authRequest(router, "GET", "/api/auth/session", "", cookie, "")
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	payload := `{"node_id":"` + all[0].ID + `","name":"HTTP edit"}`
	if w := authRequest(router, "PUT", "/api/nodes/edit", payload, cookie, ""); w.Code != http.StatusForbidden {
		t.Fatal("missing CSRF accepted")
	}
	if w := authRequest(router, "PUT", "/api/nodes/edit", payload, cookie, session.CSRF); w.Code != 200 {
		t.Fatalf("PUT edit: %d %s", w.Code, w.Body.String())
	}
	if w := authRequest(router, "PUT", "/api/nodes/edit", `{"node_id":"`+all[0].ID+`","ChainInternal":true}`, cookie, session.CSRF); w.Code != 400 {
		t.Fatal("identity fields accepted")
	}
	exit, err := h.svc.CreateChain(context.Background(), "Chain", []string{all[0].ID, all[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	response = authRequest(router, "GET", "/api/chains?node_id="+exit, "", cookie, "")
	var chain struct {
		Hops []ChainHop `json:"hops"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &chain); err != nil {
		t.Fatal(err)
	}
	if len(chain.Hops) != 2 {
		t.Fatal("GET did not return ordered hops")
	}
	body, _ := json.Marshal(map[string]any{"node_id": exit, "name": "Edited chain", "node_ids": []string{chain.Hops[1].ID, chain.Hops[0].ID}})
	if w := authRequest(router, "PUT", "/api/chains", string(body), cookie, session.CSRF); w.Code != 200 {
		t.Fatalf("PUT chain: %d %s", w.Code, w.Body.String())
	}
}

func TestChainKeepsSourceNamesAcrossEdit(t *testing.T) {
	h := deviceHarness(t)
	ctx := context.Background()
	all := h.store.All()
	id, err := h.svc.CreateChain(ctx, "My chain", []string{all[0].ID, all[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	hops, err := h.svc.chainRecords(id)
	if err != nil {
		t.Fatal(err)
	}
	for i, hop := range hops {
		if hop.SourceName != all[i].Node.Tag {
			t.Fatal("source name not stored")
		}
		legacy := hop
		legacy.SourceName = ""
		if h.svc.chainSourceName(legacy) != all[i].Node.Tag {
			t.Fatal("legacy name not recovered")
		}
	}
	id, err = h.svc.UpdateChain(ctx, id, "Renamed", []string{hops[1].ID, hops[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	current, _ := h.svc.chainRecords(id)
	if current[0].SourceName != all[1].Node.Tag || current[1].SourceName != all[0].Node.Tag {
		t.Fatal("reordering lost names")
	}
}
