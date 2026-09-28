package api

import (
	"context"
	"encoding/json"
	"errors"
	"hoolan/internal/store"
	"testing"
)

func TestRemoveSubscriptionHTTP(t *testing.T) {
	h, _ := syncHarness(t)
	router := NewRouter(h.svc, RouterOptions{Token: "test-token", Logger: quietLogger()})
	body, err := json.Marshal(map[string]string{"subscription_id": h.svc.subscriptionSnapshot()[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if w := authRequest(router, "DELETE", "/api/subscriptions", string(body), nil, ""); w.Code != 401 {
		t.Fatalf("unauthenticated delete=%d", w.Code)
	}
	login := authRequest(router, "POST", "/api/auth/login", `{"token":"test-token"}`, nil, "")
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil || login.Code != 200 {
		t.Fatalf("login=%d: %v", login.Code, err)
	}
	cookie := login.Result().Cookies()[0]
	if w := authRequest(router, "DELETE", "/api/subscriptions", string(body), cookie, ""); w.Code != 403 {
		t.Fatalf("delete without CSRF=%d", w.Code)
	}
	if w := authRequest(router, "DELETE", "/api/subscriptions", `{}`, cookie, session.CSRFToken); w.Code != 400 {
		t.Fatalf("empty delete=%d", w.Code)
	}
	w := authRequest(router, "DELETE", "/api/subscriptions", string(body), cookie, session.CSRFToken)
	if w.Code != 200 || len(h.svc.Subscriptions()) != 1 {
		t.Fatalf("delete=%d %s", w.Code, w.Body.String())
	}
	var result struct {
		RemovedNodes int `json:"removed_nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.RemovedNodes != 0 {
		t.Fatalf("empty source removal response=%s: %v", w.Body.String(), err)
	}
	if w := authRequest(router, "DELETE", "/api/subscriptions", string(body), cookie, session.CSRFToken); w.Code != 404 {
		t.Fatalf("missing delete=%d", w.Code)
	}
}

func TestRemoveSubscriptionPreservesSharedAndManual(t *testing.T) {
	h, _ := syncHarness(t)
	ctx := context.Background()
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	manual, err := h.svc.AddManualNode(ctx, providerLink)
	if err != nil {
		t.Fatal(err)
	}
	subs := h.svc.subscriptionSnapshot()
	if _, err = h.svc.RemoveSubscription(ctx, subs[0].ID); err != nil {
		t.Fatal(err)
	}
	if len(h.svc.Subscriptions()) != 1 || h.store.Len() != 2 {
		t.Fatal("removed shared or manual node")
	}
	if _, err = h.svc.RemoveSubscription(ctx, subs[1].ID); err != nil {
		t.Fatal(err)
	}
	if len(h.svc.Subscriptions()) != 0 || h.store.Len() != 1 {
		t.Fatal("exclusive node not pruned")
	}
	if _, err = h.store.Get(manual); err != nil {
		t.Fatal("manual node lost")
	}
	// Recreate the service with the same HOOLAN_SUBS seeds and persisted state.
	restarted, err := New(h.svc.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.jobCancel()
	if len(restarted.Subscriptions()) != 0 {
		t.Fatal("deleted seed reappeared after restart")
	}
	if _, err = restarted.AddSubscription("Re-added", subs[0].URL); err != nil {
		t.Fatal(err)
	}
	if restarted.state.RemovedSubscriptionIDs[subs[0].ID] {
		t.Fatal("explicit re-add must clear tombstone")
	}
}
func TestRemoveSubscriptionSelectionAndRollback(t *testing.T) {
	h, _ := syncHarness(t)
	ctx := context.Background()
	if err := h.svc.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	sub := h.svc.subscriptionSnapshot()[0]
	// Remove the other subscription first so this one owns all remaining nodes.
	if _, err := h.svc.RemoveSubscription(ctx, h.svc.subscriptionSnapshot()[1].ID); err != nil {
		t.Fatal(err)
	}
	id := sub.NodeIDs[0]
	h.svc.state.SelectedNodeID = id
	h.svc.state.AutoSelect = false
	h.svc.state.DeviceRoutes = map[string]string{"192.168.3.10": id}
	previousPath := h.svc.cfg.StatePath
	h.svc.cfg.StatePath = t.TempDir() // rename onto a directory must fail
	if _, err := h.svc.RemoveSubscription(ctx, sub.ID); err == nil {
		t.Fatal("expected persistence failure")
	}
	if len(h.svc.Subscriptions()) != 1 || h.store.Len() != 2 || h.svc.state.SelectedNodeID != id || h.svc.state.RemovedSubscriptionIDs[sub.ID] {
		t.Fatal("failed delete did not roll back")
	}
	h.svc.cfg.StatePath = previousPath
	h.svc.refreshing = true
	if _, err := h.svc.RemoveSubscription(ctx, sub.ID); !errors.Is(err, ErrRefreshInProgress) {
		t.Fatal("deleted while refresh running", err)
	}
	h.svc.refreshing = false
	if _, err := h.svc.RemoveSubscription(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	if h.store.Len() != 0 || len(h.svc.Subscriptions()) != 0 || !h.svc.state.AutoSelect || h.svc.state.SelectedNodeID != "" || len(h.svc.state.DeviceRoutes) != 0 {
		t.Fatal("selection/routes not reconciled")
	}
	if _, err := h.svc.RemoveSubscription(ctx, sub.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("missing subscription must return not found", err)
	}
}
