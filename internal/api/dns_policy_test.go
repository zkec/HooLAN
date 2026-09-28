package api

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type dnsPolicyEngine struct {
	*fakeEngine
	proxyDNS atomic.Bool
}

func (e *dnsPolicyEngine) ConfigureDNSProxy(enabled bool) { e.proxyDNS.Store(enabled) }

func TestDNSIntentSurvivesEngineFailure(t *testing.T) {
	var engine *dnsPolicyEngine
	h := newHarness(t, testNodes(), func(c *Config) {
		engine = &dnsPolicyEngine{fakeEngine: c.Engine.(*fakeEngine)}
		c.Engine = engine
	})
	ctx := context.Background()
	if engine.proxyDNS.Load() {
		t.Fatal("fresh OFF must allow Direct DNS")
	}
	if err := h.svc.SetProxyEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	if !engine.proxyDNS.Load() {
		t.Fatal("ON must require engine DNS")
	}
	// Persisted ON must establish strict DNS before startup/restore runs.
	engine.proxyDNS.Store(false)
	restored, err := New(h.svc.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.jobCancel()
	if !engine.proxyDNS.Load() {
		t.Fatal("startup window exposed Direct DNS")
	}
	engine.mu.Lock()
	engine.running = false
	engine.mu.Unlock()
	h.svc.HandleEngineExit(errors.New("test crash"))
	deadline := time.Now().Add(time.Second)
	for h.svc.Status(ctx).ProxyEnabled && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.svc.Status(ctx).ProxyEnabled {
		t.Fatal("crash cleanup did not finish")
	}
	if !engine.proxyDNS.Load() {
		t.Fatal("crash enabled Direct DNS")
	}
	if err := h.svc.SetProxyEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	if engine.proxyDNS.Load() {
		t.Fatal("explicit OFF must restore Direct DNS")
	}
	engine.applyErr = errors.New("test startup failure")
	if err := h.svc.SetProxyEnabled(ctx, true); err == nil {
		t.Fatal("expected startup failure")
	}
	if !engine.proxyDNS.Load() {
		t.Fatal("failed startup exposed Direct DNS")
	}
	if err := h.svc.SetProxyEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	if engine.proxyDNS.Load() {
		t.Fatal("OFF after startup failure did not restore DNS")
	}
}
