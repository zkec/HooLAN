package api

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"hoolan/internal/engine"
)

type fakeDNSTestEngine struct {
	*configurableTestEngine
	options engine.FakeDNSOptions
}

func (e *fakeDNSTestEngine) ConfigureFakeDNS(options engine.FakeDNSOptions) error {
	e.options = options
	return nil
}

type fakeDNSTestFirewall struct {
	*fakeFirewall
	enabled bool
}

func (f *fakeDNSTestFirewall) ConfigureFakeDNS(enabled bool) { f.enabled = enabled }

func TestFakeDNSSettingsPersistPatchAndRollback(t *testing.T) {
	h := newHarness(t, testNodes(), nil)
	e := &fakeDNSTestEngine{configurableTestEngine: &configurableTestEngine{fakeEngine: h.eng}}
	f := &fakeDNSTestFirewall{fakeFirewall: h.fw}
	h.svc.cfg.Engine = e
	h.svc.cfg.Firewall = f
	code, res := h.do(http.MethodPut, "/api/settings", `{"fake_dns":{"enabled":true,"listen":"192.168.3.5"}}`)
	if code != 200 {
		t.Fatalf("save: %d %v", code, res)
	}
	if !e.options.Enabled || !f.enabled {
		t.Fatal("engine and firewall did not receive FakeDNS")
	}
	code, res = h.do(http.MethodPut, "/api/settings", `{"iran_bypass":false}`)
	if code != 200 || !h.svc.Settings().FakeDNS.Enabled {
		t.Fatalf("Iran toggle lost FakeDNS: %d %v", code, res)
	}
	reloaded, err := New(h.svc.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.jobCancel()
	if reloaded.Settings().FakeDNS != e.options {
		t.Fatal("settings did not persist")
	}
	previous := h.svc.Settings()
	code, _ = h.do(http.MethodPut, "/api/settings", `{"fake_dns":{"enabled":true,"listen":"0.0.0.0"}}`)
	if code != 400 || h.svc.Settings() != previous {
		t.Fatal("invalid listener accepted or saved")
	}
	// Probe failure must restore state and remove interception. Avoid requiring
	// an actual FakeDNS listener in this fake-engine test by enabling its flags.
	h.svc.mu.Lock()
	h.svc.proxyEnabled = true
	h.svc.mu.Unlock()
	h.eng.applyErr = errors.New("test startup failure")
	next := previous
	next.FakeDNS.Listen = "10.42.42.1"
	if _, err = h.svc.UpdateSettings(context.Background(), next); err == nil {
		t.Fatal("startup failure reported success")
	}
	if h.svc.Settings() != previous || e.options != previous.FakeDNS || !f.enabled {
		t.Fatal("failed reload retained new configuration")
	}
}
