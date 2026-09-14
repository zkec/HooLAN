package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"hoolan/internal/engine"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
	"strings"
	"testing"
	"time"
)

type telegramProxyFake struct {
	fakeTester
	client    *http.Client
	target    subscription.Node
	inventory []subscription.Node
	calls     int
	err       error
}

func (p *telegramProxyFake) WithProxyClient(_ context.Context, n subscription.Node, all []subscription.Node, use func(*http.Client) error) error {
	p.calls++
	p.target = n
	p.inventory = all
	if p.err != nil {
		return p.err
	}
	return use(p.client)
}
func TestTelegramProxyTestUsesSavedChainAndPersistsRoute(t *testing.T) {
	sent := 0
	proxy := &telegramProxyFake{client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		sent++
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "via proxy") {
			t.Error("test message omitted route")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}}
	h := newLocalHarness(t, testNodes(), func(c *Config) {
		c.Tester = proxy
		c.NotificationClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			t.Error("proxy used direct transport")
			return nil, errors.New("direct forbidden")
		})}
	})
	all := h.store.All()
	id, err := h.svc.CreateChain(context.Background(), "Telegram chain", []string{all[0].ID, all[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.state.AutoSelect = false
	h.svc.state.SelectedNodeID = id
	router := NewRouter(h.svc, RouterOptions{Logger: quietLogger()})
	token := "123456:" + strings.Repeat("x", 30)
	response := authRequest(router, "PUT", "/api/telegram", `{"enabled":false,"use_proxy":true,"token":"`+token+`","chat_id":"123456"}`, nil, "")
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	raw, err := os.ReadFile(h.svc.cfg.StatePath)
	if err != nil || !strings.Contains(string(raw), `"use_proxy": true`) {
		t.Fatalf("route not persisted: %v", err)
	}
	// Old API clients that omit use_proxy must preserve the explicit choice.
	response = authRequest(router, "PUT", "/api/telegram", `{"enabled":false,"chat_id":"123456"}`, nil, "")
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	response = authRequest(router, "GET", "/api/telegram", "", nil, "")
	var settings struct {
		UseProxy bool `json:"use_proxy"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	if !settings.UseProxy || strings.Contains(response.Body.String(), token) {
		t.Fatal("route missing or token exposed")
	}
	response = authRequest(router, "POST", "/api/telegram/test", `{}`, nil, "")
	if response.Code != 202 {
		t.Fatalf("test: %d %s", response.Code, response.Body.String())
	}
	h.waitForJob(t, "succeeded")
	if sent != 1 || proxy.calls != 1 || proxy.target.Detour == "" || len(proxy.inventory) != 4 {
		t.Fatal("test did not use saved chain while alerts disabled")
	}
	proxy.err = errors.New("sensitive startup credentials")
	response = authRequest(router, "POST", "/api/telegram/test", `{}`, nil, "")
	if response.Code != 202 {
		t.Fatal(response.Body.String())
	}
	job := h.waitForJob(t, "failed")
	if strings.Contains(job.Error, "sensitive") || sent != 1 {
		t.Fatal("error leaked or fell back to direct")
	}
}

func TestTelegramDirectIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
	transport := directTelegramTransport()
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil {
		t.Fatal("direct mode inherits environment proxy")
	}
	sent := 0
	proxy := &telegramProxyFake{err: errors.New("proxy must not run")}
	h := newLocalHarness(t, testNodes(), func(c *Config) {
		c.Tester = proxy
		c.NotificationClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			sent++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
		})}
	})
	cfg := TelegramSettings{Token: "123456:" + strings.Repeat("x", 30), ChatID: "123456"}
	if err := h.svc.deliverTelegram(context.Background(), cfg, "test"); err != nil || sent != 1 || proxy.calls != 0 {
		t.Fatalf("direct routing failed: %v", err)
	}
}

func TestTelegramTestRequiresCredentials(t *testing.T) {
	h := deviceHarness(t)
	response := authRequest(NewRouter(h.svc, RouterOptions{Logger: quietLogger()}), "POST", "/api/telegram/test", `{}`, nil, "")
	if response.Code != 400 {
		t.Fatalf("empty credentials accepted: %d", response.Code)
	}
}

func TestTelegramAutomaticProxyChoiceOnlineAndOffline(t *testing.T) {
	proxy := &telegramProxyFake{client: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}}
	h := newLocalHarness(t, testNodes(), func(c *Config) { c.Tester = proxy })
	h.svc.state.AutoSelect = true
	all := h.store.All()
	for i, r := range all {
		if err := h.store.RecordLatency(r.ID, time.Duration(i+1)*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	cfg := TelegramSettings{UseProxy: true, Token: "123456:" + strings.Repeat("x", 30), ChatID: "123456"}
	// No engine is running: use the fastest measured saved node.
	if err := h.svc.deliverTelegram(context.Background(), cfg, "offline"); err != nil {
		t.Fatal(err)
	}
	if store.NodeID(proxy.target) != all[0].ID {
		t.Fatal("offline auto did not choose best healthy candidate")
	}
	// The running engine's tag may differ from this inventory's current tags.
	// Resolve its live choice by stable ID, rather than matching a display name.
	h.svc.cfg.Engine.(*fakeEngine).mu.Lock()
	h.svc.cfg.Engine.(*fakeEngine).running = true
	h.svc.cfg.Engine.(*fakeEngine).mu.Unlock()
	h.svc.cfg.Selector = &fakeSelector{now: engine.DefaultURLTest}
	h.svc.tagByID = map[string]string{all[1].ID: "fast-node"}
	if err := h.svc.deliverTelegram(context.Background(), cfg, "online"); err != nil {
		t.Fatal(err)
	}
	if store.NodeID(proxy.target) != all[1].ID {
		t.Fatal("live auto choice ignored")
	}
	h.svc.cfg.Engine.(*fakeEngine).mu.Lock()
	h.svc.cfg.Engine.(*fakeEngine).running = false
	h.svc.cfg.Engine.(*fakeEngine).mu.Unlock()
	for _, r := range all {
		if err := h.store.RecordFailure(r.ID, errors.New("offline")); err != nil {
			t.Fatal(err)
		}
	}
	calls := proxy.calls
	if err := h.svc.deliverTelegram(context.Background(), cfg, "no candidate"); err == nil || proxy.calls != calls {
		t.Fatal("no healthy offline candidate must fail without dialing")
	}
}

func TestTelegramDeliveryErrorDiagnostics(t *testing.T) {
	cfg := TelegramSettings{UseProxy: true, Token: "123456:" + strings.Repeat("x", 30), ChatID: "12345"}
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"blocked", 403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`, "Unblock this bot"},
		{"not started", 403, `{"ok":false,"error_code":403,"description":"Forbidden: bot can't initiate conversation with a user"}`, "send /start"},
		{"removed", 403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was kicked from the group chat"}`, "allow it to send messages"},
		{"invalid chat", 400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`, "Check the target Chat ID"},
		{"token", 401, `{"ok":false,"error_code":401,"description":"Unauthorized"}`, "BotFather token"},
		{"html denial", 403, `<html>upstream denied</html>`, "without a valid Bot API response"},
		{"unrelated json", 403, `{"message":"denied"}`, "without a valid Bot API response"},
		{"missing reason", 403, `{"ok":false,"error_code":403}`, "No reason provided"},
		{"logical rejection", 200, `{"ok":false,"error_code":403,"description":"Forbidden"}`, "chat permissions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			err := sendTelegram(context.Background(), client, cfg, "test")
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "via proxy") {
				t.Fatalf("unexpected diagnostic: %v", err)
			}
		})
	}
	description := safeTelegramDescription("URL https://api.telegram.org/bot"+cfg.Token+"/sendMessage\n"+strings.Repeat("a", 600), cfg)
	if strings.Contains(description, cfg.Token) || strings.Contains(description, "\n") || len([]rune(description)) > 513 {
		t.Fatal("unsafe description")
	}
}

func TestTelegramPinnedProxy(t *testing.T) {
	proxy := &telegramProxyFake{client: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}}
	h := newLocalHarness(t, testNodes(), func(c *Config) { c.Tester = proxy })
	all := h.store.All()
	h.svc.state.AutoSelect = false
	h.svc.state.SelectedNodeID = all[0].ID
	router := NewRouter(h.svc, RouterOptions{Logger: quietLogger()})
	cfg := TelegramSettings{UseProxy: true, NodeID: all[1].ID, Token: "123456:" + strings.Repeat("x", 30), ChatID: "654321"}
	raw, _ := json.Marshal(cfg)
	response := authRequest(router, "PUT", "/api/telegram", string(raw), nil, "")
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	saved, _ := os.ReadFile(h.svc.cfg.StatePath)
	if !strings.Contains(string(saved), all[1].ID) {
		t.Fatal("pinned node not persisted")
	}
	if err := h.svc.deliverTelegram(context.Background(), cfg, "test"); err != nil || store.NodeID(proxy.target) != all[1].ID {
		t.Fatalf("pinned delivery: %v", err)
	}
	response = authRequest(router, "PUT", "/api/telegram", `{"enabled":false,"chat_id":"654321"}`, nil, "")
	if response.Code != 200 || h.svc.state.Telegram.NodeID != all[1].ID {
		t.Fatal("omitted node_id must preserve pin")
	}
	response = authRequest(router, "PUT", "/api/telegram", `{"enabled":false,"chat_id":"654321","node_id":"missing"}`, nil, "")
	if response.Code != 400 {
		t.Fatal("missing node accepted")
	}
	h.store.SetEnabled(all[1].ID, false)
	calls := proxy.calls
	if err := h.svc.deliverTelegram(context.Background(), cfg, "test"); err == nil || proxy.calls != calls {
		t.Fatal("unavailable pin fell back")
	}
	response = authRequest(router, "PUT", "/api/telegram", `{"enabled":false,"chat_id":"654321","node_id":""}`, nil, "")
	if response.Code != 200 || h.svc.state.Telegram.NodeID != "" {
		t.Fatal("could not clear pin")
	}
	if hint := telegramFailureHint(403, 403, "Forbidden: the bot can't send messages to the bot"); !strings.Contains(hint, "receiving person's chat ID") {
		t.Fatal(hint)
	}
}
