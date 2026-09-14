package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"hoolan/internal/subscription"
	"hoolan/internal/tester"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestTelegramRedactionAndPayload(t *testing.T) {
	cfg := TelegramSettings{Enabled: true, Token: "123456:" + strings.Repeat("x", 30), ChatID: "-1001234"}
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.telegram.org" || r.URL.Path != "/bot"+cfg.Token+"/sendMessage" || r.Method != "POST" {
			t.Fatal("wrong Telegram endpoint")
		}
		var p map[string]any
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Fatal(err)
		}
		if p["chat_id"] != cfg.ChatID || p["text"] != "hello" {
			t.Fatal("wrong message")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}
	if err := sendTelegram(context.Background(), client, cfg, "hello"); err != nil {
		t.Fatal(err)
	}
	client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) { return nil, errors.New(r.URL.String()) })
	if err := sendTelegram(context.Background(), client, cfg, "hello"); err == nil || strings.Contains(err.Error(), cfg.Token) {
		t.Fatal("error leaked token or failed silently")
	}
	h := deviceHarness(t)
	h.svc.state.Telegram = cfg
	response := authRequest(NewRouter(h.svc, RouterOptions{Logger: quietLogger()}), "GET", "/api/telegram", "", nil, "")
	var settings map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(response.Body.String(), cfg.Token) || settings["token_set"] != true {
		t.Fatal("settings leaked token")
	}
}

const backupConf = `LAN_IF="eth0"
TPROXY_PORT="7892"
TPROXY_FWMARK="0x1"
TPROXY_TABLE="100"
TPROXY_RULE_PRIORITY="10000"
PI_LAN_IP="192.168.3.5"
SELF_ORIGIN_NETS=""
WG_RP_FILTER="yes"
`

type backupFirewall struct {
	*fakeFirewall
	path string
}

func (f *backupFirewall) ConfigPath() string { return f.path }

type backupTestEngine struct{ *fakeEngine }

func (e *backupTestEngine) TProxyPort() int { return 7892 }
func backupHarness(t *testing.T) *harness {
	h := newLocalHarness(t, testNodes(), func(c *Config) { c.Engine = &backupTestEngine{c.Engine.(*fakeEngine)} })
	path := filepath.Join(h.dir, "tproxy.conf")
	if err := os.WriteFile(path, []byte(backupConf), 0600); err != nil {
		t.Fatal(err)
	}
	h.svc.cfg.Firewall = &backupFirewall{h.fw, path}
	return h
}
func rewriteZIP(t *testing.T, raw []byte, change func(string, []byte) (string, []byte)) []byte {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, f := range r.File {
		in, _ := f.Open()
		data, _ := io.ReadAll(in)
		in.Close()
		name, data := change(f.Name, data)
		out, _ := w.Create(name)
		out.Write(data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
func TestBackupRoundTripAndUnsafeArchives(t *testing.T) {
	h := backupHarness(t)
	id := h.store.All()[0].ID
	h.svc.state.DeviceAliases = map[string]string{"192.168.3.141": "Phone"}
	h.svc.state.DeviceRoutes = map[string]string{"192.168.3.141": id}
	raw, err := h.svc.makeBackup()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := decodeBackup(raw, 7892)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.State.DeviceRoutes["192.168.3.141"] != id || len(bundle.Nodes.Records) != 2 {
		t.Fatal("backup lost data")
	}
	for _, tc := range []struct {
		name   string
		change func(string, []byte) (string, []byte)
	}{
		{"zip slip", func(name string, data []byte) (string, []byte) {
			if name == "nodes.json" {
				name = "../nodes.json"
			}
			return name, data
		}},
		{"duplicate", func(name string, data []byte) (string, []byte) {
			if name == "devices.json" {
				name = "state.json"
			}
			return name, data
		}},
		{"shell substitution", func(name string, data []byte) (string, []byte) {
			if name == "tproxy.conf" {
				data = []byte(strings.Replace(backupConf, "eth0", "$(touch /tmp/must-not-execute)", 1))
			}
			return name, data
		}},
		{"wrong port", func(name string, data []byte) (string, []byte) {
			if name == "tproxy.conf" {
				data = bytes.ReplaceAll(data, []byte("7892"), []byte("9999"))
			}
			return name, data
		}},
		{"inconsistent mappings", func(name string, data []byte) (string, []byte) {
			if name == "devices.json" {
				data = []byte(`{}`)
			}
			return name, data
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeBackup(rewriteZIP(t, raw, tc.change), 7892); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	if _, _, err := h.store.UpsertNodes([]subscription.Node{{Protocol: subscription.ProtoTrojan, Tag: "extra", Server: "extra.example", Port: 443, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.applyBackup(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	if h.store.Len() != 2 || h.svc.state.DeviceAliases["192.168.3.141"] != "Phone" {
		t.Fatal("restore did not replace live state")
	}
}
func TestBackupRollsBackFailedEngineApply(t *testing.T) {
	h := backupHarness(t)
	raw, err := h.svc.makeBackup()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := decodeBackup(raw, 7892)
	if err != nil {
		t.Fatal(err)
	}
	bundle.State.ProxyEnabled = true
	bundle.State.DNSServer = "8.8.8.8"
	bundle.Conf = bytes.ReplaceAll(bundle.Conf, []byte(`TPROXY_TABLE="100"`), []byte(`TPROXY_TABLE="101"`))
	h.eng.applyErr = errors.New("engine failed")
	if err := h.svc.applyBackup(context.Background(), bundle); err == nil {
		t.Fatal("application failure ignored")
	}
	path, _ := h.svc.backupConfigPath()
	conf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(conf) != backupConf || h.svc.state.ProxyEnabled || h.svc.state.DNSServer != "" {
		t.Fatal("rollback did not restore original settings")
	}
}

type speedFake struct {
	fakeTester
	target    subscription.Node
	inventory []subscription.Node
}

func (s *speedFake) TestSpeed(_ context.Context, n subscription.Node, all []subscription.Node) (tester.SpeedResult, error) {
	s.target = n
	s.inventory = all
	return tester.SpeedResult{Bytes: tester.SpeedBytes, Seconds: 2, Mbps: 60}, nil
}
func TestSpeedJobTargetsSavedChain(t *testing.T) {
	speed := &speedFake{}
	h := newLocalHarness(t, testNodes(), func(c *Config) { c.Tester = speed })
	all := h.store.All()
	id, err := h.svc.CreateChain(context.Background(), "speed chain", []string{all[0].ID, all[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(h.svc, RouterOptions{Logger: quietLogger()})
	response := authRequest(router, "POST", "/api/nodes/speed", `{"node_id":"`+id+`"}`, nil, "")
	if response.Code != 202 {
		t.Fatalf("speed API: %d %s", response.Code, response.Body.String())
	}
	h.waitForJob(t, "succeeded")
	if speed.target.Detour == "" || len(speed.inventory) != 4 {
		t.Fatal("chain path not provided")
	}
	h.svc.mu.RLock()
	result := h.svc.job.Speed
	h.svc.mu.RUnlock()
	if result == nil || result.Mbps != 60 {
		t.Fatal("speed result missing")
	}
}
func TestNotificationsStayBounded(t *testing.T) {
	h := deviceHarness(t)
	h.svc.state.Telegram.Enabled = true
	for i := 0; i < 100; i++ {
		h.svc.notify("test")
	}
	if len(h.svc.notifications) != cap(h.svc.notifications) {
		t.Fatal("queue not bounded")
	}
}
func TestActiveNodeFailureNotifiesOnce(t *testing.T) {
	fail := true
	fake := &fakeTester{results: func(nodes []subscription.Node) []tester.Result {
		if len(nodes) != 1 {
			t.Error("health check probed other configurations")
		}
		result := tester.Result{Tag: nodes[0].Tag, Latency: time.Millisecond}
		if fail {
			result.Err = errors.New("offline")
		}
		return []tester.Result{result}
	}}
	h := newLocalHarness(t, testNodes(), func(c *Config) { c.Tester = fake })
	id := h.store.All()[0].ID
	h.svc.state.Telegram.Enabled = true
	h.svc.state.AutoSelect = false
	h.svc.state.SelectedNodeID = id
	h.svc.proxyEnabled = true
	h.svc.checkActiveNode()
	h.waitForJob(t, "succeeded")
	if len(h.svc.notifications) != 1 {
		t.Fatal("first failed check did not notify")
	}
	h.svc.checkActiveNode()
	h.waitForJob(t, "succeeded")
	if len(h.svc.notifications) != 1 {
		t.Fatal("duplicate failure alert")
	}
	fail = false
	h.svc.checkActiveNode()
	h.waitForJob(t, "succeeded")
	fail = true
	h.svc.checkActiveNode()
	h.waitForJob(t, "succeeded")
	if len(h.svc.notifications) != 2 {
		t.Fatal("failure after recovery did not notify")
	}
}

func TestAdvancedRoutesRequireAuthenticationAndCSRF(t *testing.T) {
	h := backupHarness(t)
	router := NewRouter(h.svc, RouterOptions{Token: "secret", Logger: quietLogger()})
	for _, item := range []struct{ method, path string }{{"GET", "/api/backup"}, {"GET", "/api/telegram"}, {"POST", "/api/restore"}, {"POST", "/api/nodes/share"}, {"POST", "/api/nodes/speed"}, {"PUT", "/api/telegram"}, {"POST", "/api/telegram/test"}, {"POST", "/api/load-balancers"}, {"PUT", "/api/devices"}} {
		if w := authRequest(router, item.method, item.path, `{}`, nil, ""); w.Code != 401 {
			t.Fatalf("unprotected %s: %d", item.path, w.Code)
		}
	}
	login := authRequest(router, "POST", "/api/auth/login", `{"token":"secret"}`, nil, "")
	cookie := login.Result().Cookies()[0]
	for _, item := range []struct{ method, path string }{{"POST", "/api/restore"}, {"POST", "/api/nodes/share"}, {"POST", "/api/nodes/speed"}, {"PUT", "/api/telegram"}, {"POST", "/api/telegram/test"}, {"POST", "/api/load-balancers"}, {"PUT", "/api/devices"}} {
		if w := authRequest(router, item.method, item.path, `{}`, cookie, ""); w.Code != 403 {
			t.Fatalf("missing CSRF accepted %s: %d", item.path, w.Code)
		}
	}
}

func TestBackupRejectsSymlinkAndExpandedBomb(t *testing.T) {
	for _, bomb := range []bool{false, true} {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		for _, name := range []string{"nodes.json", "state.json", "tproxy.conf", "devices.json"} {
			header := &zip.FileHeader{Name: name, Method: zip.Deflate}
			header.SetMode(0600)
			if name == "nodes.json" && !bomb {
				header.SetMode(os.ModeSymlink | 0600)
			}
			out, err := w.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if name == "nodes.json" && bomb {
				chunk := make([]byte, 1<<20)
				for i := 0; i < 33; i++ {
					if _, err := out.Write(chunk); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				out.Write([]byte("{}"))
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBackup(buf.Bytes(), 7892); err == nil {
			t.Fatal("symlink or ZIP bomb accepted")
		}
	}
}
