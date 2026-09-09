package api

// Optional browser fixture: real HTTP/session/SSE/service logic with simulated
// engine/firewall operations. Never changes the host's network configuration.
import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-manager/internal/logstream"
)

func TestBrowserFixture(t *testing.T) {
	dir := os.Getenv("PROXY_MANAGER_BROWSER_FIXTURE")
	if dir == "" {
		t.Skip("set PROXY_MANAGER_BROWSER_FIXTURE to serve a simulated gateway for browser checks")
	}
	h := newHarness(t, nil, nil)
	h.svc.cfg.Engine = &configurableTestEngine{fakeEngine: h.eng}
	logs := logstream.New("browser-test-token")
	defer logs.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, providerLink) }))
	defer provider.Close()
	srv := httptest.NewServer(NewRouter(h.svc, RouterOptions{Token: "browser-test-token", Logs: logs, Logger: quietLogger()}))
	defer srv.Close()
	data, _ := json.Marshal(map[string]string{"url": srv.URL, "subscription_url": provider.URL})
	if err := os.WriteFile(filepath.Join(dir, "ready.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			return
		}
		logs.Publish("INFO", "service", "Browser fixture: service heartbeat")
		logs.Publish("INFO", "sing-box", "Browser fixture: simulated engine output")
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("browser fixture was not stopped within five minutes")
}
