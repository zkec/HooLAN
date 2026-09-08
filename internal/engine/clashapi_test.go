package engine

// Tests for the clash_api control channel.
//
// The `run`-based test here is not redundant with `check`: verified repeatedly in
// this package, sing-box's check subcommand accepts configs that run FATALs on.
// clash_api additionally depends on a BUILD TAG (with_clash_api), which check
// cannot tell you about at all -- a binary without it parses the block and simply
// never opens the listener. Only starting the engine and connecting proves the
// control channel exists.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClashAPIEmitted(t *testing.T) {
	m := NewManager(Options{
		Logger:         quietLogger(),
		ClashAPIListen: "127.0.0.1:9090",
		ClashAPISecret: "hunter2",
		CacheFilePath:  "/var/lib/pm/cache.db",
	})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if cfg.Experimental == nil || cfg.Experimental.ClashAPI == nil {
		t.Fatal("clash_api block missing")
	}
	if got := cfg.Experimental.ClashAPI.ExternalController; got != "127.0.0.1:9090" {
		t.Errorf("external_controller = %q", got)
	}
	if got := cfg.Experimental.ClashAPI.Secret; got != "hunter2" {
		t.Errorf("secret = %q", got)
	}
	// A cache file is what makes a pinned node survive an engine restart; there
	// is no separate store_selected flag on 1.14 (see CacheFileOptions).
	if cfg.Experimental.CacheFile == nil || !cfg.Experimental.CacheFile.Enabled {
		t.Error("cache_file should be enabled so the selection survives a restart")
	}
}

func TestClashAPIOmittedByDefault(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger()})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if cfg.Experimental != nil && cfg.Experimental.ClashAPI != nil {
		t.Error("clash_api emitted without ClashAPIListen set")
	}
	// An unauthenticated control API must never appear just because someone
	// enabled a cache file.
	m2 := NewManager(Options{Logger: quietLogger(), CacheFilePath: "/tmp/cache.db"})
	cfg2, err := m2.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if cfg2.Experimental.ClashAPI != nil {
		t.Error("cache file alone should not enable clash_api")
	}
}

// TestRealSingBoxServesClashAPI is the end-to-end proof that live node switching
// works: it starts the real engine and drives the selector through the API, which
// is exactly what POST /api/proxy/select does.
func TestRealSingBoxServesClashAPI(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()

	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	m := NewManager(Options{
		BinaryPath: bin,
		ConfigPath: filepath.Join(dir, "config.json"),
		Logger:     quietLogger(),
		// Iran rule-sets fetch ~350 KB from the network; irrelevant to the
		// control channel and it makes the test depend on GitHub being up.
		DisableIranBypass: true,
		ClashAPIListen:    addr,
		CacheFilePath:     filepath.Join(dir, "cache.db"),
	})

	nodes := testNodes()
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if err := m.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	if err := m.Check(context.Background()); err != nil {
		raw, _ := os.ReadFile(m.ConfigPath())
		t.Fatalf("real sing-box rejected the clash_api config: %v\n--- config ---\n%s", err, raw)
	}
	// Binding TPROXY needs CAP_NET_ADMIN, so swap in a loopback inbound. The
	// outbounds, selector, urltest group and experimental block -- everything the
	// control channel touches -- are exactly what BuildConfig produced.
	useLoopbackInbound(t, m, cfg)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = m.Stop(ctx)
	})

	base := "http://" + addr
	client := &http.Client{Timeout: 3 * time.Second}

	// The listener is not up the instant Start returns.
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(base + "/proxies/" + DefaultSelector)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				lastErr = nil
				break
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("clash api never became reachable at %s: %v "+
			"(is this binary built with with_clash_api?)", addr, lastErr)
	}

	// The selector defaults to the urltest group, so a fresh install
	// auto-switches until an operator pins a node.
	group := getGroup(t, client, base, DefaultSelector)
	if group["now"] != DefaultURLTest {
		t.Errorf("selector default = %v, want %q", group["now"], DefaultURLTest)
	}

	// Pin a specific node, the way POST /api/proxy/select does.
	target := nodes[len(nodes)-1].Tag
	body, err := json.Marshal(map[string]string{"name": target})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPut,
		base+"/proxies/"+DefaultSelector, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT selector: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("PUT selector status = %d, want 2xx", resp.StatusCode)
	}

	if group = getGroup(t, client, base, DefaultSelector); group["now"] != target {
		t.Errorf("selector now = %v, want %q: live switching does not work", group["now"], target)
	}

	// A member that does not exist must be refused, not silently accepted --
	// that is the failure the API layer's ID->tag mapping exists to prevent.
	bad, err := json.Marshal(map[string]string{"name": "no-such-node"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err = http.NewRequest(http.MethodPut,
		base+"/proxies/"+DefaultSelector, strings.NewReader(string(bad)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PUT bogus member: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		t.Error("clash api accepted a nonexistent selector member")
	}
}

// TestRealSingBoxPersistsSelectionAcrossRestart pins the behaviour the API layer
// relies on: with cache_file enabled, a pinned node survives an engine restart
// WITHOUT any store_selected field (which 1.14 rejects on cache_file and fatals
// on in clash_api). If a future sing-box changes this, the operator's pinned node
// would silently revert to auto after any config reload -- so it is asserted
// against the real binary rather than assumed.
func TestRealSingBoxPersistsSelectionAcrossRestart(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()

	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	newManager := func() *Manager {
		return NewManager(Options{
			BinaryPath:        bin,
			ConfigPath:        filepath.Join(dir, "config.json"),
			Logger:            quietLogger(),
			DisableIranBypass: true,
			ClashAPIListen:    addr,
			CacheFilePath:     filepath.Join(dir, "cache.db"),
		})
	}

	nodes := testNodes()
	target := nodes[len(nodes)-1].Tag
	client := &http.Client{Timeout: 3 * time.Second}
	base := "http://" + addr

	m := newManager()
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	useLoopbackInbound(t, m, cfg)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitClashReady(t, client, base)

	if err := putSelector(client, base, target); err != nil {
		stopManager(t, m)
		t.Fatalf("pin node: %v", err)
	}
	stopManager(t, m)

	// Restart against the same cache file, as a systemd restart would.
	m2 := newManager()
	if err := m2.Start(context.Background()); err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer stopManager(t, m2)
	waitClashReady(t, client, base)

	if group := getGroup(t, client, base, DefaultSelector); group["now"] != target {
		t.Errorf("after restart selector now = %v, want the pinned %q: "+
			"selection did not persist, so an operator's choice silently reverts to auto",
			group["now"], target)
	}
}

func stopManager(t *testing.T, m *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func putSelector(c *http.Client, base, member string) error {
	body, err := json.Marshal(map[string]string{"name": member})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut,
		base+"/proxies/"+DefaultSelector, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func waitClashReady(t *testing.T, c *http.Client, base string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := c.Get(base + "/proxies/" + DefaultSelector)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("clash api never became ready at %s: %v", base, lastErr)
}

func getGroup(t *testing.T, c *http.Client, base, name string) map[string]any {
	t.Helper()
	resp, err := c.Get(base + "/proxies/" + name)
	if err != nil {
		t.Fatalf("GET /proxies/%s: %v", name, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /proxies/%s: %v", name, err)
	}
	return out
}

// useLoopbackInbound rewrites the config's privileged tproxy inbound to a
// loopback mixed inbound and writes it, so the engine starts without
// CAP_NET_ADMIN. Everything else in the config is untouched.
func useLoopbackInbound(t *testing.T, m *Manager, cfg *Config) {
	t.Helper()
	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	cfg.Inbounds = []any{map[string]any{
		"type": "mixed", "tag": m.opts.InboundTag,
		"listen": "127.0.0.1", "listen_port": port,
	}}
	if err := m.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
}
