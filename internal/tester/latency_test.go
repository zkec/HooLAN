package tester

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"proxy-manager/internal/engine"
	"proxy-manager/internal/subscription"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func findSingBox(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SINGBOX_BIN"); p != "" {
		return p
	}
	p, err := exec.LookPath("sing-box")
	if err != nil {
		t.Skip("sing-box not found; set SINGBOX_BIN to run this test")
	}
	return p
}

func TestOptionDefaults(t *testing.T) {
	tt, err := New(Options{}, engine.RenderOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if tt.opts.ProbeURL != DefaultProbeURL {
		t.Errorf("ProbeURL = %q, want %q", tt.opts.ProbeURL, DefaultProbeURL)
	}
	// Plain HTTP on purpose: HTTPS would add a TLS handshake to the probe
	// target, which is noise unrelated to proxy quality.
	if got := DefaultProbeURL; got != "http://cp.cloudflare.com/generate_204" {
		t.Errorf("unexpected probe URL %q", got)
	}
	if tt.opts.Concurrency != 4 || tt.opts.Attempts != 1 || tt.opts.Timeout != 10*time.Second {
		t.Errorf("defaults: conc=%d attempts=%d timeout=%v",
			tt.opts.Concurrency, tt.opts.Attempts, tt.opts.Timeout)
	}
}

func TestNewRequiresRenderer(t *testing.T) {
	if _, err := New(Options{}, nil); err == nil {
		t.Error("New should reject a nil renderOutbound")
	}
}

func TestFastest(t *testing.T) {
	results := []Result{
		{Tag: "slow", Latency: 300 * time.Millisecond},
		{Tag: "dead", Err: errors.New("timeout")},
		{Tag: "fast", Latency: 50 * time.Millisecond},
	}
	best, ok := Fastest(results)
	if !ok {
		t.Fatal("Fastest found nothing")
	}
	if best.Tag != "fast" {
		t.Errorf("Fastest = %q, want fast", best.Tag)
	}
	// All-failed must report not-ok rather than a zero-latency phantom winner.
	if _, ok := Fastest([]Result{{Tag: "x", Err: errors.New("nope")}}); ok {
		t.Error("Fastest should return false when every probe failed")
	}
	if _, ok := Fastest(nil); ok {
		t.Error("Fastest(nil) should return false")
	}
}

// TestProbeThroughRealEngine is the end-to-end proof: a real sing-box, a real
// SOCKS inbound, and a real HTTP request. The "proxy node" is a local
// shadowsocks server run by the same binary, so no external network is needed
// and the measurement path is the production one.
func TestProbeThroughRealEngine(t *testing.T) {
	bin := findSingBox(t)

	// A local HTTP target standing in for cp.cloudflare.com.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	// Stand up a shadowsocks *server* so the probe has a real proxy to traverse.
	ssPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	const method, password = "aes-128-gcm", "0123456789abcdef"
	srvCfg := fmt.Sprintf(`{
	  "log": {"level": "error", "timestamp": false},
	  "inbounds": [{"type":"shadowsocks","tag":"ss-in","listen":"127.0.0.1",
	    "listen_port":%d,"method":%q,"password":%q}],
	  "outbounds": [{"type":"direct","tag":"direct"}]
	}`, ssPort, method, password)

	dir := t.TempDir()
	srvPath := dir + "/server.json"
	if err := os.WriteFile(srvPath, []byte(srvCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := exec.Command(bin, "run", "-c", srvPath, "-D", dir)
	srv.SysProcAttr = sysProcAttr()
	var srvLog safeBuffer
	srv.Stdout, srv.Stderr = &srvLog, &srvLog
	if err := srv.Start(); err != nil {
		t.Fatalf("start ss server: %v", err)
	}
	defer func() {
		if srv.Process != nil {
			killGroup(srv.Process.Pid)
			_ = srv.Process.Kill()
			_, _ = srv.Process.Wait()
		}
	}()

	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := waitForListener(waitCtx, fmt.Sprintf("127.0.0.1:%d", ssPort)); err != nil {
		t.Fatalf("ss server never listened: %v (log: %s)", err, srvLog.tail(400))
	}

	node := subscription.Node{
		Protocol: subscription.ProtoShadowsocks, Tag: "local-ss",
		Server: "127.0.0.1", Port: ssPort,
		Method: method, Password: password, Transport: subscription.TransportTCP,
	}

	tt, err := New(Options{
		BinaryPath: bin,
		ProbeURL:   target.URL,
		Timeout:    20 * time.Second,
		WorkDir:    dir,
		Logger:     quietLogger(),
	}, engine.RenderOutbound)
	if err != nil {
		t.Fatal(err)
	}

	res := tt.TestNode(context.Background(), node)
	if !res.OK() {
		t.Fatalf("probe failed: %v", res.Err)
	}
	if res.Latency <= 0 {
		t.Errorf("latency = %v, want > 0", res.Latency)
	}
	// Loopback through two local engines should be fast; a multi-second result
	// means we measured startup, not the path.
	if res.Latency > 5*time.Second {
		t.Errorf("implausible loopback latency %v", res.Latency)
	}
	if res.Tag != "local-ss" {
		t.Errorf("Tag = %q", res.Tag)
	}
	t.Logf("measured loopback latency: %v", res.Latency)

	// No probe config may be left behind.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if len(e.Name()) > 6 && e.Name()[:6] == "probe-" {
			t.Errorf("probe config leaked: %s", e.Name())
		}
	}
}

// A node pointing at a closed port must fail cleanly with an error, not hang
// or report a bogus latency.
func TestProbeUnreachableNode(t *testing.T) {
	bin := findSingBox(t)
	dead, err := freePort() // allocated then released: nothing is listening
	if err != nil {
		t.Fatal(err)
	}
	node := subscription.Node{
		Protocol: subscription.ProtoShadowsocks, Tag: "dead",
		Server: "127.0.0.1", Port: dead,
		Method: "aes-128-gcm", Password: "0123456789abcdef",
		Transport: subscription.TransportTCP,
	}
	tt, err := New(Options{
		BinaryPath: bin,
		ProbeURL:   "http://127.0.0.1:1/generate_204",
		Timeout:    6 * time.Second,
		WorkDir:    t.TempDir(),
		Logger:     quietLogger(),
	}, engine.RenderOutbound)
	if err != nil {
		t.Fatal(err)
	}
	res := tt.TestNode(context.Background(), node)
	if res.OK() {
		t.Fatal("probe to a dead node reported success")
	}
	if res.Latency != 0 {
		t.Errorf("failed probe reported latency %v, want 0", res.Latency)
	}
}

func TestTestNodesRespectsContextCancel(t *testing.T) {
	bin := findSingBox(t)
	tt, err := New(Options{
		BinaryPath: bin, Timeout: 5 * time.Second, Concurrency: 2,
		WorkDir: t.TempDir(), Logger: quietLogger(),
	}, engine.RenderOutbound)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []subscription.Node{
		{Protocol: subscription.ProtoShadowsocks, Tag: "a", Server: "127.0.0.1", Port: 1,
			Method: "aes-128-gcm", Password: "0123456789abcdef"},
		{Protocol: subscription.ProtoShadowsocks, Tag: "b", Server: "127.0.0.1", Port: 2,
			Method: "aes-128-gcm", Password: "0123456789abcdef"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already dead

	start := time.Now()
	results := tt.TestNodes(ctx, nodes)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if r.OK() {
			t.Errorf("%s: succeeded despite a cancelled context", r.Tag)
		}
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("cancelled sweep took %v; cancellation is not being honoured", elapsed)
	}
}

func TestFreePortReturnsUsable(t *testing.T) {
	p, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	if p <= 0 || p > 65535 {
		t.Fatalf("freePort = %d", p)
	}
	// Must be bindable after release.
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		t.Fatalf("port %d not bindable after freePort: %v", p, err)
	}
	l.Close()
}

func TestSafeBufferBounded(t *testing.T) {
	var b safeBuffer
	chunk := make([]byte, 1024)
	for i := range chunk {
		chunk[i] = 'x'
	}
	// Write well past the cap; a probe against a chatty engine must not grow
	// the heap without limit.
	for i := 0; i < 32; i++ {
		if _, err := b.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(b.buf); got > maxLogBytes {
		t.Errorf("buffer grew to %d, cap is %d", got, maxLogBytes)
	}
	if tail := b.tail(10); len(tail) != 10 {
		t.Errorf("tail(10) len = %d", len(tail))
	}
}
