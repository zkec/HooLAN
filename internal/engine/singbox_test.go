package engine

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"proxy-manager/internal/subscription"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testNodes() []subscription.Node {
	return []subscription.Node{
		{
			// PublicKey must be a real base64 x25519 key: sing-box validates it
			// at config-check time and rejects placeholders outright.
			Protocol: subscription.ProtoVLESS, Tag: "US", Server: "a.example", Port: 443,
			UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Flow: "xtls-rprx-vision",
			Security: subscription.SecReality, SNI: "www.microsoft.com",
			PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", ShortID: "01",
			Fingerprint: "chrome", Transport: subscription.TransportTCP,
		},
		{
			Protocol: subscription.ProtoTrojan, Tag: "JP", Server: "b.example", Port: 8443,
			Password: "pw", Security: subscription.SecTLS, SNI: "b.example",
			Transport: subscription.TransportWS, Path: "/ws", Host: "cdn.example",
		},
	}
}

// allProtocolNodes covers every protocol/transport/TLS combination the
// renderer can emit, for validation against the real engine.
func allProtocolNodes() []subscription.Node {
	return []subscription.Node{
		{
			Protocol: subscription.ProtoVLESS, Tag: "vless-reality", Server: "a.example", Port: 443,
			UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Flow: "xtls-rprx-vision",
			Security: subscription.SecReality, SNI: "www.microsoft.com",
			PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", ShortID: "0123456789abcdef",
			Fingerprint: "chrome", Transport: subscription.TransportTCP,
		},
		{
			Protocol: subscription.ProtoVLESS, Tag: "vless-grpc", Server: "g.example", Port: 443,
			UUID: "bf000d23-0752-40b4-affe-68f7707a9662", Security: subscription.SecTLS,
			SNI: "g.example", Transport: subscription.TransportGRPC, ServiceName: "GunService",
		},
		{
			Protocol: subscription.ProtoTrojan, Tag: "trojan-ws", Server: "b.example", Port: 8443,
			Password: "pw", Security: subscription.SecTLS, SNI: "b.example",
			Transport: subscription.TransportWS, Path: "/ws", Host: "cdn.example",
			ALPN: []string{"h2", "http/1.1"},
		},
		{
			Protocol: subscription.ProtoVMess, Tag: "vmess-tcp", Server: "c.example", Port: 443,
			UUID: "bf000d23-0752-40b4-affe-68f7707a9663", Method: "auto", AlterID: 0,
			Security: subscription.SecTLS, SNI: "c.example", Transport: subscription.TransportTCP,
		},
		{
			Protocol: subscription.ProtoShadowsocks, Tag: "ss", Server: "d.example", Port: 8388,
			Method: "aes-256-gcm", Password: "sspw", Transport: subscription.TransportTCP,
		},
		{
			Protocol: subscription.ProtoHysteria2, Tag: "hy2", Server: "e.example", Port: 443,
			Password: "hypw", Security: subscription.SecTLS, SNI: "e.example",
		},
	}
}

func TestBuildConfigTProxyInbound(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger()})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	buf, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(buf)

	in, ok := cfg.Inbounds[0].(*TProxyInbound)
	if !ok {
		t.Fatalf("inbound[0] is %T, want *TProxyInbound", cfg.Inbounds[0])
	}
	if in.Type != "tproxy" {
		t.Errorf("inbound type = %q, want tproxy", in.Type)
	}
	if in.Listen != "::" {
		t.Errorf("listen = %q, want ::", in.Listen)
	}
	if in.ListenPort != 7892 {
		t.Errorf("listen_port = %d, want 7892", in.ListenPort)
	}
	// The whole point: no bogus field in the emitted JSON by default.
	if strings.Contains(got, "transparent") {
		t.Errorf("config contains invalid 'transparent' field:\n%s", got)
	}
	// Removed-in-1.13 inbound fields must not appear either. Match the key with
	// its colon: a bare `"sniff"` substring also matches the legitimate
	// `"sniffer"` key inside the route rule.
	for _, dead := range []string{`"sniff":`, `"sniff_override_destination":`, `"domain_strategy":`} {
		if strings.Contains(got, dead) {
			t.Errorf("config contains field removed in sing-box 1.13: %s", dead)
		}
	}
	// Sniffing must be present as a rule action instead. Searched rather than
	// pinned to index 0: the self-connection loop breaker precedes it (see
	// TestLoopBreakerIsFirstRule).
	if cfg.Route == nil {
		t.Fatal("expected a route block")
	}
	var sniffed bool
	for _, r := range cfg.Route.Rules {
		if r.Action == "sniff" {
			sniffed = true
			break
		}
	}
	if !sniffed {
		t.Error("expected a route rule with action=sniff")
	}
}

func TestBuildConfigOptInInvalidField(t *testing.T) {
	// Opt-in reproduction path: proves the flag actually emits the bad field,
	// so the claim "sing-box rejects this" can be tested against a real binary.
	m := NewManager(Options{Logger: quietLogger(), LegacyTransparentField: true})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	buf, _ := json.Marshal(cfg)
	if !strings.Contains(string(buf), `"transparent":true`) {
		t.Error("LegacyTransparentField=true should emit the (invalid) field")
	}
}

func TestBuildConfigOutbounds(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger()})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	// direct + direct-fetch + 2 nodes + urltest + selector.
	// direct-fetch exists so remote rule-sets have a non-empty direct outbound
	// to fetch through; see TestRuleSetDownloadPrerequisites.
	if len(cfg.Outbounds) != 6 {
		t.Fatalf("got %d outbounds, want 6: %+v", len(cfg.Outbounds), cfg.Outbounds)
	}
	// Index by type rather than position so adding an infrastructure outbound
	// does not require renumbering every assertion.
	var vlessOB *VLESSOutbound
	var trojanOB *TrojanOutbound
	var autoOB *URLTestOutbound
	var selOB *SelectorOutbound
	for _, ob := range cfg.Outbounds {
		switch o := ob.(type) {
		case *VLESSOutbound:
			vlessOB = o
		case *TrojanOutbound:
			trojanOB = o
		case *URLTestOutbound:
			autoOB = o
		case *SelectorOutbound:
			selOB = o
		}
	}
	vless, ok := vlessOB, vlessOB != nil
	if !ok {
		t.Fatal("no vless outbound rendered")
	}
	if vless.TLS == nil || vless.TLS.Reality == nil {
		t.Fatal("vless reality block missing")
	}
	if want := "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"; vless.TLS.Reality.PublicKey != want {
		t.Errorf("reality public_key = %q, want %q", vless.TLS.Reality.PublicKey, want)
	}
	if vless.TLS.UTLS == nil || vless.TLS.UTLS.Fingerprint != "chrome" {
		t.Error("reality requires utls fingerprint")
	}
	if vless.TLS.Insecure {
		t.Error("reality must not set insecure")
	}
	trojan, ok := trojanOB, trojanOB != nil
	if !ok {
		t.Fatal("no trojan outbound rendered")
	}
	if trojan.Transport == nil || trojan.Transport.Type != "ws" {
		t.Fatal("trojan ws transport missing")
	}
	if h := trojan.Transport.Headers["Host"]; len(h) != 1 || h[0] != "cdn.example" {
		t.Errorf("ws Host header = %v", trojan.Transport.Headers)
	}
	auto, ok := autoOB, autoOB != nil
	if !ok {
		t.Fatal("no urltest outbound rendered")
	}
	if len(auto.Outbounds) != 2 {
		t.Errorf("urltest has %d members, want 2", len(auto.Outbounds))
	}
	sel, ok := selOB, selOB != nil
	if !ok {
		t.Fatal("no selector outbound rendered")
	}
	// auto + 2 nodes; auto must be first so it is the default.
	if len(sel.Outbounds) != 3 {
		t.Errorf("selector has %d members, want 3 (auto + 2 nodes)", len(sel.Outbounds))
	}
	if sel.Outbounds[0] != DefaultURLTest {
		t.Errorf("selector[0] = %q, want %q", sel.Outbounds[0], DefaultURLTest)
	}
	if sel.Default != DefaultURLTest {
		t.Errorf("selector default = %q, want %q", sel.Default, DefaultURLTest)
	}
}

func TestBuildConfigEmptyNodes(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger()})
	if _, err := m.BuildConfig(nil); err == nil {
		t.Error("expected error for empty node list")
	}
}

func TestWriteConfigAtomicAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.json")
	m := NewManager(Options{ConfigPath: path, Logger: quietLogger()})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if err := m.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600 (config holds UUIDs/passwords)", perm)
	}
	// Must be valid JSON and must round-trip.
	raw, _ := os.ReadFile(path)
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("written config is not valid JSON: %v", err)
	}
	// No temp files left behind.
	ents, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".config-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// --- process supervision ----------------------------------------------------

// fakeEngine writes a tiny shell script that behaves like a long-running
// engine, so lifecycle can be tested without sing-box installed.
//
// readyFile is touched by the script once it has finished initialising. Tests
// MUST wait for it before signalling: /bin/sh takes a few hundred microseconds
// to reach `trap`, and a SIGTERM that arrives first is handled by the default
// disposition (terminate) instead of the trap, which silently invalidates any
// test of the escalation path.
func fakeEngine(t *testing.T, readyFile, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-engine")
	script := "#!/bin/sh\n" + body + "\ntouch " + readyFile + "\nwhile true; do sleep 0.2; done\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake engine: %v", err)
	}
	return p
}

// waitReady blocks until the fake engine signals initialisation is complete.
func waitReady(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("fake engine never became ready (%s)", path)
}

func TestStartStopLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process-group semantics are Linux-specific here")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Default SIGTERM disposition: exits promptly.
	ready := filepath.Join(dir, "ready")
	bin := fakeEngine(t, ready, `echo started`)

	exited := make(chan error, 1)
	m := NewManager(Options{
		BinaryPath: bin, ConfigPath: cfgPath, Logger: quietLogger(),
		OnExit: func(err error) { exited <- err },
	})

	if m.Running() {
		t.Error("Running() true before Start")
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitReady(t, ready)
	if !m.Running() {
		t.Error("Running() false after Start")
	}
	pid := m.Pid()
	if pid <= 0 {
		t.Fatalf("Pid() = %d", pid)
	}
	// Double Start must be refused rather than leaking a second process.
	if err := m.Start(context.Background()); err == nil {
		t.Error("second Start should fail")
	}

	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("OnExit never fired")
	}
	if m.Running() {
		t.Error("Running() true after Stop")
	}
	// Stop must be idempotent.
	if err := m.Stop(context.Background()); err != nil {
		t.Errorf("second Stop: %v", err)
	}
	// And Start must work again after a clean Stop.
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("restart after stop: %v", err)
	}
	_ = m.Stop(context.Background())
}

func TestStopEscalatesToKill(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Deliberately ignores SIGTERM — the case StopTimeout exists for. The trap
	// must be installed before we signal, hence the ready handshake.
	ready := filepath.Join(dir, "ready")
	bin := fakeEngine(t, ready, `trap '' TERM; echo ignoring-term`)

	m := NewManager(Options{
		BinaryPath: bin, ConfigPath: cfgPath, Logger: quietLogger(),
		StopTimeout: 600 * time.Millisecond,
	})
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitReady(t, ready)
	start := time.Now()
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Errorf("Stop returned in %v — SIGTERM grace period was skipped", elapsed)
	}
	if m.Running() {
		t.Error("process survived SIGKILL escalation")
	}
}

func TestStartMissingConfig(t *testing.T) {
	m := NewManager(Options{
		BinaryPath: "/bin/true",
		ConfigPath: filepath.Join(t.TempDir(), "does-not-exist.json"),
		Logger:     quietLogger(),
	})
	if err := m.Start(context.Background()); err == nil {
		t.Error("Start should fail when config is absent")
	}
}
