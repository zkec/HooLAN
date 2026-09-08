package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// findSingBox locates a real sing-box binary. Set SINGBOX_BIN to point at one;
// otherwise PATH is searched. These tests skip when it is unavailable, so the
// suite still passes on a machine without the engine installed.
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

// TestCheckAgainstRealSingBox is the test that matters: it proves the generated
// config is accepted by the engine that will actually run it, rather than by my
// reading of the schema.
func TestCheckAgainstRealSingBox(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()
	m := NewManager(Options{
		BinaryPath: bin,
		ConfigPath: filepath.Join(dir, "config.json"),
		Logger:     quietLogger(),
	})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if err := m.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	if err := m.Check(context.Background()); err != nil {
		raw, _ := os.ReadFile(m.ConfigPath())
		t.Fatalf("real sing-box rejected the generated config: %v\n--- config ---\n%s", err, raw)
	}
}

// TestRealSingBoxRejectsTransparentField documents WHY the tproxy inbound has no
// "transparent" field, by having the engine itself say so. If a future sing-box
// ever adds the field, this test fails and the LegacyTransparentField option and
// its comments should be revisited.
func TestRealSingBoxRejectsTransparentField(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()
	m := NewManager(Options{
		BinaryPath:             bin,
		ConfigPath:             filepath.Join(dir, "config.json"),
		Logger:                 quietLogger(),
		LegacyTransparentField: true,
	})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if err := m.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	err = m.Check(context.Background())
	if err == nil {
		t.Fatal(`sing-box ACCEPTED "transparent" on the tproxy inbound — ` +
			`the schema has changed; revisit Options.LegacyTransparentField`)
	}
	if !strings.Contains(err.Error(), "transparent") {
		t.Errorf("expected the error to name the offending field, got: %v", err)
	}
	t.Logf("confirmed rejection: %v", err)
}

// TestCheckAllProtocols validates every protocol the parser can emit, so an
// unsupported field in a rarely-used outbound is caught here rather than at
// 2am on the Pi.
func TestCheckAllProtocols(t *testing.T) {
	bin := findSingBox(t)
	nodes := allProtocolNodes()
	dir := t.TempDir()
	m := NewManager(Options{
		BinaryPath: bin,
		ConfigPath: filepath.Join(dir, "config.json"),
		Logger:     quietLogger(),
	})
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if err := m.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	if err := m.Check(context.Background()); err != nil {
		raw, _ := os.ReadFile(m.ConfigPath())
		t.Fatalf("sing-box rejected multi-protocol config: %v\n--- config ---\n%s", err, raw)
	}
}
