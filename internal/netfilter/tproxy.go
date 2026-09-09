package netfilter

// Bare-metal TPROXY controller — NOT Docker.
// The Go proxy-manager runs as a systemd unit on Raspberry Pi OS and owns the
// nftables ruleset via scripts/tproxy/*.sh. This package is a thin os/exec
// wrapper; all netlink/nft logic lives in the shell scripts so it can be
// audited and tested without cgo or third-party Go nft libraries.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
)

// Manager owns paths to the nftables scripts rendered from tproxy.conf +
// tproxy.nft.template. Resolve them at construction so a bad install fails
// fast instead of at first Apply().
type Manager struct {
	applyScript  string
	removeScript string
	confFile     string
}

// New resolves script locations relative to repo root or explicit dir.
// dir should be scripts/tproxy; if empty it probes common layouts.
func New(dir string) (*Manager, error) {
	candidates := []string{dir}
	if dir == "" {
		// bare-metal systemd layout vs. dev checkout
		candidates = []string{
			"/opt/proxy-manager/scripts/tproxy",
			"/etc/proxy-manager/tproxy",
			"scripts/tproxy",
			filepath.Join(findRepoRoot(), "scripts/tproxy"),
		}
	}
	for _, d := range candidates {
		if d == "" {
			continue
		}
		apply := filepath.Join(d, "apply.sh")
		remove := filepath.Join(d, "remove.sh")
		conf := filepath.Join(d, "tproxy.conf")
		if fileExists(apply) && fileExists(remove) {
			return &Manager{
				applyScript:  apply,
				removeScript: remove,
				confFile:     conf,
			}, nil
		}
	}
	return nil, fmt.Errorf("netfilter: no tproxy scripts found (tried %v)", candidates)
}

// NewWithPaths is explicit — useful in tests.
func NewWithPaths(applyScript, removeScript, confFile string) *Manager {
	return &Manager{
		applyScript:  applyScript,
		removeScript: removeScript,
		confFile:     confFile,
	}
}

// Apply renders tproxy.nft.template with tproxy.conf and atomically loads
// the inet proxy_tproxy table at hook priority mangle (-150, matching the
// x_tables mangle PREROUTING convention and running BEFORE Docker's DNAT
// chains at -100). Also installs the fwmark policy-routing rule.
// Idempotent — safe to call on every startup / sing-box restart.
// Requires CAP_NET_ADMIN (systemd: AmbientCapabilities=CAP_NET_ADMIN or User=root).
func (m *Manager) Apply(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return m.run(ctx, m.applyScript)
}

// Remove tears down the TPROXY table and policy-routing rule installed by Apply.
// Idempotent — safe to call when nothing is installed. Does NOT reset
// net.ipv4.ip_forward / rp_filter (host-wide sysctls shared with Docker).
func (m *Manager) Remove(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return m.run(ctx, m.removeScript)
}

// ValidatePort checks the literal port in the administrator-owned shell config
// without executing it. The supported config format is KEY="value" (or a bare
// decimal value); shell expansion cannot safely be validated by the service.
// Service startup calls this optional check before installing interception.
func (m *Manager) ValidatePort(port int) error {
	f, err := os.Open(m.confFile)
	if err != nil {
		return fmt.Errorf("netfilter: read port configuration: %w", err)
	}
	defer f.Close()
	found := ""
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "TPROXY_PORT" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		found = value // shell semantics: the last assignment wins
	}
	if err := scan.Err(); err != nil {
		return fmt.Errorf("netfilter: scan port configuration: %w", err)
	}
	configured, err := strconv.Atoi(found)
	if err != nil || configured < 1 || configured > 65535 {
		return fmt.Errorf("netfilter: TPROXY_PORT must be a literal port in %s", m.confFile)
	}
	if configured != port {
		return fmt.Errorf("netfilter: TPROXY_PORT=%d in %s differs from engine port %d", configured, m.confFile, port)
	}
	return nil
}

// Status reports whether the interception table is currently loaded. Listing
// table names distinguishes absence from permission or netlink failures.
func (m *Manager) Status(ctx context.Context) (bool, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "list", "tables")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("nft status: %w: %s", err, stderr.String())
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "table inet proxy_tproxy" {
			return true, nil
		}
	}
	return false, nil
}

func (m *Manager) run(ctx context.Context, script string) error {
	if !fileExists(script) {
		return fmt.Errorf("netfilter: script not found: %s", script)
	}
	// Explicit bash invocation — scripts have `#!/usr/bin/env bash` but
	// systemd's PATH may not include /usr/local/bin; bash is the contract.
	cmd := exec.CommandContext(ctx, "bash", script)
	// Pass CONF_FILE through so a custom install path works without editing scripts.
	cmd.Env = append(os.Environ(), fmt.Sprintf("CONF_FILE=%s", m.confFile))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w\nstdout: %s\nstderr: %s",
			filepath.Base(script), err, stdout.String(), stderr.String())
	}
	return nil
}

func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultTimeout)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func findRepoRoot() string {
	// Walk up from this source file's directory at runtime — best-effort only.
	// Callers that need determinism should use NewWithPaths.
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}
