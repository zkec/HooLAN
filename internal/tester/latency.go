// Package tester measures per-node latency through the real proxy engine.
//
// DESIGN: why this does not "dial the protocol directly".
//
// A native Go dialer for each protocol would mean reimplementing VLESS with
// XTLS-Vision flow control, Trojan, VMess AEAD, Shadowsocks AEAD ciphers,
// Hysteria2 over QUIC, plus uTLS ClientHello mimicry and the REALITY handshake.
// That is thousands of lines of security-critical crypto whose bugs would be
// silent wrong answers -- a node reported dead because our handshake was
// subtly wrong, not because the node is down. Worse, the measurement would no
// longer describe the path that actually carries traffic.
//
// Instead we start a short-lived sing-box with a local SOCKS inbound per node
// and measure an HTTP request through it. The number is then a true end-to-end
// measurement of the same code path production traffic uses, and support for a
// new protocol comes for free the moment the engine supports it.
//
// The cost is one process per sweep and a few hundred ms of engine startup,
// which is irrelevant for a probe that runs on a timer.
package tester

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"hoolan/internal/subscription"
)

// DefaultProbeURL is a 204-returning endpoint: no body to download, so the
// measurement is dominated by connection setup rather than transfer size.
// Plain HTTP (not HTTPS) on purpose -- it excludes TLS handshake time to the
// probe target, which is noise unrelated to proxy quality.
const DefaultProbeURL = "http://cp.cloudflare.com/generate_204"

// Result is one node's measurement.
type Result struct {
	Tag     string
	Latency time.Duration
	Err     error
}

// OK reports a successful measurement.
func (r Result) OK() bool { return r.Err == nil }

// Options configures a Tester.
type Options struct {
	// BinaryPath is the sing-box executable. Default: "sing-box" from PATH.
	BinaryPath string
	// ProbeURL is the target. Default: DefaultProbeURL.
	ProbeURL string
	// Timeout bounds a single node's probe, including engine startup.
	// Default: 10s.
	Timeout time.Duration
	// Attempts per node; the fastest success wins. Default: 1.
	// Values above 1 reduce the effect of a single unlucky packet loss.
	Attempts int
	// Concurrency caps simultaneous probes. Default: 4. Each probe is its own
	// engine process, so this bounds memory on a Debian host -- do not set it to
	// len(nodes) for a 200-node subscription.
	Concurrency int
	// WorkDir holds temporary configs. Default: os.TempDir().
	WorkDir string
	// Logger; defaults to slog.Default().
	Logger *slog.Logger
}

func (o *Options) setDefaults() {
	if o.BinaryPath == "" {
		o.BinaryPath = "sing-box"
	}
	if o.ProbeURL == "" {
		o.ProbeURL = DefaultProbeURL
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Attempts <= 0 {
		o.Attempts = 1
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// Tester measures latency for nodes.
type Tester struct {
	opts Options
	// renderOutbound converts a node to a sing-box outbound. Injected to avoid
	// an import cycle with internal/engine, which imports this package's
	// sibling types.
	renderOutbound func(subscription.Node) (any, error)
}

// New returns a Tester. renderOutbound must produce a JSON-marshalable
// sing-box outbound for a node; pass engine.RenderOutbound.
func New(opts Options, renderOutbound func(subscription.Node) (any, error)) (*Tester, error) {
	if renderOutbound == nil {
		return nil, errors.New("tester: renderOutbound is required")
	}
	opts.setDefaults()
	return &Tester{opts: opts, renderOutbound: renderOutbound}, nil
}

// TestNode measures one node.
func (t *Tester) TestNode(ctx context.Context, node subscription.Node) Result {
	res := Result{Tag: node.Tag}
	best := time.Duration(0)
	var lastErr error

	for attempt := 0; attempt < t.opts.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			res.Err = err
			return res
		}
		d, err := t.probeOnce(ctx, node)
		if err != nil {
			lastErr = err
			continue
		}
		if best == 0 || d < best {
			best = d
		}
	}
	if best == 0 {
		res.Err = lastErr
		if res.Err == nil {
			res.Err = errors.New("tester: no successful attempt")
		}
		return res
	}
	res.Latency = best
	return res
}

// TestNodes measures many nodes, bounded by Options.Concurrency.
//
// Chained nodes (Detour set) require their upstream hops present in the same
// engine instance, so probing them in isolation would fail with
// "dependency not found". They are probed with their full chain rendered.
func (t *Tester) TestNodes(ctx context.Context, nodes []subscription.Node) []Result {
	return t.TestSelectedNodes(ctx, nodes, nodes)
}

// TestSelectedNodes probes targets with the complete inventory available for
// resolving detour dependencies, without probing those dependencies separately.
func (t *Tester) TestSelectedNodes(ctx context.Context, nodes, inventory []subscription.Node) []Result {
	results := make([]Result, len(nodes))
	sem := make(chan struct{}, t.opts.Concurrency)
	var wg sync.WaitGroup

	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n subscription.Node) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = Result{Tag: n.Tag, Err: ctx.Err()}
				return
			}
			results[i] = t.testWithChain(ctx, n, inventory)
		}(i, n)
	}
	wg.Wait()
	return results
}

// testWithChain probes a node, including any detour hops it depends on.
func (t *Tester) testWithChain(ctx context.Context, n subscription.Node, all []subscription.Node) Result {
	if n.Detour == "" {
		return t.TestNode(ctx, n)
	}
	chain := subscription.ChainOf(all, n.Tag)
	byTag := make(map[string]subscription.Node, len(all))
	for _, c := range all {
		byTag[c.Tag] = c
	}
	deps := make([]subscription.Node, 0, len(chain))
	for _, tag := range chain {
		if node, ok := byTag[tag]; ok {
			deps = append(deps, node)
		}
	}

	res := Result{Tag: n.Tag}
	best := time.Duration(0)
	var lastErr error
	for attempt := 0; attempt < t.opts.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			res.Err = err
			return res
		}
		d, err := t.probeChain(ctx, n, deps)
		if err != nil {
			lastErr = err
			continue
		}
		if best == 0 || d < best {
			best = d
		}
	}
	if best == 0 {
		res.Err = lastErr
		if res.Err == nil {
			res.Err = errors.New("tester: no successful attempt")
		}
		return res
	}
	res.Latency = best
	return res
}

// Fastest returns the successful result with the lowest latency.
func Fastest(results []Result) (Result, bool) {
	ok := make([]Result, 0, len(results))
	for _, r := range results {
		if r.OK() {
			ok = append(ok, r)
		}
	}
	if len(ok) == 0 {
		return Result{}, false
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].Latency < ok[j].Latency })
	return ok[0], true
}

func (t *Tester) probeOnce(ctx context.Context, node subscription.Node) (time.Duration, error) {
	return t.probeChain(ctx, node, []subscription.Node{node})
}

// probeChain starts a sing-box with a SOCKS inbound routed to target, renders
// every node in deps as an outbound (so detour dependencies resolve), measures
// one HTTP request, then tears the engine down.
func (t *Tester) probeChain(ctx context.Context, target subscription.Node, deps []subscription.Node) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, t.opts.Timeout)
	defer cancel()

	// Port 0 lets the kernel assign a free port; we then close the listener and
	// hand the number to sing-box. There is an unavoidable race window between
	// close and sing-box binding, but a collision surfaces as a clean startup
	// error rather than a wrong measurement, and the alternative (a fixed port)
	// breaks all concurrency.
	port, err := freePort()
	if err != nil {
		return 0, fmt.Errorf("tester: allocate port: %w", err)
	}

	cfgPath, cleanup, err := t.writeProbeConfig(target, deps, port)
	if err != nil {
		return 0, err
	}
	defer cleanup()

	proc, err := t.startEngine(ctx, cfgPath)
	if err != nil {
		return 0, err
	}
	defer proc.stop()

	socks := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitForListener(ctx, socks); err != nil {
		return 0, fmt.Errorf("tester: engine did not open socks port: %w (engine log: %s)",
			err, proc.tail())
	}

	return t.measure(ctx, socks)
}

// writeProbeConfig renders a minimal engine config: SOCKS in, target out.
func (t *Tester) writeProbeConfig(target subscription.Node, deps []subscription.Node, port int) (string, func(), error) {
	outbounds := make([]any, 0, len(deps)+1)
	seen := make(map[string]bool, len(deps))
	for _, d := range deps {
		if seen[d.Tag] {
			continue
		}
		seen[d.Tag] = true
		ob, err := t.renderOutbound(d)
		if err != nil {
			return "", func() {}, fmt.Errorf("tester: render %q: %w", d.Tag, err)
		}
		outbounds = append(outbounds, ob)
	}
	if len(outbounds) == 0 {
		return "", func() {}, errors.New("tester: no outbounds to probe")
	}

	cfg := map[string]any{
		// Engine logs go to stderr and are captured; "warn" keeps the noise
		// down while still reporting handshake failures.
		"log": map[string]any{"level": "warn", "timestamp": false},
		"inbounds": []any{map[string]any{
			"type":        "socks",
			"tag":         "probe-in",
			"listen":      "127.0.0.1",
			"listen_port": port,
		}},
		"outbounds": outbounds,
		"route": map[string]any{
			"final": target.Tag,
			// No rule_set here on purpose: a probe must not download remote
			// rule-sets, both for speed and because a rule-set fetch failure
			// would be misreported as node latency.
		},
	}

	dir := t.opts.WorkDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", func() {}, fmt.Errorf("tester: mkdir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, "probe-*.json")
	if err != nil {
		return "", func() {}, fmt.Errorf("tester: temp config: %w", err)
	}
	name := f.Name()
	cleanup := func() { os.Remove(name) }

	// 0600: probe configs contain the same credentials as the live config.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("tester: chmod: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("tester: encode probe config: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("tester: close probe config: %w", err)
	}
	return name, cleanup, nil
}

// engineProc is a running probe engine.
type engineProc struct {
	cmd  *exec.Cmd
	logs *safeBuffer
	done chan struct{}
}

func (p *engineProc) stop() {
	if p.cmd.Process != nil {
		// Signal the group: sing-box is started with its own process group so a
		// probe engine cannot outlive the sweep and hold a port.
		killGroup(p.cmd.Process.Pid)
		_ = p.cmd.Process.Kill()
	}
	<-p.done
}

func (p *engineProc) tail() string { return p.logs.tail(400) }

func (t *Tester) startEngine(ctx context.Context, cfgPath string) (*engineProc, error) {
	cmd := exec.Command(t.opts.BinaryPath, "run", "-c", cfgPath,
		"-D", filepath.Dir(cfgPath))
	cmd.SysProcAttr = sysProcAttr()
	logs := &safeBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tester: start engine: %w", err)
	}
	p := &engineProc{cmd: cmd, logs: logs, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// measure issues one request through the SOCKS proxy and returns elapsed time.
func (t *Tester) measure(ctx context.Context, socksAddr string) (time.Duration, error) {
	proxyURL, err := url.Parse("socks5://" + socksAddr)
	if err != nil {
		return 0, fmt.Errorf("tester: proxy url: %w", err)
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		// One connection, no reuse across probes: a pooled connection would
		// make the second attempt measure nothing but the request round-trip.
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.opts.ProbeURL, nil)
	if err != nil {
		return 0, fmt.Errorf("tester: build request: %w", err)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("tester: probe request: %w", err)
	}
	defer resp.Body.Close()
	// Drain so the timing covers a complete exchange; generate_204 has no body,
	// so this is a formality that also releases the connection.
	_, _ = io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)

	// 204 is the contract. Anything else means a captive portal or an
	// intercepting proxy answered, which is not a valid measurement.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("tester: unexpected status %d (captive portal?)", resp.StatusCode)
	}
	return elapsed, nil
}

// freePort asks the kernel for an unused TCP port.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

// waitForListener polls until the engine accepts connections. Engine startup is
// not instant and a request fired too early fails with connection-refused,
// which would be misreported as node failure.
func waitForListener(ctx context.Context, addr string) error {
	ticker := time.NewTicker(15 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// safeBuffer is a bounded, mutex-guarded sink for engine output. Bounded
// because a misconfigured engine can log continuously and a probe must not
// grow the heap without limit.
type safeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

const maxLogBytes = 8 << 10

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > maxLogBytes {
		b.buf = b.buf[len(b.buf)-maxLogBytes:]
	}
	return len(p), nil
}

func (b *safeBuffer) tail(n int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) <= n {
		return string(b.buf)
	}
	return string(b.buf[len(b.buf)-n:])
}
