package tester

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"hoolan/internal/subscription"
	"strings"
	"time"
)

const SpeedBytes int64 = 15_000_000
const SpeedURL = "https://speed.cloudflare.com/__down?bytes=15000000"

type SpeedResult struct {
	Bytes   int64   `json:"bytes"`
	Seconds float64 `json:"seconds"`
	Mbps    float64 `json:"mbps"`
	Server  string  `json:"server"`
}

// TestSpeed uses an isolated engine and the selected node's entire detour path.
// Engine startup is excluded; download timing includes remote DNS/TLS/TTFB.
func (t *Tester) TestSpeed(ctx context.Context, target subscription.Node, inventory []subscription.Node) (SpeedResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var result SpeedResult
	err := t.WithProxyClient(ctx, target, inventory, func(client *http.Client) error {
		var err error
		result, err = measureSpeed(ctx, client)
		return err
	})
	return result, err
}

// WithProxyClient runs a bounded HTTP operation through a temporary sing-box
// SOCKS listener and the complete target chain. It never changes LAN routing.
// The callback must finish using the client before returning.
func (t *Tester) WithProxyClient(ctx context.Context, target subscription.Node, inventory []subscription.Node, use func(*http.Client) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := subscription.ValidateChains(inventory); err != nil {
		return err
	}
	tags := subscription.ChainOf(inventory, target.Tag)
	deps := []subscription.Node{}
	for _, tag := range tags {
		for _, n := range inventory {
			if n.Tag == tag {
				deps = append(deps, n)
				break
			}
		}
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	path, cleanup, err := t.writeProbeConfig(target, deps, port)
	if err != nil {
		return err
	}
	defer cleanup()
	proc, err := t.startEngine(ctx, path)
	if err != nil {
		return err
	}
	defer proc.stop()
	socks := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitForListener(ctx, socks); err != nil {
		return fmt.Errorf("proxy HTTP engine did not start: %w", err)
	}
	proxy, _ := url.Parse("socks5://" + socks)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableCompression: true, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return use(client)
}

type speedEndpoint struct {
	URL   string
	Bytes int64
}

// Independent hosts avoid treating a CDN's rejection of a proxy exit as a
// broken proxy. Keep payloads fixed, HTTPS-only, and bounded.
var speedEndpoints = []speedEndpoint{
	{SpeedURL, SpeedBytes},
	{"https://speedtest.netone.nl/speedtest/random-10mb.bin", 10 * 1024 * 1024},
}

func measureSpeed(ctx context.Context, client *http.Client) (SpeedResult, error) {
	failures := make([]string, 0, len(speedEndpoints))
	for _, endpoint := range speedEndpoints {
		attempt, cancel := context.WithTimeout(ctx, 40*time.Second)
		result, err := measureEndpoint(attempt, client, endpoint)
		cancel()
		if err == nil {
			return result, nil
		}
		if ctx.Err() != nil {
			return SpeedResult{}, ctx.Err()
		}
		host, _ := url.Parse(endpoint.URL)
		failures = append(failures, host.Hostname()+": "+err.Error())
	}
	return SpeedResult{}, fmt.Errorf("speed download failed through selected node: %s", strings.Join(failures, "; "))
}

func measureEndpoint(ctx context.Context, client *http.Client, endpoint speedEndpoint) (SpeedResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL, nil)
	if err != nil {
		return SpeedResult{}, err
	}
	req.Header.Set("User-Agent", "hoolan-speedtest/1.0")
	req.Header.Set("Accept", "application/octet-stream, */*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return SpeedResult{}, errors.New("network or timeout error")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SpeedResult{}, fmt.Errorf("download server returned HTTP %d", resp.StatusCode)
	}
	encoding := resp.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" {
		return SpeedResult{}, errors.New("compressed speed payload")
	}
	// Never measure an HTML/JSON error or challenge page as internet throughput.
	kind := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(kind, "text/") || strings.Contains(kind, "json") || strings.Contains(kind, "xml") {
		return SpeedResult{}, errors.New("download server returned a non-binary payload")
	}
	if resp.ContentLength != -1 && resp.ContentLength != endpoint.Bytes {
		return SpeedResult{}, fmt.Errorf("unexpected speed payload length: %d", resp.ContentLength)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, endpoint.Bytes+1))
	if err != nil {
		return SpeedResult{}, errors.New("download interrupted")
	}
	if n != endpoint.Bytes {
		return SpeedResult{}, fmt.Errorf("incomplete or oversized speed payload: %d bytes", n)
	}
	seconds := time.Since(start).Seconds()
	host, _ := url.Parse(endpoint.URL)
	return SpeedResult{Bytes: n, Seconds: seconds, Mbps: float64(n) * 8 / seconds / 1_000_000, Server: host.Hostname()}, nil
}
