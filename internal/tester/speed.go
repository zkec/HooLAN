package tester

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"proxy-manager/internal/subscription"
	"time"
)

const SpeedBytes int64 = 15_000_000
const SpeedURL = "https://speed.cloudflare.com/__down?bytes=15000000"

type SpeedResult struct {
	Bytes   int64   `json:"bytes"`
	Seconds float64 `json:"seconds"`
	Mbps    float64 `json:"mbps"`
}

// TestSpeed uses an isolated engine and the selected node's entire detour path.
// Engine startup is excluded; download timing includes remote DNS/TLS/TTFB.
func (t *Tester) TestSpeed(ctx context.Context, target subscription.Node, inventory []subscription.Node) (SpeedResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := subscription.ValidateChains(inventory); err != nil {
		return SpeedResult{}, err
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
		return SpeedResult{}, err
	}
	path, cleanup, err := t.writeProbeConfig(target, deps, port)
	if err != nil {
		return SpeedResult{}, err
	}
	defer cleanup()
	proc, err := t.startEngine(ctx, path)
	if err != nil {
		return SpeedResult{}, err
	}
	defer proc.stop()
	socks := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitForListener(ctx, socks); err != nil {
		return SpeedResult{}, fmt.Errorf("speed test engine did not start: %w", err)
	}
	proxy, _ := url.Parse("socks5://" + socks)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableCompression: true, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return measureSpeed(ctx, client)
}
func measureSpeed(ctx context.Context, client *http.Client) (SpeedResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, SpeedURL, nil)
	if err != nil {
		return SpeedResult{}, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return SpeedResult{}, fmt.Errorf("speed download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" {
		return SpeedResult{}, fmt.Errorf("unexpected speed response (HTTP %d)", resp.StatusCode)
	}
	if resp.ContentLength != -1 && resp.ContentLength != SpeedBytes {
		return SpeedResult{}, fmt.Errorf("unexpected speed payload length: %d", resp.ContentLength)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, SpeedBytes+1))
	if err != nil {
		return SpeedResult{}, err
	}
	if n != SpeedBytes {
		return SpeedResult{}, fmt.Errorf("incomplete or oversized speed payload: %d bytes", n)
	}
	seconds := time.Since(start).Seconds()
	return SpeedResult{Bytes: n, Seconds: seconds, Mbps: float64(n) * 8 / seconds / 1_000_000}, nil
}
