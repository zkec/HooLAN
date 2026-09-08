package api

// Clash API client: the live control channel into a running sing-box.
//
// Why this exists at all: changing the active node by regenerating config and
// restarting the engine would drop every connection on the LAN and cost seconds
// of downtime. The Clash API switches a selector in place. See
// engine.ClashAPIOptions for the config side.
//
// Only the two calls this project needs are implemented (read a group, set a
// group's pick) plus a readiness probe. This is deliberately not a general Clash
// client.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrClashUnavailable means the engine's control API could not be reached. It is
// distinct from a rejected request: unavailable usually means the engine is not
// running (or was built without the with_clash_api tag), which callers report as
// "selection saved but not applied" rather than as a hard failure.
var ErrClashUnavailable = errors.New("clash api: unavailable")

// ClashClient talks to one sing-box Clash API.
type ClashClient struct {
	base   string
	secret string
	http   *http.Client
}

// NewClashClient builds a client for a listen address such as "127.0.0.1:9090".
// Returns nil when addr is empty, so callers can treat "no control API
// configured" as a nil client without a separate flag.
func NewClashClient(addr, secret string) *ClashClient {
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port; assume a bare host and let the request fail loudly.
		host, port = addr, ""
	}
	// A wildcard listen address is not dialable as a destination on every stack,
	// so target loopback instead: the API always answers there too.
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	hostport := host
	if port != "" {
		hostport = net.JoinHostPort(host, port)
	}
	return &ClashClient{
		base:   "http://" + hostport,
		secret: secret,
		// Short timeout: this is a loopback call to a local process. A slow
		// response means the engine is wedged, and the HTTP handler waiting on
		// it should not hang for the client's benefit.
		http: &http.Client{Timeout: 5 * time.Second},
	}
}

// ClashProxy is the subset of a Clash /proxies/{name} response this code uses.
type ClashProxy struct {
	Type string `json:"type"` // "Selector", "URLTest", "VLESS", ...
	Name string `json:"name"`
	// Now is the currently selected member, for group types.
	Now string `json:"now"`
	// All lists selectable members, for group types.
	All []string `json:"all"`
}

// Group reads one outbound group's state.
func (c *ClashClient) Group(ctx context.Context, name string) (ClashProxy, error) {
	var out ClashProxy
	// PathEscape, not raw concatenation: sing-box tags are provider-controlled
	// display names and routinely contain spaces, slashes and emoji.
	body, err := c.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(name), nil)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("clash api: decode group %q: %w", name, err)
	}
	return out, nil
}

// Select points a selector group at one of its members.
func (c *ClashClient) Select(ctx context.Context, group, member string) error {
	payload, err := json.Marshal(map[string]string{"name": member})
	if err != nil {
		return fmt.Errorf("clash api: encode selection: %w", err)
	}
	_, err = c.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), payload)
	if err != nil {
		return fmt.Errorf("clash api: select %q in %q: %w", member, group, err)
	}
	return nil
}

// WaitReady polls until the control API answers or ctx expires. Engine startup
// is not instant, and a Select fired immediately after Start would fail with
// connection refused.
func (c *ClashClient) WaitReady(ctx context.Context, group string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if _, err := c.Group(ctx, group); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("clash api: not ready: %w (last error: %v)", ctx.Err(), last)
		case <-ticker.C:
		}
	}
}

func (c *ClashClient) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, fmt.Errorf("clash api: build request: %w", err)
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// Transport-level failure: engine down, wrong port, or no with_clash_api.
		return nil, fmt.Errorf("%w: %v", ErrClashUnavailable, err)
	}
	defer resp.Body.Close()

	// Cap the read: a wrong port could point at something that streams forever.
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("clash api: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("clash api: %s %s: status %d: %s",
			method, path, resp.StatusCode, bytes.TrimSpace(buf))
	}
	return buf, nil
}
