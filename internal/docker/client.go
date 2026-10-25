// Package docker reads Docker Engine inventory over a local Unix socket.
// It never starts, stops, or modifies containers or networks.
package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Binding struct {
	IP      string `json:"ip"`
	Bridge  string `json:"bridge"`
	Network string `json:"network"`
}
type Container struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Image     string    `json:"image"`
	State     string    `json:"state"`
	Status    string    `json:"status"`
	Mode      string    `json:"network_mode"`
	Bindings  []Binding `json:"bindings"`
	Supported bool      `json:"supported"`
	Reason    string    `json:"reason,omitempty"`
}
type Client struct {
	http         *http.Client
	bridgeExists func(string) bool
}

func New(socket string) (*Client, error) {
	if socket == "" {
		return nil, nil
	}
	if !filepath.IsAbs(socket) {
		return nil, fmt.Errorf("Docker socket must be an absolute local path")
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
	}
	return &Client{bridgeExists: func(name string) bool { _, err := net.InterfaceByName(name); return err == nil }, http: &http.Client{Transport: tr, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}
func (c *Client) Close() {
	if c != nil {
		c.http.CloseIdleConnections()
	}
}
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Docker inventory unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Docker inventory returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024+1))
	if err != nil {
		return err
	}
	if len(raw) > 8*1024*1024 {
		return fmt.Errorf("Docker inventory response exceeds 8 MiB")
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("invalid Docker inventory response: %w", err)
	}
	return nil
}

var ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
var idPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type network struct {
	ID                  string `json:"Id"`
	Name, Driver, Scope string
	Options             map[string]string
}
type endpoint struct {
	NetworkID         string
	IPAddress         string
	GlobalIPv6Address string
}
type container struct {
	ID                   string `json:"Id"`
	Names                []string
	Image, State, Status string
	Labels               map[string]string
	HostConfig           struct{ NetworkMode string }
	NetworkSettings      struct{ Networks map[string]endpoint }
}

func (c *Client) List(ctx context.Context) ([]Container, error) {
	var info struct{ SecurityOptions []string }
	if err := c.get(ctx, "/info", &info); err != nil {
		return nil, err
	}
	rootless := false
	for _, o := range info.SecurityOptions {
		if strings.Contains(o, "rootless") {
			rootless = true
		}
	}
	var networks []network
	if err := c.get(ctx, "/networks", &networks); err != nil {
		return nil, err
	}
	var items []container
	if err := c.get(ctx, "/containers/json?all=1", &items); err != nil {
		return nil, err
	}
	if len(items) > 1024 || len(networks) > 1024 {
		return nil, fmt.Errorf("Docker inventory exceeds 1024 containers/networks")
	}
	byID := map[string]network{}
	for _, n := range networks {
		byID[n.ID] = n
	}
	result := make([]Container, 0, len(items))
	keys := map[string]int{}
	owners := map[string][]int{}
	bridges := map[string]bool{}
	checkedBridges := map[string]bool{}
	for _, raw := range items {
		if !idPattern.MatchString(raw.ID) {
			return nil, fmt.Errorf("invalid Docker container ID")
		}
		name := raw.ID[:12]
		if len(raw.Names) > 0 {
			name = strings.TrimPrefix(raw.Names[0], "/")
		}
		identity := "name\x00" + name
		if p, s, n := raw.Labels["com.docker.compose.project"], raw.Labels["com.docker.compose.service"], raw.Labels["com.docker.compose.container-number"]; p != "" && s != "" && n != "" {
			identity = "compose\x00" + p + "\x00" + s + "\x00" + n
		}
		digest := sha256.Sum256([]byte(identity))
		item := Container{ID: raw.ID, Key: hex.EncodeToString(digest[:]), Name: name, Image: raw.Image, State: raw.State, Status: raw.Status, Mode: raw.HostConfig.NetworkMode, Bindings: []Binding{}}
		if rootless {
			item.Reason = "Rootless Docker does not expose an interceptable host bridge"
		}
		if raw.State != "running" {
			item.Reason = "Container is not running"
		}
		if item.Mode == "host" || item.Mode == "none" || strings.HasPrefix(item.Mode, "container:") {
			item.Reason = "Host, shared and isolated network modes cannot be controlled separately"
		}
		for name, ep := range raw.NetworkSettings.Networks {
			n, ok := byID[ep.NetworkID]
			if !ok || n.Driver != "bridge" || n.Scope != "local" {
				item.Reason = "Only local IPv4 bridge networks are supported"
				continue
			}
			if ep.GlobalIPv6Address != "" {
				item.Reason = "Disable container IPv6 to prevent traffic bypassing IPv4 controls"
			}
			ip, err := netip.ParseAddr(ep.IPAddress)
			if err != nil || !ip.Is4() || !ip.IsPrivate() {
				if raw.State == "running" {
					item.Reason = "Container needs a private bridge IPv4 address"
				}
				continue
			}
			bridge := n.Options["com.docker.network.bridge.name"]
			if bridge == "" {
				if n.Name == "bridge" {
					bridge = "docker0"
				} else if len(n.ID) >= 12 {
					bridge = "br-" + n.ID[:12]
				}
			}
			if !ifacePattern.MatchString(bridge) || bridge == "lo" {
				item.Reason = "Invalid Docker bridge interface"
				continue
			}
			// Rootless or remote daemons can report bridge names absent on this host.
			if !checkedBridges[bridge] {
				bridges[bridge] = c.bridgeExists(bridge)
				checkedBridges[bridge] = true
			}
			if !bridges[bridge] {
				item.Reason = "Docker bridge is not present in the gateway's network namespace"
			}
			item.Bindings = append(item.Bindings, Binding{IP: ip.String(), Bridge: bridge, Network: name})
		}
		if len(item.Bindings) == 0 && item.Reason == "" {
			item.Reason = "No bridge IPv4 endpoint available"
		}
		sort.Slice(item.Bindings, func(i, j int) bool {
			if item.Bindings[i].IP == item.Bindings[j].IP {
				return item.Bindings[i].Bridge < item.Bindings[j].Bridge
			}
			return item.Bindings[i].IP < item.Bindings[j].IP
		})
		if prior, ok := keys[item.Key]; ok {
			result[prior].Reason = "Ambiguous container identity"
			item.Reason = "Ambiguous container identity"
		}
		keys[item.Key] = len(result)
		for _, b := range item.Bindings {
			owners[b.IP] = append(owners[b.IP], len(result))
		}
		result = append(result, item)
	}
	for _, indexes := range owners {
		unique := map[int]bool{}
		for _, i := range indexes {
			unique[i] = true
		}
		if len(unique) > 1 {
			for i := range unique {
				result[i].Reason = "Bridge IP is shared by multiple containers"
			}
		}
	}

	for i := range result {
		result[i].Supported = result[i].Reason == ""
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}
