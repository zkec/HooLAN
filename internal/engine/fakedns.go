package engine

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const FakeDNSInbound = "dns-in"
const FakeDNSPort = 1053
const FakeDNSRange = "198.18.0.0/15"
const fakeIPServer = "hoolan-fakeip"
const secureDNSServer = "dns-remote"

// FakeDNSOptions is persisted with routing settings. Bind only a specific
// private host address; Docker users choose the host's bridge or LAN address.
type FakeDNSOptions struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
}

func NormalizeFakeDNS(o FakeDNSOptions) (FakeDNSOptions, error) {
	o.Listen = strings.TrimSpace(o.Listen)
	if o.Listen == "" {
		o.Listen = "127.0.0.1"
	}
	ip, err := netip.ParseAddr(o.Listen)
	if err != nil || !ip.Is4() || (!ip.IsPrivate() && !ip.IsLoopback()) {
		return o, fmt.Errorf("FakeDNS listen address must be a specific private or loopback IPv4 address on this host")
	}
	o.Listen = ip.String()
	return o, nil
}

func (m *Manager) ConfigureFakeDNS(o FakeDNSOptions) error {
	o, err := NormalizeFakeDNS(o)
	if err != nil {
		return err
	}
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	if o.Enabled && (m.opts.CacheFilePath == "" || m.opts.DNS != nil) {
		return fmt.Errorf("FakeDNS requires a persistent cache file and cannot be combined with a custom DNS block")
	}
	if m.dnsRelay != nil {
		if err := m.dnsRelay.Listen(net.JoinHostPort(o.Listen, strconv.Itoa(FakeDNSPort))); err != nil {
			return fmt.Errorf("DNS listener: %w", err)
		}
	}
	m.opts.FakeDNS = o
	return nil
}

func (m *Manager) buildFakeDNS(inbounds []string, rules []RouteRule) (*DNSOptions, []RouteRule, error) {
	opts, err := NormalizeFakeDNS(m.opts.FakeDNS)
	if err != nil {
		return nil, nil, err
	}
	if m.opts.CacheFilePath == "" || m.opts.DNS != nil {
		return nil, nil, fmt.Errorf("FakeDNS requires a persistent cache file and cannot be combined with a custom DNS block")
	}
	m.opts.FakeDNS = opts
	if m.opts.TProxyPort == FakeDNSPort {
		return nil, nil, fmt.Errorf("FakeDNS port conflicts with TPROXY port")
	}
	var listenerPorts []int
	for _, rule := range rules {
		for _, port := range rule.Port {
			listenerPorts = append(listenerPorts, port)
			if port == FakeDNSPort {
				return nil, nil, fmt.Errorf("FakeDNS port conflicts with a distribution listener")
			}
		}
	}
	// Bootstrap must not depend on the proxy it resolves. Literal IP + verified
	// TLS avoids poisoned bootstrap DNS; failure never falls back to plain UDP.
	doh := func(tag, detour string) map[string]any {
		server := map[string]any{"type": "https", "tag": tag, "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "tls": map[string]any{"enabled": true, "server_name": "cloudflare-dns.com"}}
		if detour != "" {
			server["detour"] = detour
		}
		return server
	}
	clients := append(append([]string(nil), inbounds...), FakeDNSInbound)
	dns := &DNSOptions{
		Servers: []any{doh(DefaultResolverTag, ""), doh(DefaultBootstrapResolverTag, ""), doh(secureDNSServer, DefaultSelector), map[string]any{"type": "fakeip", "tag": fakeIPServer, "inet4_range": FakeDNSRange}},
		Final:   DefaultResolverTag,
		Rules: []any{
			// IPv4 gateway: suppress IPv6 and HTTPS/SVCB address hints for clients.
			map[string]any{"inbound": clients, "query_type": []string{"AAAA", "HTTPS", "SVCB"}, "action": "predefined", "rcode": "NOERROR"},
			map[string]any{"inbound": clients, "query_type": []string{"A"}, "action": "route", "server": fakeIPServer, "rewrite_ttl": 60},
			map[string]any{"inbound": clients, "action": "route", "server": secureDNSServer},
		},
	}
	// Consume dedicated DNS and ordinary port 53 before sniffing or bypasses.
	// The engine recovers domains from its FakeIP store before route evaluation.
	prefix := []RouteRule{
		{Inbound: []string{FakeDNSInbound}, Action: "hijack-dns"},
		{Inbound: inbounds, Port: []int{53}, Action: "hijack-dns"},
	}
	for _, rule := range rules {
		if len(rule.Protocol) == 1 && rule.Protocol[0] == "dns" {
			rule = RouteRule{Inbound: inbounds, Protocol: []string{"dns"}, Action: "hijack-dns"}
			prefix = append(prefix, rule)
			// Resolve with the real encrypted resolver before IP/GeoIP/private rules.
			// Explicit server prevents this lookup from matching the fake A rule.
			resolve := RouteRule{Action: "resolve", Server: secureDNSServer, Strategy: "ipv4_only"}
			if ips := m.directDevicePrefixes(); len(ips) > 0 && (m.opts.TunneledDoH != "" || m.opts.DirectDNS != "") {
				prefix = append(prefix, RouteRule{SourceIPCIDR: ips, Action: "resolve", Server: directDNSTag, Strategy: "ipv4_only"})
				resolve.SourceIPCIDR, resolve.Invert = ips, true
			}
			prefix = append(prefix, resolve)
			// A recovered domain can resolve to a private listener address.
			// Recheck after resolution to preserve the self-dial loop guard.
			prefix = append(prefix, RouteRule{IPIsPrivate: true, Port: listenerPorts, Action: "reject"})
		} else {
			prefix = append(prefix, rule)
		}
	}
	return dns, prefix, nil
}
