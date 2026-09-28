package engine

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const DefaultTunneledDoH = "https://1.1.1.1/dns-query"
const DefaultDirectDNS = "192.168.3.1"
const directDNSTag = "dns-direct"

// NormalizeSplitDNS supplies upgrade defaults without using the host resolver:
// the latter may point to AdGuard, which would create a recursive DNS loop.
func NormalizeSplitDNS(doh, direct string) (string, string, error) {
	doh = strings.TrimSpace(doh)
	if doh == "" {
		doh = DefaultTunneledDoH
	}
	u, err := url.Parse(doh)
	if err != nil || len(doh) > 4096 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", "", fmt.Errorf("tunneled DoH must be an HTTPS URL without credentials or a fragment")
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("invalid DoH port")
		}
	}
	if strings.TrimSpace(direct) == "" {
		direct = DefaultDirectDNS
	}
	direct, err = NormalizeDNSServer(direct)
	if err != nil {
		return "", "", err
	}
	return doh, direct, nil
}

// ValidateDNSListener rejects a direct upstream that would recurse into itself.
func ValidateDNSListener(direct, listen string) error {
	server, err := dnsServerOptions(direct)
	if err != nil {
		return err
	}
	if (server["server"] == listen && server["server_port"] == FakeDNSPort) || (server["server"] == "127.0.0.1" && server["server_port"] == ManagedDNSPort) {
		return fmt.Errorf("direct DNS cannot point back to the sing-box DNS listener")
	}
	return nil
}

func (m *Manager) ConfigureSplitDNS(doh, direct string) error {
	doh, direct, err := NormalizeSplitDNS(doh, direct)
	if err != nil {
		return err
	}
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	if m.opts.DNS != nil {
		return fmt.Errorf("split DNS cannot be combined with a custom DNS block")
	}
	m.opts.TunneledDoH, m.opts.DirectDNS = doh, direct
	return nil
}

// DNSListener lets the service verify both sockets before enabling interception.
func (m *Manager) DNSListener() (string, int) {
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	if m.opts.TunneledDoH == "" && m.opts.DirectDNS == "" && !m.opts.FakeDNS.Enabled {
		return "", 0
	}
	return m.dnsBindAddress(), m.dnsBindPort()
}

// buildSplitDNS is called after applyRulePolicy, before per-device rules.
// DNS received from AdGuard no longer carries the original device identity.
func (m *Manager) buildSplitDNS(route *RouteOptions, clients []string) (*DNSOptions, error) {
	doh, direct, err := NormalizeSplitDNS(m.opts.TunneledDoH, m.opts.DirectDNS)
	if err != nil {
		return nil, err
	}
	o, err := NormalizeFakeDNS(m.opts.FakeDNS)
	if err != nil {
		return nil, err
	}
	for _, r := range route.Rules {
		for _, port := range r.Port {
			if port == FakeDNSPort {
				return nil, fmt.Errorf("DNS port 1053 conflicts with a TPROXY listener")
			}
		}
	}
	udp, err := dnsServerOptions(direct)
	if err != nil {
		return nil, err
	}
	if err := ValidateDNSListener(direct, o.Listen); err != nil {
		return nil, err
	}
	udp["tag"] = directDNSTag
	u, _ := url.Parse(doh)
	port := 443
	if u.Port() != "" {
		port, _ = strconv.Atoi(u.Port())
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/dns-query"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	remote := map[string]any{"type": "https", "tag": secureDNSServer, "server": u.Hostname(), "server_port": port, "path": path, "tls": map[string]any{"enabled": true, "server_name": u.Hostname()}, "detour": DefaultSelector}
	if _, e := netip.ParseAddr(u.Hostname()); e != nil {
		remote["domain_resolver"] = directDNSTag
	}
	dns := &DNSOptions{Servers: []any{udp, remote}, Final: secureDNSServer}
	// Only proxy endpoint / rule-set bootstrap uses these direct aliases. Client
	// requests always enter the split policy, never the system's /etc/resolv.conf.
	for _, tag := range []string{DefaultResolverTag, DefaultBootstrapResolverTag} {
		copy := map[string]any{}
		for k, v := range udp {
			copy[k] = v
		}
		copy["tag"] = tag
		dns.Servers = append(dns.Servers, copy)
	}
	route.DefaultDomainResolver = &DomainResolverOptions{Server: DefaultResolverTag}
	clients = append(append([]string{}, clients...), FakeDNSInbound)
	if ips := m.directDevicePrefixes(); len(ips) > 0 {
		dns.Rules = append(dns.Rules, map[string]any{"source_ip_cidr": ips, "action": "route", "server": directDNSTag})
	}
	if o.Enabled {
		dns.Servers = append(dns.Servers, map[string]any{"type": "fakeip", "tag": fakeIPServer, "inet4_range": FakeDNSRange})
		dns.Rules = append(dns.Rules, map[string]any{"inbound": clients, "query_type": []string{"AAAA", "HTTPS", "SVCB"}, "action": "predefined", "rcode": "NOERROR"})
	}
	clone := func(r map[string]any) map[string]any {
		c := map[string]any{}
		for k, v := range r {
			c[k] = v
		}
		return c
	}
	decision := func(match map[string]any, action string, evaluated bool) {
		r := clone(match)
		switch action {
		case "reject":
			r["action"] = "reject"
			r["no_drop"] = true
		case DefaultDirect:
			r["action"] = "route"
			r["server"] = directDNSTag
		default:
			if o.Enabled {
				f := clone(match)
				f["inbound"] = clients
				f["query_type"] = []string{"A"}
				f["action"] = "route"
				f["server"] = fakeIPServer
				f["rewrite_ttl"] = 60
				dns.Rules = append(dns.Rules, f)
			}
			if evaluated {
				r["action"] = "respond"
				r["match_response"] = true
			} else {
				r["action"] = "route"
				r["server"] = secureDNSServer
			}
		}
		dns.Rules = append(dns.Rules, r)
	}
	// Local names and reverse lookups remain usable without the proxy resolver.
	decision(map[string]any{"domain_suffix": []string{"lan", "local", "home.arpa", "in-addr.arpa", "ip6.arpa"}}, DefaultDirect, false)
	evaluated := false
	evaluate := func() {
		if !evaluated {
			dns.Rules = append(dns.Rules, map[string]any{"action": "evaluate", "server": secureDNSServer})
			evaluated = true
			decision(map[string]any{"match_response": true, "ip_is_private": true}, DefaultDirect, true)
		}
	}
	for _, r := range route.Rules {
		if len(r.Inbound) > 0 || len(r.Port) > 0 || len(r.Protocol) > 0 || r.IPIsPrivate {
			continue
		}
		match := map[string]any{}
		switch {
		case len(r.Domain) > 0:
			match["domain"] = r.Domain
		case len(r.DomainSuffix) > 0:
			match["domain_suffix"] = r.DomainSuffix
		case len(r.IPCIDR) > 0:
			evaluate()
			match["ip_cidr"] = r.IPCIDR
			match["match_response"] = true
		case len(r.RuleSet) > 0:
			// Only built-in geosite sets are known to be domain-only. Custom sets
			// may contain address criteria and must see a securely evaluated answer.
			if r.RuleSet[0] != TagGeositeIR && r.RuleSet[0] != TagGeositeAdsIR {
				evaluate()
				match["match_response"] = true
			}
			match["rule_set"] = r.RuleSet
		default:
			continue
		}
		action := r.Outbound
		if r.Action == "reject" {
			action = "reject"
		}
		decision(match, action, evaluated)
	}
	decision(map[string]any{}, DefaultSelector, evaluated)
	return dns, nil
}
