package engine

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// NormalizeDNSServer validates the browser setting without resolving hostnames
// or allowing bootstrap dependencies on the very resolver being configured.
func NormalizeDNSServer(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	host, port := value, ""
	if _, err := netip.ParseAddr(host); err != nil {
		var splitErr error
		host, port, splitErr = net.SplitHostPort(value)
		if splitErr != nil {
			return "", fmt.Errorf("DNS server must be an IP address or IP:port (IPv6 with a port uses [address]:port)")
		}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" {
		return "", fmt.Errorf("DNS server must be a unicast IP address")
	}
	if port == "" {
		return addr.String(), nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("DNS server port must be between 1 and 65535")
	}
	return net.JoinHostPort(addr.String(), strconv.Itoa(n)), nil
}

func dnsServerOptions(value string) (map[string]any, error) {
	value, err := NormalizeDNSServer(value)
	if err != nil {
		return nil, err
	}
	if value == "" {
		return map[string]any{"type": "local", "tag": DefaultResolverTag}, nil
	}
	host, port := value, 53
	if _, err := netip.ParseAddr(value); err != nil {
		var p string
		host, p, _ = net.SplitHostPort(value)
		port, _ = strconv.Atoi(p)
	}
	return map[string]any{"type": "udp", "tag": DefaultResolverTag, "server": host, "server_port": port}, nil
}

// ConfigureRouting changes the next rendered configuration. The service owns
// firewall teardown, engine restart and listener checks when applying it live.
func (m *Manager) ConfigureRouting(dnsServer string, iranBypass bool) error {
	value, err := NormalizeDNSServer(dnsServer)
	if err != nil {
		return err
	}
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	m.opts.DNSServer = value
	m.opts.DisableIranBypass = !iranBypass
	return nil
}
