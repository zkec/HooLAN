package engine

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"

	"hoolan/internal/dnsrelay"
)

// The public listener stays at 1053. Only sing-box owns loopback 1054.
const ManagedDNSPort = 1054

// ConfigureDNSProxy follows control-plane intent, not process liveness. A
// crashed/restarting engine must not silently move proxied DNS onto the ISP.
func (m *Manager) ConfigureDNSProxy(enabled bool) {
	m.settingsMu.Lock()
	m.dnsProxyRequired = enabled
	m.settingsMu.Unlock()
}

func (m *Manager) dnsPolicy(client net.IP) dnsrelay.Policy {
	m.settingsMu.RLock()
	direct := m.opts.DirectDNS
	directDevice := m.deviceRoutes[client.String()] == DefaultDirect
	proxyRequired := m.dnsProxyRequired
	m.settingsMu.RUnlock()
	if proxyRequired && !directDevice {
		return dnsrelay.Policy{Primary: net.JoinHostPort("127.0.0.1", strconv.Itoa(ManagedDNSPort))}
	}
	if direct == "" {
		direct = DefaultDirectDNS
	}
	if a, err := netip.ParseAddr(direct); err == nil {
		direct = net.JoinHostPort(a.String(), "53")
	}
	return dnsrelay.Policy{Direct: direct}
}

func (m *Manager) dnsBindAddress() string {
	if m.opts.ManagedDNS {
		return "127.0.0.1"
	}
	o, _ := NormalizeFakeDNS(m.opts.FakeDNS)
	return o.Listen
}
func (m *Manager) dnsBindPort() int {
	if m.opts.ManagedDNS {
		return ManagedDNSPort
	}
	return FakeDNSPort
}
func (m *Manager) directDevicePrefixes() []string {
	var ips []string
	for ip, route := range m.deviceRoutes {
		if route == DefaultDirect {
			if a, err := netip.ParseAddr(ip); err == nil {
				a = a.Unmap()
				ips = append(ips, netip.PrefixFrom(a, a.BitLen()).String())
			}
		}
	}
	sort.Strings(ips)
	return ips
}
func (m *Manager) StartDNS() error {
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	if !m.opts.ManagedDNS || m.dnsRelay != nil {
		return nil
	}
	o, err := NormalizeFakeDNS(m.opts.FakeDNS)
	if err != nil {
		return err
	}
	relay := dnsrelay.New(m.dnsPolicy)
	if err := relay.Listen(net.JoinHostPort(o.Listen, strconv.Itoa(FakeDNSPort))); err != nil {
		return fmt.Errorf("listen on DNS port %d: %w", FakeDNSPort, err)
	}
	m.dnsRelay = relay
	return nil
}
func (m *Manager) CloseDNS() {
	m.settingsMu.Lock()
	relay := m.dnsRelay
	m.dnsRelay = nil
	m.settingsMu.Unlock()
	if relay != nil {
		relay.Close()
	}
}
