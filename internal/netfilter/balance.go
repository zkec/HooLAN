package netfilter

import (
	"fmt"
	"os"
	"hoolan/internal/engine"
	"regexp"
	"sort"
	"strings"
)

func (m *Manager) ConfigureDistribution(groups []engine.DistributionGroup, selected string, routes map[string]string) {
	m.qosMu.Lock()
	defer m.qosMu.Unlock()
	m.distribution = make([]engine.DistributionGroup, len(groups))
	for i, g := range groups {
		m.distribution[i] = g
		m.distribution[i].Members = append([]engine.DistributionMember(nil), g.Members...)
	}
	m.defaultGroup = selected
	m.deviceRoutes = make(map[string]string, len(routes))
	for ip, id := range routes {
		m.deviceRoutes[ip] = id
	}
}

var groupIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// RenderDistribution lives inside proxy_tproxy, after private/local bypass and
// before the ordinary TPROXY rules. Hash the complete tuple on every packet:
// established TCP and UDP keep their lane without repurposing conntrack marks.
func RenderDistribution(groups []engine.DistributionGroup, selected string, routes map[string]string) ([]byte, error) {
	var b strings.Builder
	names := map[string]string{}
	ports := map[int]bool{}
	for i, group := range groups {
		if !groupIDPattern.MatchString(group.ID) || len(group.Members) < 2 || len(group.Members) > 32 {
			return nil, fmt.Errorf("invalid distribution group")
		}
		name := fmt.Sprintf("balance_g%d", i)
		names[group.ID] = name
		for j, member := range group.Members {
			if member.Port < 1 || member.Port > 65535 || ports[member.Port] {
				return nil, fmt.Errorf("invalid or duplicate distribution port")
			}
			ports[member.Port] = true
			fmt.Fprintf(&b, "chain %s_m%d {\n", name, j)
			fmt.Fprintf(&b, " meta l4proto tcp tproxy ip to :%d meta mark set {{TPROXY_FWMARK}} counter accept\n", member.Port)
			fmt.Fprintf(&b, " meta l4proto udp tproxy ip to :%d meta mark set {{TPROXY_FWMARK}} counter accept\n", member.Port)
			b.WriteString(" counter drop\n}\n") // never send a failed handoff directly to WAN
		}
		fmt.Fprintf(&b, "chain %s {\n meta l4proto { tcp, udp } jhash ip saddr . ip daddr . meta l4proto . th sport . th dport mod %d seed 0x%s vmap { ", name, len(group.Members), group.ID[:8])
		for j := range group.Members {
			if j > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%d : jump %s_m%d", j, name, j)
		}
		b.WriteString(" }\n}\n")
	}
	b.WriteString("chain balance_dispatch {\n meta l4proto != { tcp, udp } return\n")
	ips := make([]string, 0, len(routes))
	for ip := range routes {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		if err := ValidateDeviceLimits(map[string]DeviceLimits{ip: {}}); err != nil {
			return nil, err
		}
		if routes[ip] == "" {
			continue
		}
		if name := names[routes[ip]]; name != "" {
			fmt.Fprintf(&b, " ip saddr %s jump %s\n", ip, name)
		} else {
			fmt.Fprintf(&b, " ip saddr %s return\n", ip)
		}
	}
	if name := names[selected]; name != "" {
		fmt.Fprintf(&b, " jump %s\n", name)
	}
	b.WriteString("}\n")
	return []byte(b.String()), nil
}
func (m *Manager) distributionFile() (string, func(), error) {
	raw, err := RenderDistribution(m.distribution, m.defaultGroup, m.deviceRoutes)
	if err != nil {
		return "", func() {}, err
	}
	f, err := os.CreateTemp("", "hoolan-balance-*.nft")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { os.Remove(f.Name()) }
	_, err = f.Write(raw)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return f.Name(), cleanup, nil
}
