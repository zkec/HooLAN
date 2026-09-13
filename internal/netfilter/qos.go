package netfilter

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// Limits are decimal megabits/second, independently enforced in each direction.
// nft byte rates use explicit bytes to avoid MB/MiB conversion ambiguities.
func ValidateDeviceLimits(limits map[string]float64) error {
	if len(limits) > 256 {
		return fmt.Errorf("at most 256 device limits are supported")
	}
	for ip, mbps := range limits {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() || !addr.IsPrivate() || addr.String() != ip {
			return fmt.Errorf("invalid private IPv4 device address")
		}
		if math.IsNaN(mbps) || math.IsInf(mbps, 0) || mbps < 0 || mbps > 10000 || (mbps > 0 && mbps < 0.01) {
			return fmt.Errorf("speed limit must be 0 (unlimited) or 0.01–10000 Mbps")
		}
	}
	return nil
}
func copyLimits(limits map[string]float64) map[string]float64 {
	result := make(map[string]float64, len(limits))
	for ip, rate := range limits {
		if rate > 0 {
			result[ip] = rate
		}
	}
	return result
}
func (m *Manager) ConfigureDeviceLimits(limits map[string]float64) {
	m.qosMu.Lock()
	defer m.qosMu.Unlock()
	m.deviceLimits = copyLimits(limits)
}

var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func (m *Manager) lanInterface() (string, error) {
	f, err := os.Open(m.confFile)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var value string
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		key, v, ok := strings.Cut(strings.TrimSpace(scan.Text()), "=")
		if !ok || strings.TrimSpace(key) != "LAN_IF" {
			continue
		}
		value = strings.TrimSpace(v)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
	}
	if err := scan.Err(); err != nil {
		return "", err
	}
	if !interfacePattern.MatchString(value) {
		return "", fmt.Errorf("LAN_IF must be a literal interface name")
	}
	return value, nil
}

// RenderDeviceLimits owns a separate table so proxy OFF preserves routing and
// limits. Upload policing precedes TPROXY; postrouting sees both transparent
// replies generated locally and ordinary forwarded downloads, before SNAT.
func RenderDeviceLimits(lan string, limits map[string]float64) ([]byte, error) {
	if err := ValidateDeviceLimits(limits); err != nil {
		return nil, err
	}
	if !interfacePattern.MatchString(lan) {
		return nil, fmt.Errorf("invalid LAN interface")
	}
	var b strings.Builder
	b.WriteString("add table inet proxy_qos\ndelete table inet proxy_qos\n")
	if len(copyLimits(limits)) == 0 {
		return []byte(b.String()), nil
	}
	b.WriteString(`table inet proxy_qos {
 set local_networks {
  type ipv4_addr; flags interval;
  elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
 }
 chain upload {
  type filter hook prerouting priority -151; policy accept;
`)
	fmt.Fprintf(&b, "  iifname != %q return\n", lan)
	b.WriteString("  meta nfproto != ipv4 return\n  fib daddr type { local, broadcast, multicast } return\n  ip daddr @local_networks return\n")
	ips := make([]string, 0, len(limits))
	for ip := range limits {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	appendRules := func(field, direction string) {
		for _, ip := range ips {
			if limits[ip] == 0 {
				continue
			}
			rate := int64(math.Round(limits[ip] * 1_000_000 / 8))
			burst := rate / 10
			if burst < 1500 {
				burst = 1500
			}
			fmt.Fprintf(&b, "  ip %s %s limit rate over %d bytes/second burst %d bytes counter drop comment %q\n", field, ip, rate, burst, "qos-"+direction+"-"+ip)
		}
	}
	appendRules("saddr", "upload")
	b.WriteString(" }\n chain download {\n  type filter hook postrouting priority 99; policy accept;\n")
	fmt.Fprintf(&b, "  oifname != %q return\n", lan)
	b.WriteString("  meta nfproto != ipv4 return\n  ip saddr @local_networks return\n")
	appendRules("daddr", "download")
	b.WriteString(" }\n}\n")
	return []byte(b.String()), nil
}
func (m *Manager) qosFile(limits map[string]float64) (string, func(), error) {
	lan, err := m.lanInterface()
	if err != nil {
		return "", func() {}, err
	}
	raw, err := RenderDeviceLimits(lan, limits)
	if err != nil {
		return "", func() {}, err
	}
	f, err := os.CreateTemp("", "proxy-manager-qos-*.nft")
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

// ApplyDeviceLimits submits a complete replacement in one nft transaction.
// A rejected batch leaves the old table intact; no engine restart is needed.
func (m *Manager) ApplyDeviceLimits(ctx context.Context, limits map[string]float64) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	m.qosMu.Lock()
	defer m.qosMu.Unlock()
	path, cleanup, err := m.qosFile(limits)
	if err != nil {
		return err
	}
	defer cleanup()
	for _, args := range [][]string{{"--check", "-f", path}, {"-f", path}} {
		cmd := exec.CommandContext(ctx, "nft", args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("device limits: nft failed: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
	}
	m.deviceLimits = copyLimits(limits)
	return nil
}
