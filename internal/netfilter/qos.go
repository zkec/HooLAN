package netfilter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DeviceLimits uses decimal Mbps. A zero field means unlimited.
// The JSON decoder migrates the old single numeric cap to all four fields.
type DeviceLimits struct {
	ProxyUpload    float64 `json:"proxy_upload_mbps"`
	ProxyDownload  float64 `json:"proxy_download_mbps"`
	DirectUpload   float64 `json:"direct_upload_mbps"`
	DirectDownload float64 `json:"direct_download_mbps"`
}

func UniformLimits(rate float64) DeviceLimits { return DeviceLimits{rate, rate, rate, rate} }
func (l *DeviceLimits) UnmarshalJSON(raw []byte) error {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("device limits must be an object or legacy number")
	}
	if bytes.TrimSpace(raw)[0] != '{' {
		var rate float64
		if err := json.Unmarshal(raw, &rate); err != nil {
			return err
		}
		*l = UniformLimits(rate)
		return nil
	}
	type plain DeviceLimits
	var v plain
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("invalid device limits")
	}
	*l = DeviceLimits(v)
	return nil
}
func ValidateDeviceLimits(limits map[string]DeviceLimits) error {
	if len(limits) > 256 {
		return fmt.Errorf("at most 256 device limits are supported")
	}
	for ip, limits := range limits {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() || !addr.IsPrivate() || addr.String() != ip {
			return fmt.Errorf("invalid private IPv4 device address")
		}
		for _, mbps := range []float64{limits.ProxyUpload, limits.ProxyDownload, limits.DirectUpload, limits.DirectDownload} {
			if math.IsNaN(mbps) || math.IsInf(mbps, 0) || mbps < 0 || mbps > 10000 || (mbps > 0 && mbps < 0.01) {
				return fmt.Errorf("each speed limit must be 0 (unlimited) or 0.01–10000 Mbps")
			}
		}
	}
	return nil
}
func copyLimits(limits map[string]DeviceLimits) map[string]DeviceLimits {
	result := make(map[string]DeviceLimits, len(limits))
	for ip, rate := range limits {
		if rate != (DeviceLimits{}) {
			result[ip] = rate
		}
	}
	return result
}
func (m *Manager) ConfigureDeviceLimits(limits map[string]DeviceLimits) {
	m.qosMu.Lock()
	defer m.qosMu.Unlock()
	m.deviceLimits = copyLimits(limits)
}

var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func (m *Manager) literalConfig(name string) (string, error) {
	f, err := os.Open(m.confFile)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var value string
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		key, v, ok := strings.Cut(strings.TrimSpace(scan.Text()), "=")
		if !ok || strings.TrimSpace(key) != name {
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

	return value, nil
}

// RenderDeviceLimits is the default-mark renderer. The manager reads the actual
// administrator-configured mark for both standalone updates and engine startup.
func RenderDeviceLimits(lan string, limits map[string]DeviceLimits) ([]byte, error) {
	return renderDeviceLimits(lan, "0x1", limits)
}

// No conntrack or policy-routing marks are modified. The interception mark only
// distinguishes delivery to sing-box, NOT its eventual outbound. Flow sets are
// populated from Clash metadata. Unclassified flows use the stricter bucket.
func renderDeviceLimits(lan, mark string, limits map[string]DeviceLimits) ([]byte, error) {
	return renderEndpointLimits(lan, mark, limits, nil)
}
func renderEndpointLimits(lan, mark string, limits map[string]DeviceLimits, bindings []ContainerBinding) ([]byte, error) {
	if err := ValidateDeviceLimits(limits); err != nil {
		return nil, err
	}
	if !interfacePattern.MatchString(lan) {
		return nil, fmt.Errorf("invalid LAN interface")
	}
	base := 10
	if strings.HasPrefix(mark, "0x") {
		base = 16
		mark = mark[2:]
	}
	parsed, err := strconv.ParseUint(mark, base, 32)
	if err != nil || parsed == 0 {
		return nil, fmt.Errorf("invalid TPROXY_FWMARK")
	}
	mark = fmt.Sprintf("0x%x", parsed)
	interfaces := map[string]bool{lan: true}
	owners := map[string]string{}
	for _, endpoint := range bindings {
		if !interfacePattern.MatchString(endpoint.Bridge) {
			return nil, fmt.Errorf("invalid container interface")
		}
		interfaces[endpoint.Bridge] = true
		owners[endpoint.IP] = endpoint.Owner
	}
	interfaceNames := make([]string, 0, len(interfaces))
	for name := range interfaces {
		interfaceNames = append(interfaceNames, strconv.Quote(name))
	}
	sort.Strings(interfaceNames)
	interfaceMatch := strconv.Quote(lan)
	if len(interfaceNames) > 1 {
		interfaceMatch = "{ " + strings.Join(interfaceNames, ", ") + " }"
	}
	var b strings.Builder
	b.WriteString("add table inet proxy_qos\ndelete table inet proxy_qos\n")
	limits = copyLimits(limits)
	if len(limits) == 0 {
		return []byte(b.String()), nil
	}
	b.WriteString("table inet proxy_qos {\n")
	// Only limited devices reach the update rules below. Bound kernel memory
	// and retain original FakeIP tuples when Clash exposes only a domain.
	b.WriteString(" set fakedns_flows { type ipv4_addr . inet_proto . inet_service . ipv4_addr . inet_service; flags dynamic,timeout; timeout 5s; size 8192; }\n")
	for _, class := range []string{"proxy", "direct"} {
		fmt.Fprintf(&b, " set %s_flows {\n  type ipv4_addr . inet_proto . inet_service . ipv4_addr . inet_service; flags timeout; timeout 3s; size 8192;\n }\n", class)
	}
	ips := make([]string, 0, len(limits))
	for ip := range limits {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	// Multiple endpoints belonging to one container share one rate bucket.
	representatives := []string{}
	groupByOwner := map[string]int{}
	groupByIP := map[string]int{}
	for _, ip := range ips {
		owner := owners[ip]
		if owner == "" {
			owner = "device:" + ip
		}
		group, ok := groupByOwner[owner]
		if !ok {
			group = len(representatives)
			groupByOwner[owner] = group
			representatives = append(representatives, ip)
		}
		if limits[representatives[group]] != limits[ip] {
			return nil, fmt.Errorf("inconsistent container endpoint limits")
		}
		groupByIP[ip] = group
	}
	// Verdict-map dispatch avoids scanning every device for each packet.
	for _, direction := range []string{"up", "down"} {
		fmt.Fprintf(&b, " map devices_%s {\n  type ipv4_addr : verdict;\n  elements = { ", direction)
		for i, ip := range ips {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s : jump device_%d_%s", ip, groupByIP[ip], direction)
		}
		b.WriteString(" }\n }\n")
	}
	for i, ip := range representatives {
		l := limits[ip]
		for _, d := range []struct {
			name, tuple, forwarded string
			proxy, direct          float64
		}{
			{"up", "ip saddr . meta l4proto . th sport . ip daddr . th dport", "meta mark != " + mark, l.ProxyUpload, l.DirectUpload},
			{"down", "ip daddr . meta l4proto . th dport . ip saddr . th sport", "meta iif != 0", l.ProxyDownload, l.DirectDownload},
		} {
			prefix := fmt.Sprintf("device_%d_%s", i, d.name)
			// Each class has exactly one shared bucket per device and direction.
			// The unknown path jumps to that same bucket; it cannot gain a third budget.
			for _, class := range []struct {
				name string
				rate float64
			}{{"proxy", d.proxy}, {"direct", d.direct}} {
				fmt.Fprintf(&b, " chain %s_%s {\n", prefix, class.name)
				if class.rate > 0 {
					rate := int64(math.Round(class.rate * 1_000_000 / 8))
					burst := rate / 10
					if burst < 1500 {
						burst = 1500
					}
					fmt.Fprintf(&b, "  limit rate over %d bytes/second burst %d bytes counter drop comment %q\n", rate, burst, "qos-"+class.name+"-"+d.name+"-"+ip)
				}
				b.WriteString("  return\n }\n")
			}
			fallback := "proxy"
			if d.direct > 0 && (d.proxy == 0 || d.direct < d.proxy) {
				fallback = "direct"
			}
			fmt.Fprintf(&b, " chain %s {\n  %s goto %s_direct\n", prefix, d.forwarded, prefix)
			fakeAddress := "ip daddr"
			if d.name == "down" {
				fakeAddress = "ip saddr"
			}
			fmt.Fprintf(&b, "  %s 198.18.0.0/15 meta l4proto { tcp, udp } update @fakedns_flows { %s timeout 5s }\n", fakeAddress, d.tuple)
			for _, class := range []string{"direct", "proxy"} {
				fmt.Fprintf(&b, "  meta l4proto { tcp, udp } %s @%s_flows goto %s_%s\n", d.tuple, class, prefix, class)
			}
			fmt.Fprintf(&b, "  counter goto %s_%s comment %q\n }\n", prefix, fallback, "qos-unclassified-"+d.name+"-"+ip)
		}
	}
	// -149 sees the TPROXY verdict at -150, but still precedes userspace and DNAT.
	// Private destinations are not excluded: routed LAN traffic uses Direct.
	fmt.Fprintf(&b, ` chain upload {
  type filter hook prerouting priority -149; policy accept;
  iifname != %s return
  meta nfproto != ipv4 return
  fib daddr type { local, broadcast, multicast } return
  ip saddr vmap @devices_up
 }
 chain download {
  type filter hook postrouting priority 99; policy accept;
  oifname != %s return
  meta nfproto != ipv4 return
  fib saddr type local return
  ip daddr vmap @devices_down
 }
}
`, interfaceMatch, interfaceMatch)
	return []byte(b.String()), nil
}
func (m *Manager) qosFile(limits map[string]DeviceLimits) (string, func(), error) {
	lan, err := m.literalConfig("LAN_IF")
	if err != nil {
		return "", func() {}, err
	}
	mark, err := m.literalConfig("TPROXY_FWMARK")
	if err != nil {
		return "", func() {}, err
	}
	raw, err := renderEndpointLimits(lan, mark, limits, m.containerBindings)
	if err != nil {
		return "", func() {}, err
	}
	f, err := os.CreateTemp("", "hoolan-qos-*.nft")
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
func (m *Manager) ApplyDeviceLimits(ctx context.Context, limits map[string]DeviceLimits) error {
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
	m.qosFlowsPresent = false
	return nil
}
