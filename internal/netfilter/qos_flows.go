package netfilter

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// QoSFlow identifies the ORIGINAL LAN socket, never the Pi's outbound socket.
// The same tuple is matched in reverse for transparent return packets. These
// short-lived observations intentionally do not overwrite conntrack marks.
type QoSFlow struct {
	SourceIP, DestinationIP     string
	Network                     string
	SourcePort, DestinationPort uint16
	Direct                      bool
}

func renderQoSFlows(flows []QoSFlow, limits map[string]DeviceLimits) ([]byte, error) {
	if len(flows) > 8192 {
		return nil, fmt.Errorf("QoS classification exceeds 8192 connections; using conservative limits until the next sample")
	}
	classes := map[string]map[string]bool{"proxy": {}, "direct": {}}
	for _, f := range flows {
		src, err := netip.ParseAddr(f.SourceIP)
		dst, destErr := netip.ParseAddr(f.DestinationIP)
		if err != nil || !src.Is4() || !src.IsPrivate() || destErr != nil || !dst.Is4() || dst.IsUnspecified() || dst.IsMulticast() || f.SourcePort == 0 || f.DestinationPort == 0 || (f.Network != "tcp" && f.Network != "udp") {
			return nil, fmt.Errorf("invalid QoS connection tuple")
		}
		if limits[src.String()] == (DeviceLimits{}) {
			continue
		}
		key := fmt.Sprintf("%s . %s . %d . %s . %d", src, f.Network, f.SourcePort, dst, f.DestinationPort)
		class := "proxy"
		if f.Direct {
			class = "direct"
		}
		classes[class][key] = true
	}
	// Conflicting observations of the same tuple (e.g. UDP trackers) stay unknown.
	for key := range classes["proxy"] {
		if classes["direct"][key] {
			delete(classes["proxy"], key)
			delete(classes["direct"], key)
		}
	}
	var b strings.Builder
	for _, class := range []string{"proxy", "direct"} {
		fmt.Fprintf(&b, "flush set inet proxy_qos %s_flows\n", class)
		keys := make([]string, 0, len(classes[class]))
		for key := range classes[class] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) != 0 {
			fmt.Fprintf(&b, "add element inet proxy_qos %s_flows { %s }\n", class, strings.Join(keys, ", "))
		}
	}
	return []byte(b.String()), nil
}

// SyncQoSFlows only replaces set elements, in one transaction. It NEVER resets
// rate buckets. Expiring observations bound the effect of a failed sampler or
// a reused TCP/UDP tuple. Missing metadata continues through the stricter cap.
func (m *Manager) SyncQoSFlows(ctx context.Context, flows []QoSFlow) error {
	m.qosMu.Lock()
	defer m.qosMu.Unlock()
	if len(m.deviceLimits) == 0 {
		return nil
	}
	if len(flows) == 0 && !m.qosFlowsPresent {
		return nil
	}
	raw, err := renderQoSFlows(flows, m.deviceLimits)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = bytes.NewReader(raw)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("QoS classification: nft failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	m.qosFlowsPresent = len(flows) != 0
	return nil
}
