package netfilter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
)

// DeviceNeighbors reads only the configured LAN interface. REACHABLE is a
// recent kernel confirmation; STALE/PERMANENT entries are not proof of life.
// No scans, probes or neighbour-table mutations are performed.
func (m *Manager) DeviceNeighbors(ctx context.Context) (map[string]bool, error) {
	lan, err := m.literalConfig("LAN_IF")
	if err != nil {
		return nil, err
	}
	if !interfacePattern.MatchString(lan) {
		return nil, fmt.Errorf("invalid LAN interface")
	}
	cmd := exec.CommandContext(ctx, "ip", "-j", "-4", "neigh", "show", "dev", lan)
	var stdout, stderr cappedOutput
	stdout.limit = 1024 * 1024
	stderr.limit = 4096
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("LAN presence: ip neighbour lookup failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.overflow {
		return nil, fmt.Errorf("LAN neighbour response exceeds 1 MiB")
	}
	return parseDeviceNeighbors(stdout.Bytes())
}
func parseDeviceNeighbors(raw []byte) (map[string]bool, error) {
	var entries []struct {
		Destination string   `json:"dst"`
		State       []string `json:"state"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("invalid LAN neighbour response: %w", err)
	}
	result := map[string]bool{}
	for _, entry := range entries {
		ip, err := netip.ParseAddr(entry.Destination)
		if err != nil || !ip.Is4() || !ip.IsPrivate() {
			continue
		}
		online := false
		for _, state := range entry.State {
			if strings.EqualFold(state, "reachable") {
				online = true
			}
		}
		result[ip.String()] = result[ip.String()] || online
	}
	return result, nil
}

// Drain command output without unbounded allocation or breaking its pipe.
type cappedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedOutput) String() string { return b.buffer.String() }
func (b *cappedOutput) Bytes() []byte  { return b.buffer.Bytes() }
func (b *cappedOutput) Len() int       { return b.buffer.Len() }
func (b *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.buffer.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

var _ io.Writer = (*cappedOutput)(nil)
