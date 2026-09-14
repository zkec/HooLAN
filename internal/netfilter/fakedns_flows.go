package netfilter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
)

// Read only when a limited FakeDNS connection lacks Clash destinationIP.
// The kernel set contains at most 8192 five-second observations. Do not query
// DNS again: SNI may differ from the queried name and would produce a new IP.
func readFakeDNSFlows(ctx context.Context) ([]QoSFlow, error) {
	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", "proxy_qos", "fakedns_flows")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(pipe, (4<<20)+1))
	// Closing after a bounded read also prevents an oversized output blocking Wait.
	pipe.Close()
	waitErr := cmd.Wait()
	if readErr != nil || waitErr != nil || len(raw) > 4<<20 {
		return nil, fmt.Errorf("FakeDNS QoS observations unavailable or oversized")
	}
	return parseFakeDNSFlows(raw)
}

func parseFakeDNSFlows(raw []byte) ([]QoSFlow, error) {
	var document struct {
		NFTables []struct {
			Set *struct {
				Name     string            `json:"name"`
				Elements []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	var result []QoSFlow
	found := false
	pool := netip.MustParsePrefix("198.18.0.0/15")
	for _, entry := range document.NFTables {
		if entry.Set == nil || entry.Set.Name != "fakedns_flows" {
			continue
		}
		found = true
		if len(entry.Set.Elements) > 8192 {
			return nil, fmt.Errorf("too many FakeDNS QoS observations")
		}
		for _, element := range entry.Set.Elements {
			// nft JSON wraps timed elements as elem.val.concat; accept bare concat
			// too (some versions omit the timeout wrapper for freshly added entries).
			var value struct {
				Concat []json.RawMessage `json:"concat"`
				Elem   json.RawMessage   `json:"elem"`
				Val    json.RawMessage   `json:"val"`
			}
			for depth := 0; depth < 3; depth++ {
				value.Concat = nil
				value.Elem = nil
				value.Val = nil
				if err := json.Unmarshal(element, &value); err != nil {
					return nil, err
				}
				if len(value.Concat) != 0 {
					break
				}
				if len(value.Elem) > 0 {
					element = value.Elem
				} else {
					element = value.Val
				}
			}
			if len(value.Concat) != 5 {
				return nil, fmt.Errorf("invalid FakeDNS QoS observation")
			}
			var f QoSFlow
			fields := []any{&f.SourceIP, &f.Network, &f.SourcePort, &f.DestinationIP, &f.DestinationPort}
			for i, target := range fields {
				if err := json.Unmarshal(value.Concat[i], target); err != nil {
					// Protocol names normally render as tcp/udp, but nft -n uses numbers.
					var protocol int
					if i != 1 || json.Unmarshal(value.Concat[i], &protocol) != nil || (protocol != 6 && protocol != 17) {
						return nil, err
					}
					f.Network = "tcp"
					if protocol == 17 {
						f.Network = "udp"
					}
				}
			}
			src, err := netip.ParseAddr(f.SourceIP)
			dst, dstErr := netip.ParseAddr(f.DestinationIP)
			if err != nil || !src.Is4() || !src.IsPrivate() || dstErr != nil || !pool.Contains(dst) || f.SourcePort == 0 || f.DestinationPort == 0 || (f.Network != "tcp" && f.Network != "udp") {
				return nil, fmt.Errorf("invalid FakeDNS QoS tuple")
			}
			result = append(result, f)
		}
	}
	if !found {
		return nil, fmt.Errorf("FakeDNS QoS set missing; update the gateway firewall")
	}
	return result, nil
}

// A source socket may be reused for multiple destinations. Recover only an
// unambiguous current tuple; otherwise keep the existing stricter unknown cap.
func recoverFakeDNSFlows(flows, observed []QoSFlow) []QoSFlow {
	type key struct {
		Source, Network             string
		SourcePort, DestinationPort uint16
	}
	keyOf := func(f QoSFlow) key { return key{f.SourceIP, f.Network, f.SourcePort, f.DestinationPort} }
	destinations := make(map[key]string, len(observed))
	for _, f := range observed {
		k := keyOf(f)
		if old, ok := destinations[k]; ok && old != f.DestinationIP {
			destinations[k] = ""
		} else if !ok {
			destinations[k] = f.DestinationIP
		}
	}
	// Conflicting live classifications must not turn into an over-permissive
	// guess even if the kernel set has seen only one side of the collision yet.
	classes := map[key]bool{}
	ambiguous := map[key]bool{}
	for _, f := range flows {
		k := keyOf(f)
		if old, ok := classes[k]; ok && old != f.Direct {
			ambiguous[k] = true
		}
		classes[k] = f.Direct
	}
	result := make([]QoSFlow, 0, len(flows))
	for _, f := range flows {
		if f.DestinationIP == "" {
			k := keyOf(f)
			if ambiguous[k] {
				continue
			}
			f.DestinationIP = destinations[k]
			if f.DestinationIP == "" {
				continue
			}
		}
		result = append(result, f)
	}
	return result
}
