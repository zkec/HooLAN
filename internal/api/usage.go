package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"hoolan/internal/netfilter"
	"strconv"
	"strings"
	"time"
)

type Bytes struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}
type Usage struct {
	Devices    map[string]Bytes `json:"devices"`
	Total      Bytes            `json:"total"`
	Outbounds  map[string]Bytes `json:"outbounds"`
	LastSample time.Time        `json:"last_sample"`
	QoSError   string           `json:"qos_error,omitempty"`
	Error      string           `json:"error,omitempty"`
	PID        int              `json:"pid"`
	Previous   Bytes            `json:"previous"`
}
type connectionMetadata struct {
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationPort string `json:"destinationPort"`
	Network         string `json:"network"`
	Type            string `json:"type"`
}
type connectionSample struct {
	Metadata connectionMetadata `json:"metadata"`
	ID       string             `json:"id"`
	Upload   uint64             `json:"upload"`
	Download uint64             `json:"download"`
	Chains   []string           `json:"chains"`
}
type trafficSnapshot struct {
	Upload      uint64             `json:"uploadTotal"`
	Download    uint64             `json:"downloadTotal"`
	Connections []connectionSample `json:"connections"`
}

func (c *ClashClient) Traffic(ctx context.Context) (trafficSnapshot, error) {
	var snapshot trafficSnapshot
	body, err := c.do(ctx, http.MethodGet, "/connections", nil)
	if err != nil {
		return snapshot, err
	}
	err = json.Unmarshal(body, &snapshot)
	return snapshot, err
}
func delta(now, old uint64) uint64 {
	if now >= old {
		return now - old
	}
	return now
}

// sampleUsage is serialized with engine lifecycle transitions by opMu.
// Global counters include closed connections; per-outbound attribution uses
// observed connection deltas and is explicitly approximate (short flows vanish).
func (s *Service) sampleUsage(ctx context.Context) {
	source, ok := s.cfg.Selector.(interface {
		Traffic(context.Context) (trafficSnapshot, error)
	})
	if !ok || !s.cfg.Engine.Running() {
		return
	}
	snap, err := source.Traffic(ctx)
	qosErr := err
	if err == nil {
		if firewall, ok := s.cfg.Firewall.(interface {
			SyncQoSFlows(context.Context, []netfilter.QoSFlow) error
		}); ok {
			s.mu.RLock()
			flows := classifyQoSFlows(snap.Connections, s.state.DeviceLimits, s.tagByID)
			s.mu.RUnlock()
			qosErr = firewall.SyncQoSFlows(ctx, flows)
		}
	}
	s.mu.Lock()
	s.state.Usage.QoSError = ""
	if qosErr != nil {
		s.state.Usage.QoSError = qosErr.Error()
	}
	defer s.mu.Unlock()
	if err != nil {
		s.state.Usage.Error = err.Error()
		return
	}
	u := &s.state.Usage
	pid := s.cfg.Engine.Pid()
	if u.PID != pid {
		u.Previous = Bytes{}
		s.usageSeen = nil
		u.PID = pid
	}
	if u.Outbounds == nil {
		u.Outbounds = map[string]Bytes{}
	}
	if u.Devices == nil {
		u.Devices = map[string]Bytes{}
	}
	u.Total.Upload += delta(snap.Upload, u.Previous.Upload)
	u.Total.Download += delta(snap.Download, u.Previous.Download)
	u.Previous = Bytes{snap.Upload, snap.Download}
	u.LastSample = time.Now().UTC()
	u.Error = ""
	next := make(map[string]Bytes, len(snap.Connections))
	idByTag := make(map[string]string, len(s.tagByID))
	for id, tag := range s.tagByID {
		idByTag[tag] = id
	}
	for _, c := range snap.Connections {
		old := s.usageSeen[c.ID]
		next[c.ID] = Bytes{c.Upload, c.Download}
		// Only original LAN sources on the transparent inbound are devices.
		// Count independently of outbound attribution (including direct traffic).
		if ip, err := deviceIP(c.Metadata.SourceIP); err == nil && strings.HasPrefix(c.Metadata.Type, "tproxy/") {
			v := u.Devices[ip]
			v.Upload += delta(c.Upload, old.Upload)
			v.Download += delta(c.Download, old.Download)
			u.Devices[ip] = v
		}
		// Attribute once to the selected leaf, not to selector/auto or each hop.
		tag := ""
		for i := len(c.Chains) - 1; i >= 0; i-- {
			candidate := c.Chains[i]
			if candidate != "proxy" && candidate != "auto" {
				tag = candidate
				break
			}
		}
		if tag == "" {
			continue
		}
		key := "outbound:" + tag
		if tag == "direct" {
			key = "direct"
		} else {
			if id := idByTag[tag]; id != "" {
				key = id
			}
			// Distributed listeners bypass the selector, so attribute their proxied
			// bytes to the visible saved group. Direct bypass remains direct above.
			inbound := strings.TrimPrefix(c.Metadata.Type, "tproxy/balance-")
			if len(inbound) > 33 && inbound[32] == '-' && s.tagByID[inbound[:32]] != "" {
				key = inbound[:32]
			}

		}
		v := u.Outbounds[key]
		v.Upload += delta(c.Upload, old.Upload)
		v.Download += delta(c.Download, old.Download)
		u.Outbounds[key] = v
	}
	s.usageSeen = next
	// Persist at most once per minute to limit SD-card writes.
	if time.Since(s.usageSaved) >= time.Minute {
		if err := s.saveState(); err != nil {
			u.Error = fmt.Sprintf("usage persistence: %v", err)
		} else {
			s.usageSaved = time.Now()
		}
	}
}
func (s *Service) startUsageSampler() {
	if _, ok := s.cfg.Selector.(interface {
		Traffic(context.Context) (trafficSnapshot, error)
	}); !ok {
		return
	}
	s.mu.Lock()
	if s.closing || s.usageStarted {
		s.mu.Unlock()
		return
	}
	s.usageStarted = true
	s.jobs.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.jobs.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.jobCtx.Done():
				return
			case <-ticker.C:
				s.opMu.Lock()
				s.mu.RLock()
				on := s.proxyEnabled
				s.mu.RUnlock()
				if on {
					ctx, cancel := context.WithTimeout(s.jobCtx, 3*time.Second)
					s.sampleUsage(ctx)
					cancel()
				}
				s.opMu.Unlock()
			}
		}
	}()
}
func (h *handlers) usage(w http.ResponseWriter, r *http.Request) {
	s := h.svc
	s.mu.RLock()
	usage := s.state.Usage
	usage.Devices = cloneBytes(usage.Devices)
	usage.Outbounds = cloneBytes(usage.Outbounds)
	aliases, routes, limits := copyStrings(s.state.DeviceAliases), copyStrings(s.state.DeviceRoutes), cloneLimits(s.state.DeviceLimits)
	s.mu.RUnlock()
	writeJSON(w, 200, map[string]any{"usage": usage, "device_aliases": aliases, "device_routes": routes, "device_limits": limits, "supported": supportsTraffic(s.cfg.Selector), "scope": "sing-box payload counters while managed; excludes raw forwarding, local Docker/AdGuard traffic and protocol overhead", "attribution": "Per-device/node/direct values are sampled estimates. Short connections between samples may be missed. Chain traffic is attributed once, not added to every hop."})
}

func supportsTraffic(v any) bool {
	_, ok := v.(interface {
		Traffic(context.Context) (trafficSnapshot, error)
	})
	return ok
}

// Upstream Clash reports the final leaf first in chains. Never infer the class
// from the device's assignment: DNS/custom/Iran routing can override it.
func classifyQoSFlows(connections []connectionSample, limits map[string]netfilter.DeviceLimits, tags map[string]string) []netfilter.QoSFlow {
	known := make(map[string]bool, len(tags))
	for _, tag := range tags {
		known[tag] = true
	}
	var flows []netfilter.QoSFlow
	for _, c := range connections {
		m := c.Metadata
		if !strings.HasPrefix(m.Type, "tproxy/") || len(c.Chains) == 0 {
			continue
		}
		ip, err := deviceIP(m.SourceIP)
		if err != nil || limits[ip] == (netfilter.DeviceLimits{}) {
			continue
		}
		dst, err := netip.ParseAddr(m.DestinationIP)
		if err != nil || !dst.Unmap().Is4() || dst.IsUnspecified() || dst.IsMulticast() {
			continue
		}
		sport, srcErr := strconv.ParseUint(m.SourcePort, 10, 16)
		dport, dstErr := strconv.ParseUint(m.DestinationPort, 10, 16)
		if srcErr != nil || dstErr != nil || sport == 0 || dport == 0 || (m.Network != "tcp" && m.Network != "udp") {
			continue
		}
		leaf := c.Chains[0]
		if leaf != "direct" && !known[leaf] {
			continue
		}
		flows = append(flows, netfilter.QoSFlow{SourceIP: ip, DestinationIP: dst.Unmap().String(), Network: m.Network, SourcePort: uint16(sport), DestinationPort: uint16(dport), Direct: leaf == "direct"})
	}
	return flows
}

func cloneBytes(source map[string]Bytes) map[string]Bytes {
	if source == nil {
		return nil
	}
	result := make(map[string]Bytes, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
