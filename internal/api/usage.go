package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Bytes struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}
type Usage struct {
	Total      Bytes            `json:"total"`
	Outbounds  map[string]Bytes `json:"outbounds"`
	LastSample time.Time        `json:"last_sample"`
	Error      string           `json:"error,omitempty"`
	PID        int              `json:"pid"`
	Previous   Bytes            `json:"previous"`
}
type connectionSample struct {
	ID       string   `json:"id"`
	Upload   uint64   `json:"upload"`
	Download uint64   `json:"download"`
	Chains   []string `json:"chains"`
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
	s.mu.Lock()
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
	u.Total.Upload += delta(snap.Upload, u.Previous.Upload)
	u.Total.Download += delta(snap.Download, u.Previous.Download)
	u.Previous = Bytes{snap.Upload, snap.Download}
	u.LastSample = time.Now().UTC()
	u.Error = ""
	next := map[string]Bytes{}
	for _, c := range snap.Connections {
		old := s.usageSeen[c.ID]
		next[c.ID] = Bytes{c.Upload, c.Download}
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
			for id, t := range s.tagByID {
				if t == tag {
					key = id
					break
				}
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
	defer s.mu.RUnlock()
	writeJSON(w, 200, map[string]any{"usage": s.state.Usage, "supported": supportsTraffic(s.cfg.Selector), "scope": "sing-box payload counters while managed; excludes raw forwarding, local Docker/AdGuard traffic and protocol overhead", "attribution": "Per-node/direct values are sampled estimates. Short connections between samples may be missed. Chain traffic is attributed once, not added to every hop."})
}

func supportsTraffic(v any) bool {
	_, ok := v.(interface {
		Traffic(context.Context) (trafficSnapshot, error)
	})
	return ok
}
