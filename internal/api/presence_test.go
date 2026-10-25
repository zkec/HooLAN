package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type presenceFirewall struct {
	*fakeFirewall
	neighborMu sync.Mutex
	neighbors  map[string]bool
	err        error
	called     chan struct{}
}

func (f *presenceFirewall) DeviceNeighbors(context.Context) (map[string]bool, error) {
	f.neighborMu.Lock()
	defer f.neighborMu.Unlock()
	out := map[string]bool{}
	for ip, online := range f.neighbors {
		out[ip] = online
	}
	if f.called != nil {
		select {
		case f.called <- struct{}{}:
		default:
		}
	}
	return out, f.err
}
func TestDevicePresenceFromLANAndTrafficExpires(t *testing.T) {
	h := newLocalHarness(t, nil, nil)
	fw := &presenceFirewall{fakeFirewall: h.fw, neighbors: map[string]bool{"192.168.3.2": true, "192.168.3.3": false, "8.8.8.8": true}}
	h.svc.cfg.Firewall = fw
	h.svc.refreshDevicePresence(context.Background())
	h.svc.mu.Lock()
	now := time.Now()
	presence := h.svc.devicePresenceLocked(now)
	if !presence["192.168.3.2"].Online || presence["192.168.3.3"].Online {
		t.Fatal("reachability misclassified")
	}
	if _, exists := presence["8.8.8.8"]; exists {
		t.Fatal("public IP admitted as LAN client")
	}
	h.svc.deviceSeen["192.168.3.4"] = now.Add(-2 * time.Minute)
	h.svc.deviceSeen["192.168.3.5"] = now.Add(-time.Second)
	presence = h.svc.devicePresenceLocked(now)
	h.svc.mu.Unlock()
	if presence["192.168.3.4"].Online || !presence["192.168.3.5"].Online {
		t.Fatal("recent traffic window ignored")
	}
	fw.neighbors = map[string]bool{"192.168.3.4": false}
	h.svc.refreshDevicePresence(context.Background())
	w := httptest.NewRecorder()
	(&handlers{svc: h.svc}).usage(w, httptest.NewRequest("GET", "/api/usage", nil))
	var result struct {
		Presence map[string]DevicePresence `json:"device_presence"`
		Window   int                       `json:"device_online_window_seconds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Presence["192.168.3.4"].Online || !result.Presence["192.168.3.5"].Online || result.Window != 60 {
		t.Fatal("API failed to expose current presence")
	}
	fw.err = errors.New("ip failed")
	h.svc.refreshDevicePresence(context.Background())
	h.svc.mu.RLock()
	errText := h.svc.devicePresenceError
	past := h.svc.devicePresenceLocked(now.Add(2 * time.Minute))
	h.svc.mu.RUnlock()
	if errText == "" || past["192.168.3.5"].Online {
		t.Fatal("failed lookup made stale presence immortal")
	}
}
func TestIdleConnectionDoesNotKeepDeviceOnline(t *testing.T) {
	sel := &trafficSelector{}
	h := newLocalHarness(t, testNodes(), func(c *Config) { c.Selector = sel })
	h.eng.mu.Lock()
	h.eng.running = true
	h.eng.mu.Unlock()
	sel.snapshot = trafficSnapshot{Connections: []connectionSample{{ID: "lan", Metadata: connectionMetadata{Type: "tproxy/tproxy-in", SourceIP: "192.168.3.5"}, Upload: 5}, {ID: "local", Metadata: connectionMetadata{Type: "mixed", SourceIP: "192.168.3.6"}, Upload: 8}}}
	h.svc.sampleUsage(context.Background())
	if !h.svc.devicePresenceLocked(time.Now())["192.168.3.5"].Online {
		t.Fatal("first traffic sample not observed")
	}
	if _, exists := h.svc.deviceSeen["192.168.3.6"]; exists {
		t.Fatal("host/health-check traffic treated as LAN presence")
	}
	h.svc.deviceSeen["192.168.3.5"] = time.Now().Add(-2 * time.Minute)
	h.svc.sampleUsage(context.Background())
	if h.svc.devicePresenceLocked(time.Now())["192.168.3.5"].Online {
		t.Fatal("idle TCP connection kept device online")
	}
	sel.snapshot.Connections[0].Download++
	h.svc.sampleUsage(context.Background())
	if !h.svc.devicePresenceLocked(time.Now())["192.168.3.5"].Online {
		t.Fatal("new bytes not observed")
	}
}
func TestPresenceRunsWithEngineOffAndStops(t *testing.T) {
	h := newLocalHarness(t, nil, nil)
	fw := &presenceFirewall{fakeFirewall: h.fw, neighbors: map[string]bool{"192.168.3.5": true}, called: make(chan struct{}, 1)}
	h.svc.cfg.Firewall = fw
	h.svc.startDevicePresence()
	h.svc.startDevicePresence()
	select {
	case <-fw.called:
	case <-time.After(time.Second):
		t.Fatal("discovery did not run with engine off")
	}
	h.svc.jobCancel()
	done := make(chan struct{})
	go func() { h.svc.jobs.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("presence job survived cancellation")
	}
	h.svc.mu.RLock()
	online := h.svc.devicePresenceLocked(time.Now())["192.168.3.5"].Online
	h.svc.mu.RUnlock()
	if !online {
		t.Fatal("OFF engine discarded LAN presence")
	}
}
func TestPresenceMemoryBoundAndPruning(t *testing.T) {
	h := newLocalHarness(t, nil, nil)
	now := time.Now()
	h.svc.deviceSeen = map[string]time.Time{}
	for i := 0; i < maxDevicePresence; i++ {
		h.svc.deviceSeen[time.Unix(int64(i), 0).String()] = now
	}
	h.svc.noteDeviceSeenLocked("192.168.3.5", now)
	if len(h.svc.deviceSeen) != maxDevicePresence {
		t.Fatal("presence memory unbounded")
	}
	h.svc.deviceSeen["expired"] = now.Add(-25 * time.Hour)
	h.svc.deviceSeen["unknown"] = time.Time{}
	h.svc.pruneDevicePresenceLocked(now)
	if _, exists := h.svc.deviceSeen["expired"]; exists {
		t.Fatal("old runtime entries not pruned")
	}
	if _, exists := h.svc.deviceSeen["unknown"]; exists {
		t.Fatal("unconfirmed entries not pruned")
	}
}
