package api

import (
	"context"
	"testing"
)

type trafficSelector struct {
	fakeSelector
	snapshot trafficSnapshot
}

func (f *trafficSelector) Traffic(context.Context) (trafficSnapshot, error) { return f.snapshot, nil }
func TestUsageCounterDeltasAndClosedFlows(t *testing.T) {
	selector := &trafficSelector{}
	h := newLocalHarness(t, testNodes(), func(c *Config) { c.Selector = selector })
	h.eng.mu.Lock()
	h.eng.running = true
	h.eng.mu.Unlock()
	node := h.store.All()[0]
	h.svc.tagByID[node.ID] = "node-A"
	selector.snapshot = trafficSnapshot{Upload: 100, Download: 500, Connections: []connectionSample{{ID: "one", Upload: 70, Download: 400, Chains: []string{"node-A", "auto", "proxy"}}, {ID: "two", Upload: 30, Download: 100, Chains: []string{"direct"}}}}
	h.svc.sampleUsage(context.Background())
	h.svc.sampleUsage(context.Background())
	u := h.svc.state.Usage
	if u.Total.Upload != 100 || u.Total.Download != 500 || u.Outbounds[node.ID].Download != 400 || u.Outbounds["direct"].Upload != 30 {
		t.Fatalf("first sample %+v", u)
	}
	selector.snapshot = trafficSnapshot{Upload: 150, Download: 900}
	h.svc.sampleUsage(context.Background())
	u = h.svc.state.Usage
	if u.Total.Upload != 150 || u.Total.Download != 900 || u.Outbounds[node.ID].Download != 400 {
		t.Fatalf("closed flows %+v", u)
	}
	// Engine counters reset: account new bytes rather than unsigned underflow.
	selector.snapshot = trafficSnapshot{Upload: 10, Download: 20}
	h.svc.sampleUsage(context.Background())
	if h.svc.state.Usage.Total.Download != 920 {
		t.Fatal("counter reset mishandled")
	}
}
