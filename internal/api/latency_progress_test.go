package api

import (
	"context"
	"errors"
	"hoolan/internal/subscription"
	"hoolan/internal/tester"
	"testing"
	"time"
)

type stagedLatencyTester struct {
	fakeTester
	first  chan struct{}
	resume chan struct{}
}

func (p *stagedLatencyTester) TestSelectedNodesProgress(ctx context.Context, nodes, inventory []subscription.Node, done func(int, tester.Result)) []tester.Result {
	results := make([]tester.Result, len(nodes))
	results[0] = tester.Result{Tag: nodes[0].Tag, Latency: 42 * time.Millisecond}
	done(0, results[0])
	close(p.first)
	select {
	case <-p.resume:
	case <-ctx.Done():
		return results
	}
	for i := 1; i < len(nodes); i++ {
		results[i] = tester.Result{Tag: nodes[i].Tag, Err: errors.New("probe failed")}
		done(i, results[i])
	}
	return results
}
func TestLatencyPublishesBeforeBatchFinishes(t *testing.T) {
	probe := &stagedLatencyTester{first: make(chan struct{}), resume: make(chan struct{})}
	h := newLocalHarness(t, nil, func(c *Config) { c.Tester = probe })
	a, err := h.svc.AddManualNode(context.Background(), providerLink)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.svc.AddManualNode(context.Background(), manualLink)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.StartBulkLatency([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	defer close(probe.resume)
	select {
	case <-probe.first:
	case <-time.After(5 * time.Second):
		t.Fatal("no incremental result")
	}
	job := h.svc.JobStatus()
	if job.State != "running" || job.TestsTotal != 2 || job.Tested != 1 || job.Reachable != 1 {
		t.Fatalf("progress: %+v", job)
	}
	measured := 0
	for _, r := range h.store.All() {
		if !r.LastCheckedAt.IsZero() {
			measured++
			if r.LastLatencyMS != 42 {
				t.Fatalf("result not visible: %+v", r)
			}
		}
	}
	if measured != 1 {
		t.Fatalf("expected one completed node, got %d", measured)
	}
}
