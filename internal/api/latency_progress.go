package api

import (
	"context"
	"errors"
	"sync"

	"hoolan/internal/store"
	"hoolan/internal/subscription"
	"hoolan/internal/tester"
)

// probeNodes publishes completed measurements before the rest of the batch ends.
// Only the completion path is serialized; probes retain the tester's concurrency.
func (s *Service) probeNodes(ctx context.Context, nodes, inventory []subscription.Node, ids []string) error {
	s.mu.Lock()
	s.job.TestsTotal, s.job.Tested, s.job.Reachable = len(nodes), 0, 0
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var saveErr error
	seen := make([]bool, len(nodes))
	completed := func(i int, result tester.Result) {
		mu.Lock()
		defer mu.Unlock()
		if saveErr != nil || ctx.Err() != nil {
			return
		}
		if i < 0 || i >= len(ids) || seen[i] {
			saveErr = errors.New("invalid latency progress result")
			cancel()
			return
		}
		if err := s.cfg.Store.RecordMeasurements([]store.Measurement{{ID: ids[i], Latency: result.Latency, Err: result.Err}}); err != nil {
			saveErr = err
			cancel()
			return
		}
		seen[i] = true
		s.mu.Lock()
		s.job.Tested++
		if result.OK() {
			s.job.Reachable++
		}
		s.mu.Unlock()
	}
	var results []tester.Result
	if progress, ok := s.cfg.Tester.(interface {
		TestSelectedNodesProgress(context.Context, []subscription.Node, []subscription.Node, func(int, tester.Result)) []tester.Result
	}); ok {
		results = progress.TestSelectedNodesProgress(ctx, nodes, inventory, completed)
	} else {
		if selected, ok := s.cfg.Tester.(interface {
			TestSelectedNodes(context.Context, []subscription.Node, []subscription.Node) []tester.Result
		}); ok {
			results = selected.TestSelectedNodes(ctx, nodes, inventory)
		} else {
			results = s.cfg.Tester.TestNodes(ctx, nodes)
		}
		if len(results) == len(ids) {
			for i, r := range results {
				completed(i, r)
			}
		}
	}
	if saveErr != nil {
		return saveErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(results) != len(ids) {
		return errors.New("latency tester returned incomplete results")
	}
	for _, done := range seen {
		if !done {
			return errors.New("latency tester returned incomplete progress")
		}
	}
	return nil
}
