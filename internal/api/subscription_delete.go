package api

import (
	"context"
	"fmt"
	"strings"

	"hoolan/internal/store"
)

// RemoveSubscription prunes nodes owned only by this source, preserving manual
// nodes and nodes belonging to another subscription. Seeded sources are
// tombstoned so HOOLAN_SUBS cannot silently restore them on restart.
func (s *Service) RemoveSubscription(ctx context.Context, id string) (int, error) {
	if strings.TrimSpace(id) == "" {
		return 0, fmt.Errorf("%w: subscription_id is required", ErrInvalidInput)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	if s.closing || s.refreshing {
		s.mu.RUnlock()
		return 0, ErrRefreshInProgress
	}
	found := false
	candidates, keep := map[string]bool{}, map[string]bool{}
	for _, sub := range s.state.Subscriptions {
		if sub.ID == id {
			found = true
			for _, node := range sub.NodeIDs {
				candidates[node] = true
			}
		} else {
			for _, node := range sub.NodeIDs {
				keep[node] = true
			}
		}
	}
	for node, manual := range s.state.ManualNodeIDs {
		if manual {
			keep[node] = true
		}
	}
	s.mu.RUnlock()
	if !found {
		return 0, store.ErrNotFound
	}
	remove := map[string]bool{}
	for node := range candidates {
		if !keep[node] {
			if _, err := s.cfg.Store.Get(node); err == nil {
				remove[node] = true
			}
		}
	}
	return s.deleteNodesLocked(ctx, remove, id)
}
