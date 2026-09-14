package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"hoolan/internal/engine"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
	"strings"
	"time"
)

func nodeSet(ids []string) (map[string]bool, error) {
	if len(ids) == 0 || len(ids) > 500 {
		return nil, fmt.Errorf("%w: select 1–500 configurations", ErrInvalidInput)
	}
	set := map[string]bool{}
	for _, id := range ids {
		if id == "" {
			return nil, fmt.Errorf("%w: empty node ID", ErrInvalidInput)
		}
		set[id] = true
	}
	return set, nil
}
func (s *Service) StartBulkLatency(ids []string) (JobStatus, error) {
	if s.cfg.Tester == nil {
		return JobStatus{}, ErrNoTester
	}
	set, err := nodeSet(ids)
	if err != nil {
		return JobStatus{}, err
	}
	for id := range set {
		r, err := s.cfg.Store.Get(id)
		if err != nil {
			return JobStatus{}, err
		}
		if r.Node.Protocol == subscription.ProtoBalance {
			return JobStatus{}, fmt.Errorf("%w: latency-test the original members, not the balancer", ErrInvalidInput)
		}
		if r.Node.ChainInternal {
			return JobStatus{}, fmt.Errorf("%w: select the chain configuration, not an internal hop", ErrInvalidInput)
		}
	}
	return s.startJob(JobStatus{Kind: "latency"}, func(ctx context.Context) error { return s.testSelectedNodes(ctx, set) })
}
func (s *Service) DeleteNodes(ctx context.Context, ids []string) (int, error) {
	remove, err := nodeSet(ids)
	if err != nil {
		return 0, err
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	busy := s.closing || s.refreshing
	s.mu.RUnlock()
	if busy {
		return 0, ErrRefreshInProgress
	}
	before := s.cfg.Store.All()
	byID := map[string]store.Record{}
	for _, r := range before {
		byID[r.ID] = r
	}
	chains := map[string]bool{}
	for id := range remove {
		r, ok := byID[id]
		if !ok {
			return 0, store.ErrNotFound
		}
		if r.Node.ChainInternal {
			return 0, fmt.Errorf("%w: delete the chain configuration instead of its internal hop", ErrInvalidInput)
		}
		if r.ChainID != "" {
			chains[r.ChainID] = true
		}
	}
	visibleCount := len(remove)
	for _, r := range before {
		if chains[r.ChainID] {
			remove[r.ID] = true
		}
	}
	remaining := []store.Record{}
	for _, r := range before {
		if remove[r.ID] {
			continue
		}
		if remove[r.DetourID] {
			return 0, fmt.Errorf("%w: an unselected configuration depends on a selected node", ErrInvalidInput)
		}
		for id := range remove {
			if r.DetourID == "" && r.Node.Detour != "" && r.Node.Detour == byID[id].Node.Tag {
				return 0, fmt.Errorf("%w: an unselected legacy chain uses a selected node", ErrInvalidInput)
			}
		}
		remaining = append(remaining, r)
	}
	s.mu.Lock()
	oldRoutes := s.state.DeviceRoutes
	s.state.DeviceRoutes = withoutRoutes(oldRoutes, remove)
	oldSubs, oldManual, oldAuto, oldSelected := s.state.Subscriptions, s.state.ManualNodeIDs, s.state.AutoSelect, s.state.SelectedNodeID
	s.state.Subscriptions = append([]Subscription(nil), oldSubs...)
	for i, sub := range oldSubs {
		next := []string{}
		for _, id := range sub.NodeIDs {
			if !remove[id] {
				next = append(next, id)
			}
		}
		s.state.Subscriptions[i].NodeIDs = next
	}
	s.state.ManualNodeIDs = map[string]bool{}
	for id, v := range oldManual {
		if !remove[id] {
			s.state.ManualNodeIDs[id] = v
		}
	}
	if remove[s.state.SelectedNodeID] {
		s.state.SelectedNodeID = ""
		s.state.AutoSelect = true
	}
	err = s.cfg.Store.ReplaceRecords(remaining)
	if err == nil {
		err = s.saveState()
	}
	if err != nil {
		s.state.Subscriptions = oldSubs
		s.state.DeviceRoutes = oldRoutes
		s.state.ManualNodeIDs = oldManual
		s.state.AutoSelect = oldAuto
		s.state.SelectedNodeID = oldSelected
		err = errors.Join(err, s.cfg.Store.ReplaceRecords(before))
		s.mu.Unlock()
		return 0, err
	}
	s.mu.Unlock()
	if len(s.cfg.Store.EnabledNodes()) == 0 {
		if err := s.disable(ctx); err != nil {
			return visibleCount, err
		}
		s.mu.Lock()
		s.state.ProxyEnabled = false
		err = s.saveState()
		s.mu.Unlock()
		return visibleCount, err
	}
	return visibleCount, s.reloadRunningLocked(ctx)
}

// CreateChain snapshots each endpoint without changing any source configuration.
// IDs are in traversal order: first hop -> ... -> exit; each later hop detours
// through its predecessor. Only the exit copy is shown/selectable in the UI.
func (s *Service) CreateChain(ctx context.Context, name string, ids []string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 || len(ids) < 2 || len(ids) > 8 {
		return "", fmt.Errorf("%w: chain needs a name and 2–8 ordered nodes", ErrInvalidInput)
	}
	switch name {
	case engine.DefaultSelector, engine.DefaultURLTest, engine.DefaultDirect, engine.DefaultFetchOutbound:
		return "", fmt.Errorf("%w: choose a chain name other than a reserved outbound tag", ErrInvalidInput)
	}
	set, err := nodeSet(ids)
	if err != nil {
		return "", err
	}
	if len(set) != len(ids) {
		return "", fmt.Errorf("%w: a node cannot appear twice in a chain", ErrInvalidInput)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	busy := s.closing || s.refreshing
	s.mu.RUnlock()
	if busy {
		return "", ErrRefreshInProgress
	}
	before := s.cfg.Store.All()
	sources := map[string]store.Record{}
	for _, r := range before {
		sources[r.ID] = r
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	group := hex.EncodeToString(random)
	records := append([]store.Record{}, before...)
	newIDs := []string{}
	previous := ""
	now := time.Now().UTC()
	for i, id := range ids {
		r, ok := sources[id]
		if !ok {
			return "", store.ErrNotFound
		}
		if !r.Enabled || r.Node.ChainInternal {
			return "", fmt.Errorf("%w: chain nodes must be enabled visible configurations", ErrInvalidInput)
		}
		if r.DetourID != "" || r.Node.Detour != "" || r.Node.Protocol == subscription.ProtoBalance {
			return "", fmt.Errorf("%w: use original single-hop nodes, not an existing chain", ErrInvalidInput)
		}
		node := r.Node
		node.LocalVariant = fmt.Sprintf("%s-%d", group, i)
		node.ChainInternal = i < len(ids)-1
		node.Tag = fmt.Sprintf("%s · hop %d", name, i+1)
		node.Detour = ""
		if i == len(ids)-1 {
			node.Tag = name
		}
		copy := store.Record{SourceName: s.chainSourceName(r), ID: store.NodeID(node), Node: node, DetourID: previous, ChainID: group, Enabled: true, CreatedAt: now, UpdatedAt: now, LastLatencyMS: store.LatencyUnmeasured}
		records = append(records, copy)
		newIDs = append(newIDs, copy.ID)
		previous = copy.ID
	}
	s.mu.Lock()
	old := s.state.ManualNodeIDs
	s.state.ManualNodeIDs = map[string]bool{}
	for id, v := range old {
		s.state.ManualNodeIDs[id] = v
	}
	for _, id := range newIDs {
		s.state.ManualNodeIDs[id] = true
	}
	err = s.cfg.Store.ReplaceRecords(records)
	if err == nil {
		err = s.saveState()
	}
	if err != nil {
		s.state.ManualNodeIDs = old
		err = errors.Join(err, s.cfg.Store.ReplaceRecords(before))
		s.mu.Unlock()
		return "", err
	}
	s.mu.Unlock()
	if err := s.reloadRunningLocked(ctx); err != nil {
		return previous, fmt.Errorf("chain saved; applying it failed: %w", err)
	}
	return previous, nil
}
func (h *handlers) createChain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string   `json:"name"`
		IDs  []string `json:"node_ids"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	id, err := h.svc.CreateChain(r.Context(), req.Name, req.IDs)
	if err != nil {
		h.dashboardError(w, err)
		return
	}
	writeJSON(w, 201, map[string]string{"node_id": id, "message": "Chain saved as a new configuration"})
}
