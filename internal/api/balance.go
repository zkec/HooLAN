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

// CreateLoadBalancer snapshots members and their complete detour paths. A
// provider refresh can then prune originals without breaking saved groups.
func (s *Service) CreateLoadBalancer(ctx context.Context, name string, ids []string) (string, error) {
	return s.CreateLoadBalancerWithStrategy(ctx, name, ids, "hash")
}
func (s *Service) CreateLoadBalancerWithStrategy(ctx context.Context, name string, ids []string, strategy string) (string, error) {
	if strategy == "" {
		strategy = "hash"
	}
	if strategy != "hash" && strategy != "latency" {
		return "", fmt.Errorf("%w: unknown balancing strategy", ErrInvalidInput)
	}
	name = strings.TrimSpace(name)
	if !validEditName(name) || len(ids) < 2 || len(ids) > 32 {
		return "", fmt.Errorf("%w: provide a name and 2–32 distinct nodes", ErrInvalidInput)
	}
	set, err := nodeSet(ids)
	if err != nil {
		return "", err
	}
	if len(set) != len(ids) {
		return "", fmt.Errorf("%w: duplicate member", ErrInvalidInput)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	busy := s.refreshing || s.closing
	s.mu.RUnlock()
	if busy {
		return "", ErrRefreshInProgress
	}
	if _, ok := s.cfg.Firewall.(distributionFirewall); !ok {
		return "", fmt.Errorf("firewall does not support connection distribution")
	}
	before := s.cfg.Store.All()
	inventory := s.cfg.Store.EnabledNodes()
	if err := subscription.ValidateChains(inventory); err != nil {
		return "", err
	}
	byID := map[string]store.Record{}
	byTag := map[string]subscription.Node{}
	runtimeByID := map[string]subscription.Node{}
	count := 0
	for _, r := range before {
		byID[r.ID] = r
		if r.Node.Protocol == subscription.ProtoBalance {
			count++
		}
	}
	if count >= 16 {
		return "", fmt.Errorf("%w: at most 16 load balancers", ErrInvalidInput)
	}
	for _, n := range inventory {
		byTag[n.Tag] = n
		runtimeByID[store.NodeID(n)] = n
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	group := hex.EncodeToString(random)
	copies := map[string]store.Record{}
	order := []string{}
	members := []string{}
	now := time.Now().UTC()
	for _, id := range ids {
		r, ok := byID[id]
		if !ok {
			return "", store.ErrNotFound
		}
		if !r.Enabled || r.Node.ChainInternal || r.Node.Protocol == subscription.ProtoBalance {
			return "", fmt.Errorf("%w: choose enabled nodes or chains, not existing balancers", ErrInvalidInput)
		}
		var target subscription.Node
		for _, n := range inventory {
			if store.NodeID(n) == id {
				target = n
				break
			}
		}
		for _, tag := range subscription.ChainOf(inventory, target.Tag) {
			source := byTag[tag]
			sourceID := store.NodeID(source)
			if _, ok := copies[sourceID]; ok {
				continue
			}
			if source.Protocol == subscription.ProtoBalance {
				return "", fmt.Errorf("%w: nested balancers are unsupported", ErrInvalidInput)
			}
			node := source
			node.LocalVariant = group + "-" + sourceID
			node.ChainInternal = true
			node.Tag = fmt.Sprintf("%s · member %d", name, len(order)+1)
			node.Detour = ""
			rec := store.Record{ID: store.NodeID(node), Node: node, ChainID: group, Enabled: true, CreatedAt: now, UpdatedAt: now, LastLatencyMS: store.LatencyUnmeasured}
			copies[sourceID] = rec
			order = append(order, sourceID)
		}
		members = append(members, copies[id].ID)
	}
	records := append([]store.Record{}, before...)
	for _, sourceID := range order {
		rec := copies[sourceID]
		source := byID[sourceID]
		dep := source.DetourID
		if dep == "" && runtimeByID[sourceID].Detour != "" {
			dep = store.NodeID(byTag[runtimeByID[sourceID].Detour])
		}
		if dep != "" {
			copy, ok := copies[dep]
			if !ok {
				return "", fmt.Errorf("missing copied detour")
			}
			rec.DetourID = copy.ID
		}
		records = append(records, rec)
	}
	root := subscription.Node{Protocol: subscription.ProtoBalance, Tag: name, LocalVariant: group, BalanceMembers: members, BalanceStrategy: strategy}
	id := store.NodeID(root)
	records = append(records, store.Record{ID: id, Node: root, ChainID: group, Enabled: true, CreatedAt: now, UpdatedAt: now, LastLatencyMS: store.LatencyUnmeasured})
	candidate := store.EnabledRecords(records)
	if _, err := engine.DistributionPlan(candidate, s.cfg.Engine.TProxyPort()); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if err := subscription.ValidateChains(candidate); err != nil {
		return "", err
	}
	s.mu.Lock()
	oldManual := s.state.ManualNodeIDs
	s.state.ManualNodeIDs = map[string]bool{}
	for id, v := range oldManual {
		s.state.ManualNodeIDs[id] = v
	}
	for _, r := range records {
		if r.ChainID == group {
			s.state.ManualNodeIDs[r.ID] = true
		}
	}
	err = s.cfg.Store.ReplaceRecords(records)
	if err == nil {
		err = s.saveState()
	}
	if err != nil {
		s.state.ManualNodeIDs = oldManual
		err = errors.Join(err, s.cfg.Store.ReplaceRecords(before))
		s.mu.Unlock()
		return "", err
	}
	s.mu.Unlock()
	if err := s.configureDistribution(); err != nil {
		return id, err
	}
	if err := s.reloadRunningLocked(ctx); err != nil {
		return id, fmt.Errorf("load balancer saved; applying it failed: %w", err)
	}
	return id, nil
}
func (h *handlers) createLoadBalancer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Strategy string   `json:"strategy"`
		Name     string   `json:"name"`
		IDs      []string `json:"node_ids"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	id, err := h.svc.CreateLoadBalancerWithStrategy(r.Context(), req.Name, req.IDs, req.Strategy)
	if err != nil {
		h.dashboardError(w, err)
		return
	}
	writeJSON(w, 201, map[string]string{"node_id": id, "message": "Load balancer saved"})
}

type distributionFirewall interface {
	ConfigureDistribution([]engine.DistributionGroup, string, map[string]string)
}

func (s *Service) configureDistribution() error {
	all := s.cfg.Store.EnabledNodes()
	plan, err := engine.DistributionPlan(all, s.cfg.Engine.TProxyPort())
	if err != nil {
		return err
	}
	s.mu.RLock()
	selected := s.state.SelectedNodeID
	if s.state.AutoSelect {
		selected = engine.AutomaticFallback(all)
	}
	routes := copyStrings(s.state.DeviceRoutes)
	s.mu.RUnlock()
	valid := map[string]bool{engine.DefaultDirect: true}
	for _, n := range all {
		if !n.ChainInternal {
			valid[store.NodeID(n)] = true
		}
	}
	for ip, id := range routes {
		if !valid[id] {
			delete(routes, ip)
		}
	}
	if configurable, ok := s.cfg.Firewall.(distributionFirewall); ok {
		configurable.ConfigureDistribution(plan, selected, routes)
	} else if len(plan) > 0 {
		return errors.New("firewall does not support connection distribution")
	}
	return nil
}
