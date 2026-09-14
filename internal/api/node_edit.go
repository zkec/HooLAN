package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
)

func (s *Service) DeleteManual(ctx context.Context, id string) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	rec, err := s.cfg.Store.Get(id)
	if err != nil {
		return err
	}
	_, manual := s.NodeOrigins(id)
	if !manual {
		return fmt.Errorf("%w: only manual configs can be deleted", ErrInvalidInput)
	}
	s.mu.RLock()
	busy := s.refreshing || s.closing
	selected := !s.state.AutoSelect && s.state.SelectedNodeID == id
	s.mu.RUnlock()
	if busy {
		return ErrRefreshInProgress
	}
	if selected {
		return fmt.Errorf("%w: select another node or Auto before deleting this node", ErrInvalidInput)
	}
	for _, r := range s.cfg.Store.All() {
		if r.DetourID == id || r.Node.Detour == rec.Node.Tag {
			return fmt.Errorf("%w: remove chains referencing this node first", ErrInvalidInput)
		}
	}
	if s.cfg.Engine.Running() && len(s.cfg.Store.EnabledNodes()) <= 1 {
		return fmt.Errorf("%w: turn the proxy off before deleting its last node", ErrInvalidInput)
	}
	if err := s.cfg.Store.Delete(id); err != nil {
		return err
	}
	s.mu.Lock()
	wasManual := s.state.ManualNodeIDs[id]
	delete(s.state.ManualNodeIDs, id)
	err = s.saveState()
	if err != nil {
		s.state.ManualNodeIDs[id] = wasManual
	}
	s.mu.Unlock()
	if err != nil {
		_, _, restore := s.cfg.Store.UpsertNodes([]subscription.Node{rec.Node})
		if restore == nil {
			restore = s.cfg.Store.Update(id, func(r *store.Record) error { *r = rec; return nil })
		}
		return errors.Join(err, restore)
	}
	// Subscription membership is retained: deleting a shared node removes it now,
	// but an explicit provider refresh can import it again.
	return s.reloadRunningLocked(ctx)
}
func (s *Service) SetNodeDetour(ctx context.Context, id, target string) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	busy := s.refreshing || s.closing
	s.mu.RUnlock()
	if busy {
		return ErrRefreshInProgress
	}
	old, err := s.cfg.Store.Get(id)
	if err != nil {
		return err
	}
	if old.ChainID != "" {
		return fmt.Errorf("%w: rebuild saved chains with the Chain Builder", ErrInvalidInput)
	}
	if target != "" {
		hop, err := s.cfg.Store.Get(target)
		if err != nil {
			return err
		}
		if hop.Node.ChainInternal || hop.Node.Protocol == subscription.ProtoBalance {
			return fmt.Errorf("%w: internal chain hops cannot be targeted", ErrInvalidInput)
		}
	}
	if err := s.cfg.Store.SetDetour(id, target); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	nodes := s.cfg.Store.EnabledNodes()
	if err := subscription.ValidateChains(nodes); err != nil {
		rollback := s.cfg.Store.Update(id, func(r *store.Record) error { *r = old; return nil })
		return errors.Join(fmt.Errorf("%w: %v", ErrInvalidInput, err), rollback)
	}
	if err := s.reloadRunningLocked(ctx); err != nil {
		rollback := s.cfg.Store.Update(id, func(r *store.Record) error { *r = old; return nil })
		return errors.Join(err, rollback)
	}
	return nil
}
func (h *handlers) deleteNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"node_ids"`
		ID  string   `json:"node_id"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.ID != "" {
		if len(req.IDs) > 0 {
			writeError(w, 400, "use node_ids or node_id, not both")
			return
		}
		req.IDs = []string{req.ID}
	}
	count, err := h.svc.DeleteNodes(r.Context(), req.IDs)
	if err != nil {
		h.dashboardError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": count, "message": "Selected configurations deleted"})
}
func (h *handlers) detourNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"node_id"`
		Target string `json:"detour_id"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err := h.svc.SetNodeDetour(r.Context(), req.ID, req.Target); err != nil {
		h.dashboardError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"message": "Chain saved"})
}
