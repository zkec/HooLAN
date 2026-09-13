package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"proxy-manager/internal/engine"
	"proxy-manager/internal/store"
	"proxy-manager/internal/subscription"
)

// NodePatch deliberately excludes identity, ownership, protocol and detour fields.
// Secrets are write-only; omission preserves the stored credential.
type NodePatch struct {
	ID          string  `json:"node_id"`
	Name        *string `json:"name,omitempty"`
	Server      *string `json:"server,omitempty"`
	Port        *int    `json:"port,omitempty"`
	Password    *string `json:"password,omitempty"`
	UUID        *string `json:"uuid,omitempty"`
	Method      *string `json:"method,omitempty"`
	SNI         *string `json:"sni,omitempty"`
	Security    *string `json:"security,omitempty"`
	Transport   *string `json:"transport,omitempty"`
	Path        *string `json:"path,omitempty"`
	Host        *string `json:"host,omitempty"`
	ServiceName *string `json:"service_name,omitempty"`
	Flow        *string `json:"flow,omitempty"`
	PublicKey   *string `json:"public_key,omitempty"`
	ShortID     *string `json:"short_id,omitempty"`
	Fingerprint *string `json:"fingerprint,omitempty"`
	Insecure    *bool   `json:"insecure,omitempty"`
}

func localVariant() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func validEditName(name string) bool {
	if strings.TrimSpace(name) == "" || len(name) > 120 {
		return false
	}
	switch name {
	case engine.DefaultSelector, engine.DefaultURLTest, engine.DefaultDirect, engine.DefaultFetchOutbound:
		return false
	}
	return true
}
func (s *Service) editableNode(id string) (store.Record, error) {
	rec, err := s.cfg.Store.Get(id)
	if err != nil {
		return rec, err
	}
	_, manual := s.NodeOrigins(id)
	if !manual || rec.Node.ChainInternal || rec.ChainID != "" {
		return rec, fmt.Errorf("%w: select a manual configuration; use the Chain Builder for chains", ErrInvalidInput)
	}
	return rec, nil
}
func (s *Service) UpdateManualNode(ctx context.Context, patch NodePatch) (string, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.editAllowed(); err != nil {
		return "", err
	}
	old, err := s.editableNode(patch.ID)
	if err != nil {
		return "", err
	}
	n := old.Node
	for _, field := range []struct {
		value  *string
		target *string
	}{
		{patch.Name, &n.Tag}, {patch.Server, &n.Server}, {patch.Password, &n.Password}, {patch.UUID, &n.UUID}, {patch.Method, &n.Method},
		{patch.SNI, &n.SNI}, {patch.Path, &n.Path}, {patch.Host, &n.Host}, {patch.ServiceName, &n.ServiceName}, {patch.Flow, &n.Flow},
		{patch.PublicKey, &n.PublicKey}, {patch.ShortID, &n.ShortID}, {patch.Fingerprint, &n.Fingerprint},
	} {
		if field.value != nil {
			*field.target = *field.value
		}
	}
	n.Tag = strings.TrimSpace(n.Tag)
	n.Server = strings.TrimSpace(n.Server)
	if patch.UUID != nil {
		compact := strings.ReplaceAll(n.UUID, "-", "")
		_, uuidErr := hex.DecodeString(compact)
		if len(n.UUID) != 36 || len(compact) != 32 || uuidErr != nil || n.UUID[8] != '-' || n.UUID[13] != '-' || n.UUID[18] != '-' || n.UUID[23] != '-' {
			return "", fmt.Errorf("%w: UUID must be a valid UUID", ErrInvalidInput)
		}
	}
	if patch.Port != nil {
		n.Port = *patch.Port
	}
	if patch.Insecure != nil {
		n.Insecure = *patch.Insecure
	}
	if patch.Security != nil {
		n.Security = subscription.Security(*patch.Security)
	}
	if patch.Transport != nil {
		n.Transport = subscription.Transport(*patch.Transport)
	}
	if !validEditName(n.Tag) || strings.ContainsAny(n.Server, " /\t\r\n") {
		return "", fmt.Errorf("%w: invalid name or server", ErrInvalidInput)
	}
	switch n.Security {
	case subscription.SecNone, subscription.SecTLS, subscription.SecReality:
	default:
		return "", fmt.Errorf("%w: unsupported security", ErrInvalidInput)
	}
	switch n.Transport {
	case "", subscription.TransportTCP, subscription.TransportWS, subscription.TransportGRPC, subscription.TransportHTTP:
	default:
		return "", fmt.Errorf("%w: unsupported transport", ErrInvalidInput)
	}
	if err := n.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	// Shared provider records remain provider-owned; fork their manual copy.
	origins, _ := s.NodeOrigins(old.ID)
	shared := len(origins) > 0
	if shared {
		n.LocalVariant, err = localVariant()
		if err != nil {
			return "", err
		}
	}
	next := old
	next.Node = n
	next.ID = store.NodeID(n)
	next.UpdatedAt = time.Now().UTC()
	next.LastLatencyMS = store.LatencyUnmeasured
	next.LastCheckedAt = time.Time{}
	next.LastError = ""
	next.ConsecutiveFailures = 0
	before := s.cfg.Store.All()
	after := make([]store.Record, 0, len(before)+1)
	for _, r := range before {
		if r.ID == next.ID && r.ID != old.ID {
			return "", fmt.Errorf("%w: another configuration already has this endpoint", ErrInvalidInput)
		}
		if r.ID != old.ID || shared {
			after = append(after, r)
		}
	}
	after = append(after, next)
	return next.ID, s.commitEdit(ctx, before, after, old.ID, next.ID, map[string]bool{old.ID: true}, []string{next.ID})
}
func (s *Service) editAllowed() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closing || s.refreshing {
		return ErrRefreshInProgress
	}
	return nil
}

// commitEdit keeps node-ID references consistent and rolls back persistence and
// managed settings if rendering or applying the edited inventory fails. opMu held.
func (s *Service) commitEdit(ctx context.Context, before, after []store.Record, oldID, newID string, removeManual map[string]bool, manualIDs []string) error {
	newCopies := map[string]bool{}
	for _, id := range manualIDs {
		newCopies[id] = true
	}
	for i := range after {
		if !newCopies[after[i].ID] && after[i].DetourID == oldID {
			after[i].DetourID = newID
		}
	}
	s.mu.Lock()
	oldManual, oldRoutes, oldSelected := s.state.ManualNodeIDs, s.state.DeviceRoutes, s.state.SelectedNodeID
	s.state.ManualNodeIDs = map[string]bool{}
	for id, v := range oldManual {
		if !removeManual[id] {
			s.state.ManualNodeIDs[id] = v
		}
	}
	for _, id := range manualIDs {
		s.state.ManualNodeIDs[id] = true
	}
	s.state.DeviceRoutes = copyStrings(oldRoutes)
	for ip, id := range s.state.DeviceRoutes {
		if id == oldID {
			s.state.DeviceRoutes[ip] = newID
		}
	}
	if s.state.SelectedNodeID == oldID {
		s.state.SelectedNodeID = newID
	}
	rollback := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.state.ManualNodeIDs, s.state.DeviceRoutes, s.state.SelectedNodeID = oldManual, oldRoutes, oldSelected
		return errors.Join(s.cfg.Store.ReplaceRecords(before), s.saveState())
	}
	err := s.cfg.Store.ReplaceRecords(after)
	if err == nil {
		err = subscription.ValidateChains(s.cfg.Store.EnabledNodes())
	}
	if err == nil {
		err = s.saveState()
	}
	s.mu.Unlock()
	if err != nil {
		return errors.Join(err, rollback())
	}
	if err = s.configureEngineRouting(); err == nil {
		err = s.reloadRunningLocked(ctx)
	}
	if err != nil {
		return errors.Join(err, rollback(), s.configureEngineRouting())
	}
	return nil
}

func (h *handlers) editNode(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rec, err := h.svc.editableNode(r.URL.Query().Get("node_id"))
		if err != nil {
			h.dashboardError(w, err)
			return
		}
		n := rec.Node
		// Do not return stored UUID/password, even to populate the editing form.
		writeJSON(w, 200, map[string]any{"node_id": rec.ID, "protocol": n.Protocol, "name": n.Tag, "server": n.Server, "port": n.Port, "method": n.Method, "security": n.Security, "transport": n.Transport, "sni": n.SNI, "path": n.Path, "host": n.Host, "service_name": n.ServiceName, "flow": n.Flow, "public_key": n.PublicKey, "short_id": n.ShortID, "fingerprint": n.Fingerprint, "insecure": n.Insecure})
	case http.MethodPut:
		var req NodePatch
		if err := decodeBody(r, &req); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		id, err := h.svc.UpdateManualNode(r.Context(), req)
		if err != nil {
			h.dashboardError(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"node_id": id, "message": "Configuration updated"})
	default:
		methodsNotAllowed(w, "GET, PUT")
	}
}

type ChainHop struct {
	ID     string `json:"id"`
	Tag    string `json:"tag"`
	Server string `json:"server"`
}

func (s *Service) chainRecords(id string) ([]store.Record, error) {
	exit, err := s.cfg.Store.Get(id)
	if err != nil {
		return nil, err
	}
	if exit.ChainID == "" || exit.Node.ChainInternal || exit.Node.Protocol == subscription.ProtoBalance {
		return nil, fmt.Errorf("%w: select a saved chain", ErrInvalidInput)
	}
	seen := map[string]bool{}
	result := []store.Record{}
	r := exit
	for {
		if seen[r.ID] || r.ChainID != exit.ChainID {
			return nil, fmt.Errorf("%w: broken saved chain", ErrInvalidInput)
		}
		seen[r.ID] = true
		result = append(result, r)
		if r.DetourID == "" {
			break
		}
		r, err = s.cfg.Store.Get(r.DetourID)
		if err != nil {
			return nil, err
		}
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result, nil
}
func (s *Service) UpdateChain(ctx context.Context, id, name string, ids []string) (string, error) {
	name = strings.TrimSpace(name)
	set, err := nodeSet(ids)
	if err != nil {
		return "", err
	}
	if !validEditName(name) || len(ids) < 2 || len(ids) > 8 || len(set) != len(ids) {
		return "", fmt.Errorf("%w: chain needs a name and 2–8 distinct hops", ErrInvalidInput)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.editAllowed(); err != nil {
		return "", err
	}
	oldHops, err := s.chainRecords(id)
	if err != nil {
		return "", err
	}
	own := map[string]bool{}
	for _, r := range oldHops {
		own[r.ID] = true
	}
	group := oldHops[0].ChainID
	before := s.cfg.Store.All()
	after := []store.Record{}
	for _, r := range before {
		if !own[r.ID] {
			after = append(after, r)
		}
	}
	previous := ""
	newIDs := []string{}
	now := time.Now().UTC()
	for i, sourceID := range ids {
		source, err := s.cfg.Store.Get(sourceID)
		if err != nil {
			return "", err
		}
		if !source.Enabled || (!own[sourceID] && (source.Node.ChainInternal || source.ChainID != "" || source.DetourID != "" || source.Node.Detour != "")) {
			return "", fmt.Errorf("%w: use current chain hops or enabled single-hop configurations", ErrInvalidInput)
		}
		n := source.Node
		n.LocalVariant = fmt.Sprintf("%s-%d", group, i)
		n.ChainInternal = i < len(ids)-1
		n.Detour = ""
		n.Tag = fmt.Sprintf("%s · hop %d", name, i+1)
		if !n.ChainInternal {
			n.Tag = name
		}
		r := store.Record{ID: store.NodeID(n), Node: n, ChainID: group, DetourID: previous, Enabled: true, CreatedAt: oldHops[len(oldHops)-1].CreatedAt, UpdatedAt: now, LastLatencyMS: store.LatencyUnmeasured}
		after = append(after, r)
		newIDs = append(newIDs, r.ID)
		previous = r.ID
	}
	return previous, s.commitEdit(ctx, before, after, id, previous, own, newIDs)
}
func (h *handlers) chains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createChain(w, r)
	case http.MethodGet:
		h.svc.opMu.Lock()
		defer h.svc.opMu.Unlock()
		records, err := h.svc.chainRecords(r.URL.Query().Get("node_id"))
		if err != nil {
			h.dashboardError(w, err)
			return
		}
		hops := []ChainHop{}
		for _, rec := range records {
			hops = append(hops, ChainHop{rec.ID, rec.Node.Tag, rec.Node.Server})
		}
		writeJSON(w, 200, map[string]any{"node_id": records[len(records)-1].ID, "name": records[len(records)-1].Node.Tag, "hops": hops})
	case http.MethodPut:
		var req struct {
			ID   string   `json:"node_id"`
			Name string   `json:"name"`
			IDs  []string `json:"node_ids"`
		}
		if err := decodeBody(r, &req); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		id, err := h.svc.UpdateChain(r.Context(), req.ID, req.Name, req.IDs)
		if err != nil {
			h.dashboardError(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"node_id": id, "message": "Chain updated"})
	default:
		methodsNotAllowed(w, "GET, POST, PUT")
	}
}
