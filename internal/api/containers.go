package api

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"time"

	"hoolan/internal/docker"
	"hoolan/internal/netfilter"
)

type ContainerInventory interface {
	List(context.Context) ([]docker.Container, error)
}
type ContainerSettings struct {
	Proxy  bool                   `json:"proxy"`
	NodeID string                 `json:"node_id,omitempty"`
	QoS    netfilter.DeviceLimits `json:"qos"`
}
type ContainerUpdate struct {
	Key    string                  `json:"key"`
	Proxy  *bool                   `json:"proxy,omitempty"`
	NodeID *string                 `json:"node_id,omitempty"`
	QoS    *netfilter.DeviceLimits `json:"qos,omitempty"`
}

var containerKeyPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validateContainerSettings(settings map[string]ContainerSettings) error {
	if len(settings) > 256 {
		return fmt.Errorf("at most 256 container policies are supported")
	}
	for key, p := range settings {
		if !containerKeyPattern.MatchString(key) {
			return fmt.Errorf("invalid container identity")
		}
		if p.NodeID != "" && !containerNodeIDPattern.MatchString(p.NodeID) {
			return fmt.Errorf("invalid container node ID")
		}
		if err := netfilter.ValidateDeviceLimits(map[string]netfilter.DeviceLimits{"192.168.0.1": p.QoS}); err != nil {
			return err
		}
	}
	return nil
}

var containerNodeIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func copyContainerSettings(source map[string]ContainerSettings) map[string]ContainerSettings {
	out := make(map[string]ContainerSettings, len(source))
	maps.Copy(out, source)
	return out
}
func remapContainerNodes(source map[string]ContainerSettings, removed map[string]bool, oldID, newID string) map[string]ContainerSettings {
	out := copyContainerSettings(source)
	for key, p := range out {
		if removed[p.NodeID] {
			p.NodeID = ""
		}
		if oldID != "" && p.NodeID == oldID {
			p.NodeID = newID
		}
		out[key] = p
	}
	return out
}

// Caller holds mu. Container identity is persisted; current IPs are never saved
// as routing identity. Unmanaged containers keep Docker's ordinary direct path.
func (s *Service) endpointPoliciesLocked() (map[string]string, map[string]netfilter.DeviceLimits, []netfilter.ContainerBinding, error) {
	routes := copyStrings(s.state.DeviceRoutes)
	limits := cloneLimits(s.state.DeviceLimits)
	bindings := []netfilter.ContainerBinding{}
	for _, c := range s.containers {
		p, configured := s.state.ContainerSettings[c.Key]
		if !configured || !c.Supported || (!p.Proxy && p.QoS == (netfilter.DeviceLimits{})) {
			continue
		}
		for _, b := range c.Bindings {
			if _, ok := s.state.DeviceRoutes[b.IP]; ok {
				return nil, nil, nil, fmt.Errorf("container IP %s conflicts with a device routing policy", b.IP)
			}
			if _, ok := s.state.DeviceLimits[b.IP]; ok {
				return nil, nil, nil, fmt.Errorf("container IP %s conflicts with a device limit", b.IP)
			}
			if p.Proxy {
				routes[b.IP] = p.NodeID
			}
			if p.QoS != (netfilter.DeviceLimits{}) {
				limits[b.IP] = p.QoS
			}
			bindings = append(bindings, netfilter.ContainerBinding{IP: b.IP, Bridge: b.Bridge, Owner: c.Key, Proxy: p.Proxy})
		}
	}
	if len(bindings) > 256 {
		return nil, nil, nil, fmt.Errorf("at most 256 managed container endpoints are supported")
	}
	if err := netfilter.ValidateDeviceLimits(limits); err != nil {
		return nil, nil, nil, err
	}
	return routes, limits, bindings, nil
}
func (s *Service) configureContainerBindings() error {
	s.mu.RLock()
	_, _, bindings, err := s.endpointPoliciesLocked()
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if fw, ok := s.cfg.Firewall.(interface {
		ConfigureContainers([]netfilter.ContainerBinding) error
	}); ok {
		return fw.ConfigureContainers(bindings)
	}
	if len(bindings) > 0 {
		return fmt.Errorf("firewall does not support Docker containers")
	}
	return nil
}
func proxyBindings(bindings []netfilter.ContainerBinding) []netfilter.ContainerBinding {
	out := []netfilter.ContainerBinding{}
	for _, b := range bindings {
		if b.Proxy {
			out = append(out, b)
		}
	}
	return out
}

// Network I/O precedes opMu; only applying the discovered snapshot serializes
// with engine transitions. Failed discovery keeps the last good snapshot.
func (s *Service) RefreshContainers(ctx context.Context) error {
	if s.cfg.Docker == nil {
		return fmt.Errorf("Docker discovery is disabled")
	}
	s.dockerMu.Lock()
	defer s.dockerMu.Unlock()
	items, err := s.cfg.Docker.List(ctx)
	if err != nil {
		s.mu.Lock()
		s.containerError = err.Error()
		s.mu.Unlock()
		return err
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if s.closing || s.refreshing {
		s.mu.Unlock()
		return ErrRefreshInProgress
	}
	previous := s.containers
	wasEnabled := s.proxyEnabled
	oldRoutes, oldLimits, oldBindings, _ := s.endpointPoliciesLocked()
	s.containers = items
	newRoutes, newLimits, newBindings, err := s.endpointPoliciesLocked()
	s.mu.Unlock()
	if err == nil && (!reflect.DeepEqual(oldBindings, newBindings) || !maps.Equal(oldRoutes, newRoutes) || !maps.Equal(oldLimits, newLimits)) {
		err = s.applyContainerPolicies(ctx, !maps.Equal(oldRoutes, newRoutes) || !reflect.DeepEqual(proxyBindings(oldBindings), proxyBindings(newBindings)))
	}
	s.mu.Lock()
	if err != nil {
		s.containers = previous
		s.containerError = err.Error()
	} else {
		s.containerError = ""
		s.containerUpdated = time.Now()
	}
	s.mu.Unlock()
	if err != nil {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return errors.Join(err, s.restoreContainerPolicies(cleanCtx, wasEnabled))
	}
	return nil
}
func (s *Service) applyContainerPolicies(ctx context.Context, reload bool) error {
	if err := s.configureEngineRouting(); err != nil {
		return err
	}
	if err := s.syncDeviceLimits(ctx); err != nil {
		return err
	}
	if reload {
		return s.reloadRunningLocked(ctx)
	}
	return nil
}

// Caller holds opMu. A failed reload may have removed interception; restore
// the previous running intent after reverting state/bindings, not just memory.
func (s *Service) restoreContainerPolicies(ctx context.Context, wasEnabled bool) error {
	err := s.configureEngineRouting()
	if err != nil {
		return err
	}
	if err = s.syncDeviceLimits(ctx); err != nil {
		return err
	}
	s.mu.RLock()
	enabled := s.proxyEnabled
	s.mu.RUnlock()
	if wasEnabled && !enabled {
		return s.enable(ctx)
	}
	return nil
}
func (s *Service) UpdateContainer(ctx context.Context, req ContainerUpdate) error {
	if !containerKeyPattern.MatchString(req.Key) || req.Proxy == nil && req.NodeID == nil && req.QoS == nil {
		return fmt.Errorf("%w: supply container key and proxy, node_id or qos", ErrInvalidInput)
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if s.closing || s.refreshing {
		s.mu.Unlock()
		return ErrRefreshInProgress
	}
	var found *docker.Container
	for i := range s.containers {
		if s.containers[i].Key == req.Key {
			found = &s.containers[i]
			break
		}
	}
	if found == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: container not found; refresh inventory", ErrInvalidInput)
	}
	if !found.Supported {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrInvalidInput, found.Reason)
	}
	if s.containerError != "" {
		s.mu.Unlock()
		return fmt.Errorf("%w: refresh Docker inventory before changing settings", ErrInvalidInput)
	}
	old := s.state.ContainerSettings
	wasEnabled := s.proxyEnabled
	p := old[req.Key]
	oldRoutes, _, oldBindings, _ := s.endpointPoliciesLocked()
	if req.NodeID != nil && *req.NodeID == "direct" {
		if req.Proxy != nil && *req.Proxy {
			s.mu.Unlock()
			return fmt.Errorf("%w: Direct cannot be combined with proxy=true", ErrInvalidInput)
		}
		p.Proxy = false
		p.NodeID = ""
	} else {
		if req.NodeID != nil {
			p.NodeID = *req.NodeID
			p.Proxy = true
		}
		// Accept legacy explicit proxy settings for existing API clients/backups.
		if req.Proxy != nil {
			p.Proxy = *req.Proxy
		}
	}
	if req.QoS != nil {
		p.QoS = *req.QoS
	}
	if p.NodeID != "" && (req.NodeID != nil || req.Proxy != nil && *req.Proxy) {
		r, err := s.cfg.Store.Get(p.NodeID)
		if err != nil || !r.Enabled || r.Node.ChainInternal {
			s.mu.Unlock()
			return fmt.Errorf("%w: choose an enabled visible configuration", ErrInvalidInput)
		}
	}
	if p == old[req.Key] {
		s.mu.Unlock()
		return nil
	}
	s.state.ContainerSettings = copyContainerSettings(old)
	if p == (ContainerSettings{}) {
		delete(s.state.ContainerSettings, req.Key)
	} else {
		s.state.ContainerSettings[req.Key] = p
	}
	err := validateContainerSettings(s.state.ContainerSettings)
	newRoutes, _, newBindings, policyErr := s.endpointPoliciesLocked()
	if err == nil {
		err = policyErr
	}
	if err != nil {
		s.state.ContainerSettings = old
		s.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if err = s.saveState(); err != nil {
		s.state.ContainerSettings = old
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	err = s.applyContainerPolicies(ctx, !maps.Equal(oldRoutes, newRoutes) || !reflect.DeepEqual(proxyBindings(oldBindings), proxyBindings(newBindings)))
	if err == nil {
		return nil
	}
	s.mu.Lock()
	s.state.ContainerSettings = old
	saveErr := s.saveState()
	s.mu.Unlock()
	cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return errors.Join(fmt.Errorf("container settings were not applied: %w", err), saveErr, s.restoreContainerPolicies(cleanCtx, wasEnabled))
}
func (s *Service) startContainerDiscovery() {
	s.mu.Lock()
	if s.containerStarted || s.closing || s.cfg.Docker == nil {
		s.mu.Unlock()
		return
	}
	s.containerStarted = true
	s.jobs.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.jobs.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.jobCtx.Done():
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(s.jobCtx, 45*time.Second)
				err := s.RefreshContainers(ctx)
				cancel()
				if err != nil && !errors.Is(err, ErrRefreshInProgress) && s.jobCtx.Err() == nil {
					s.log.Debug("container discovery", "err", err)
				}
			}
		}
	}()
}
func (h *handlers) containers(w http.ResponseWriter, r *http.Request) {
	s := h.svc
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		type entry struct {
			docker.Container
			Settings ContainerSettings `json:"settings"`
		}
		entries := make([]entry, 0, len(s.containers))
		for _, c := range s.containers {
			entries = append(entries, entry{c, s.state.ContainerSettings[c.Key]})
		}
		updated, errText, enabled := s.containerUpdated, s.containerError, s.cfg.Docker != nil
		s.mu.RUnlock()
		writeJSON(w, 200, map[string]any{"containers": entries, "enabled": enabled, "updated_at": updated, "error": errText})
	case http.MethodPut:
		var req ContainerUpdate
		if err := decodeBody(r, &req); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		if err := s.UpdateContainer(r.Context(), req); err != nil {
			h.dashboardError(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"message": "Container settings saved"})
	default:
		methodsNotAllowed(w, "GET, PUT")
	}
}
func (h *handlers) refreshContainers(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.RefreshContainers(r.Context()); err != nil {
		h.dashboardError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"message": "Container inventory refreshed"})
}
