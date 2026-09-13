package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"proxy-manager/internal/engine"
	"proxy-manager/internal/netfilter"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// DeviceUpdate changes only the supplied fields. Empty strings clear them.
type DeviceUpdate struct {
	IP         string                  `json:"ip"`
	QoS        *netfilter.DeviceLimits `json:"qos,omitempty"`
	SpeedLimit *float64                `json:"speed_limit_mbps,omitempty"`
	Alias      *string                 `json:"alias,omitempty"`
	NodeID     *string                 `json:"node_id,omitempty"`
}

func deviceIP(value string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" || !addr.Unmap().Is4() || !addr.IsPrivate() {
		return "", fmt.Errorf("%w: device IP must be a private IPv4 host address (the gateway intercepts IPv4)", ErrInvalidInput)
	}
	return addr.Unmap().String(), nil
}
func copyStrings(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for k, v := range source {
		result[k] = v
	}
	return result
}
func withoutRoutes(source map[string]string, removed map[string]bool) map[string]string {
	result := copyStrings(source)
	for ip, id := range result {
		if removed[id] {
			delete(result, ip)
		}
	}
	return result
}

// UpdateDevice serializes route changes with inventory and engine operations.
// Aliases alone are persisted without restarting the engine.
func (s *Service) UpdateDevice(ctx context.Context, req DeviceUpdate) error {
	ip, err := deviceIP(req.IP)
	if err != nil {
		return err
	}
	if req.Alias == nil && req.NodeID == nil && req.SpeedLimit == nil && req.QoS == nil {
		return fmt.Errorf("%w: supply alias, node_id or qos", ErrInvalidInput)
	}
	if req.SpeedLimit != nil && req.QoS != nil {
		return fmt.Errorf("%w: supply qos or legacy speed_limit_mbps, not both", ErrInvalidInput)
	}
	if req.SpeedLimit != nil {
		limits := netfilter.UniformLimits(*req.SpeedLimit)
		req.QoS = &limits
	}
	if req.QoS != nil {
		if err := netfilter.ValidateDeviceLimits(map[string]netfilter.DeviceLimits{ip: *req.QoS}); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	alias := ""
	if req.Alias != nil {
		alias = strings.TrimSpace(*req.Alias)
		if !utf8.ValidString(alias) || utf8.RuneCountInString(alias) > 80 || strings.IndexFunc(alias, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: device name must contain at most 80 characters without control characters", ErrInvalidInput)
		}
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	busy := s.closing || s.refreshing
	s.mu.RUnlock()
	if busy {
		return ErrRefreshInProgress
	}
	if req.NodeID != nil && *req.NodeID != "" && *req.NodeID != engine.DefaultDirect {
		record, err := s.cfg.Store.Get(*req.NodeID)
		if err != nil {
			return err
		}
		if !record.Enabled || record.Node.ChainInternal {
			return fmt.Errorf("%w: choose an enabled visible configuration", ErrInvalidInput)
		}
	}
	s.mu.Lock()
	oldAliases, oldRoutes := s.state.DeviceAliases, s.state.DeviceRoutes
	oldLimits := s.state.DeviceLimits
	limitChanged := req.QoS != nil && oldLimits[ip] != *req.QoS
	if limitChanged {
		if _, ok := s.cfg.Firewall.(deviceLimiter); !ok {
			s.mu.Unlock()
			return errors.New("firewall does not support device limits")
		}
	}
	routeChanged := req.NodeID != nil && oldRoutes[ip] != *req.NodeID
	if routeChanged {
		if _, ok := s.cfg.Engine.(interface{ ConfigureDeviceRoutes(map[string]string) }); !ok {
			s.mu.Unlock()
			return errors.New("engine does not support device routing")
		}
	}
	s.state.DeviceAliases, s.state.DeviceRoutes = copyStrings(oldAliases), copyStrings(oldRoutes)
	if req.Alias != nil {
		if alias == "" {
			delete(s.state.DeviceAliases, ip)
		} else {
			s.state.DeviceAliases[ip] = alias
		}
	}
	if req.NodeID != nil {
		if *req.NodeID == "" {
			delete(s.state.DeviceRoutes, ip)
		} else {
			s.state.DeviceRoutes[ip] = *req.NodeID
		}
	}
	s.state.DeviceLimits = cloneLimits(oldLimits)
	if req.QoS != nil {
		if *req.QoS == (netfilter.DeviceLimits{}) {
			delete(s.state.DeviceLimits, ip)
		} else {
			s.state.DeviceLimits[ip] = *req.QoS
		}
	}
	if err := netfilter.ValidateDeviceLimits(s.state.DeviceLimits); err != nil {
		s.state.DeviceAliases, s.state.DeviceRoutes, s.state.DeviceLimits = oldAliases, oldRoutes, oldLimits
		s.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if err := s.saveState(); err != nil {
		s.state.DeviceAliases, s.state.DeviceRoutes, s.state.DeviceLimits = oldAliases, oldRoutes, oldLimits
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	if limitChanged {
		err = s.syncDeviceLimits(ctx)
	}
	if err == nil && routeChanged {
		if err = s.configureEngineRouting(); err == nil {
			err = s.reloadRunningLocked(ctx)
		}
	}
	if err == nil {
		return nil
	}
	s.mu.Lock()
	s.state.DeviceAliases, s.state.DeviceRoutes, s.state.DeviceLimits = oldAliases, oldRoutes, oldLimits
	saveErr := s.saveState()
	s.mu.Unlock()
	configureErr := s.configureEngineRouting()
	var limitErr error
	if limitChanged {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		limitErr = s.syncDeviceLimits(cleanCtx)
	}
	return errors.Join(fmt.Errorf("device settings were not applied: %w", err), saveErr, configureErr, limitErr)
}

func (h *handlers) updateDevice(w http.ResponseWriter, r *http.Request) {
	var req DeviceUpdate
	if err := decodeBody(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err := h.svc.UpdateDevice(r.Context(), req); err != nil {
		h.dashboardError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"message": "Device settings saved"})
}

type deviceLimiter interface {
	ApplyDeviceLimits(context.Context, map[string]netfilter.DeviceLimits) error
}

func cloneLimits(source map[string]netfilter.DeviceLimits) map[string]netfilter.DeviceLimits {
	result := make(map[string]netfilter.DeviceLimits, len(source))
	for k, v := range source {
		result[k] = v
	}
	return result
}
func (s *Service) configureDeviceLimits() error {
	s.mu.RLock()
	limits := cloneLimits(s.state.DeviceLimits)
	s.mu.RUnlock()
	if err := netfilter.ValidateDeviceLimits(limits); err != nil {
		return err
	}
	if configurable, ok := s.cfg.Firewall.(interface {
		ConfigureDeviceLimits(map[string]netfilter.DeviceLimits)
	}); ok {
		configurable.ConfigureDeviceLimits(limits)
	}
	return nil
}
func (s *Service) syncDeviceLimits(ctx context.Context) error {
	s.mu.RLock()
	limits := cloneLimits(s.state.DeviceLimits)
	s.mu.RUnlock()
	if limiter, ok := s.cfg.Firewall.(deviceLimiter); ok {
		return limiter.ApplyDeviceLimits(ctx, limits)
	}
	if len(limits) > 0 {
		return errors.New("firewall does not support device limits")
	}
	return nil
}
