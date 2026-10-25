package api

import (
	"context"
	"time"
)

const deviceOnlineWindow = time.Minute
const maxDevicePresence = 4096

type DevicePresence struct {
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"last_seen,omitempty"`
}
type deviceNeighbors interface {
	DeviceNeighbors(context.Context) (map[string]bool, error)
}

// Caller holds mu. Presence is runtime-only; old state cannot make a device
// appear online after service restart. Bound discovery independently of usage.
func (s *Service) noteDeviceSeenLocked(ip string, now time.Time) {
	if s.deviceSeen == nil {
		s.deviceSeen = map[string]time.Time{}
	}
	old, known := s.deviceSeen[ip]
	if !known && len(s.deviceSeen) >= maxDevicePresence {
		return
	}
	if !known || now.After(old) {
		s.deviceSeen[ip] = now
	}
}
func (s *Service) pruneDevicePresenceLocked(now time.Time) {
	for ip, seen := range s.deviceSeen {
		if seen.IsZero() || now.Sub(seen) > 24*time.Hour {
			delete(s.deviceSeen, ip)
		}
	}
}
func (s *Service) refreshDevicePresence(ctx context.Context) {
	reader, ok := s.cfg.Firewall.(deviceNeighbors)
	if !ok {
		return
	}
	neighbors, err := reader.DeviceNeighbors(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devicePresenceError = ""
	if err != nil {
		s.devicePresenceError = err.Error()
		return
	}
	now := time.Now().UTC()
	s.pruneDevicePresenceLocked(now)
	for ip, reachable := range neighbors {
		// Defend the source boundary as well as the production reader.
		normalized, err := deviceIP(ip)
		if err != nil || normalized != ip {
			continue
		}
		seen := time.Time{}
		if reachable {
			seen = now
		}
		s.noteDeviceSeenLocked(ip, seen)
	}
}
func (s *Service) devicePresenceLocked(now time.Time) map[string]DevicePresence {
	result := make(map[string]DevicePresence, len(s.deviceSeen))
	for ip, seen := range s.deviceSeen {
		result[ip] = DevicePresence{Online: !seen.IsZero() && !seen.After(now) && now.Sub(seen) <= deviceOnlineWindow, LastSeen: seen}
	}
	return result
}
func (s *Service) startDevicePresence() {
	if _, ok := s.cfg.Firewall.(deviceNeighbors); !ok {
		return
	}
	s.mu.Lock()
	if s.presenceStarted || s.closing {
		s.mu.Unlock()
		return
	}
	s.presenceStarted = true
	s.jobs.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.jobs.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			ctx, cancel := context.WithTimeout(s.jobCtx, 2*time.Second)
			s.refreshDevicePresence(ctx)
			cancel()
			select {
			case <-s.jobCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
