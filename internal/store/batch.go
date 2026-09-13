package store

import (
	"fmt"
	"time"
)

// ReplaceRecords commits a complete inventory in one atomic file replacement.
// Services serialize inventory mutations; on persistence failure memory rolls back.
func (s *Store) ReplaceRecords(records []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.records
	next := make(map[string]*Record, len(records))
	for _, r := range records {
		copy := cloneRecord(r)
		next[r.ID] = &copy
	}
	s.records = next
	if err := s.persist(); err != nil {
		s.records = old
		return err
	}
	return nil
}

// Measurement is one completed probe. A sweep writes the store once, reducing
// SD-card fsyncs and keeping readers from seeing partially updated health.
type Measurement struct {
	ID      string
	Latency time.Duration
	Err     error
}

func (s *Store) RecordMeasurements(results []Measurement) error {
	if len(results) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.records
	next := make(map[string]*Record, len(old))
	for id, r := range old {
		next[id] = r
	}
	now := s.now()
	for _, result := range results {
		current, ok := next[result.ID]
		if !ok {
			return fmt.Errorf("%w: %s", ErrNotFound, result.ID)
		}
		r := cloneRecord(*current)
		r.LastCheckedAt, r.UpdatedAt = now, now
		if result.Err != nil {
			r.LastLatencyMS = LatencyUnmeasured
			r.LastError = result.Err.Error()
			r.ConsecutiveFailures++
		} else {
			r.LastLatencyMS = int(result.Latency.Milliseconds())
			if r.LastLatencyMS < 0 {
				r.LastLatencyMS = 0
			}
			r.LastError = ""
			r.ConsecutiveFailures = 0
		}
		next[result.ID] = &r
	}
	s.records = next
	if err := s.persist(); err != nil {
		s.records = old
		return err
	}
	return nil
}
