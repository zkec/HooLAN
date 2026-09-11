package store

// ReplaceRecords commits a complete inventory in one atomic file replacement.
// Services serialize inventory mutations; on persistence failure memory rolls back.
func (s *Store) ReplaceRecords(records []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.records
	next := make(map[string]*Record, len(records))
	for _, r := range records {
		copy := r
		next[r.ID] = &copy
	}
	s.records = next
	if err := s.persist(); err != nil {
		s.records = old
		return err
	}
	return nil
}
