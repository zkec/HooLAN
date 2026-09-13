// Package store persists proxy nodes and their measured health to a single
// JSON file.
//
// Why JSON and not SQLite: this store holds tens to low-hundreds of rows, is
// written on subscription refresh and after latency sweeps, and is read on
// startup. SQLite would add a cgo dependency (or a pure-Go driver plus its
// own quirks) to a bare-metal Pi build for no gain at this size. The whole
// dataset fits comfortably in memory, so reads never touch disk.
//
// Durability model: every mutation rewrites the whole file via temp-file +
// fsync + atomic rename, so a power loss mid-write leaves the previous
// generation intact rather than a truncated file. On an SD card that failure
// mode is not hypothetical.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"proxy-manager/internal/subscription"
)

// schemaVersion is bumped when the on-disk shape changes incompatibly.
// Load refuses a file from the future rather than silently dropping fields.
const schemaVersion = 1

// ErrNotFound is returned by lookups that match no record.
var ErrNotFound = errors.New("store: node not found")

// Record wraps a parsed node with the metadata the store owns.
//
// The node itself comes from the subscription; everything else is measured or
// assigned locally and must survive a subscription refresh that re-delivers
// the same node.
type Record struct {
	ChainID  string `json:"chain_id,omitempty"`
	DetourID string `json:"detour_id,omitempty"`
	// ID is a stable content-derived identity, NOT the tag. Providers rename
	// nodes freely ("US-1" becoming "🇺🇸 US-1" between refreshes), which would
	// otherwise orphan the latency history. See NodeID.
	ID   string            `json:"id"`
	Node subscription.Node `json:"node"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// LastLatencyMS is the most recent successful measurement in
	// milliseconds. -1 means "never measured or last attempt failed", which is
	// distinct from 0 (a measurement that came back impossibly fast).
	LastLatencyMS int `json:"last_latency_ms"`
	// LastCheckedAt is when the latency probe last ran, success or failure.
	// The zero value means "never probed". Deliberately not tagged omitzero:
	// that option requires Go 1.24+ and is silently ignored by older
	// toolchains, and omitempty has never worked for time.Time. An always-
	// emitted zero timestamp is portable; a tag that changes behaviour with
	// the build toolchain is not.
	LastCheckedAt time.Time `json:"last_checked_at"`
	// LastError is the failure reason from the most recent probe, empty on
	// success. Kept so the UI can show why a node is dark.
	LastError string `json:"last_error,omitempty"`

	// ConsecutiveFailures drives eviction/deprioritisation policy upstream.
	ConsecutiveFailures int `json:"consecutive_failures"`

	// Enabled is operator intent: a disabled node is kept (with its history)
	// but excluded from generated configs.
	Enabled bool `json:"enabled"`
}

// LatencyUnmeasured is the sentinel for "no successful measurement".
const LatencyUnmeasured = -1

// Healthy reports whether the record has a usable recent measurement.
func (r Record) Healthy() bool {
	return r.Enabled && r.LastLatencyMS >= 0
}

// file is the on-disk document.
type file struct {
	Version int       `json:"version"`
	SavedAt time.Time `json:"saved_at"`
	Records []Record  `json:"records"`
}

// Store is a thread-safe persistent node store.
//
// A single mutex guards both the in-memory map and the file: writes are
// infrequent (subscription refresh, latency sweep) and the file is small, so
// finer-grained locking would add risk without measurable benefit.
type Store struct {
	path string
	// now is injectable so tests get deterministic timestamps.
	now func() time.Time

	mu      sync.RWMutex
	records map[string]*Record
}

// Option configures a Store.
type Option func(*Store)

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// Open loads the store at path, creating an empty one if the file is absent.
func Open(path string, opts ...Option) (*Store, error) {
	s := &Store{
		path:    path,
		now:     time.Now,
		records: make(map[string]*Record),
	}
	for _, o := range opts {
		o(s)
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the backing file path.
func (s *Store) Path() string { return s.path }

func (s *Store) load() error {
	buf, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // fresh store
	}
	if err != nil {
		return fmt.Errorf("store: read %s: %w", s.path, err)
	}
	if len(buf) == 0 {
		return nil // treat a zero-length file as empty rather than corrupt
	}
	var doc file
	if err := json.Unmarshal(buf, &doc); err != nil {
		return fmt.Errorf("store: parse %s: %w", s.path, err)
	}
	if doc.Version > schemaVersion {
		return fmt.Errorf("store: file schema v%d is newer than supported v%d",
			doc.Version, schemaVersion)
	}
	for i := range doc.Records {
		r := doc.Records[i]
		if r.ID == "" {
			r.ID = NodeID(r.Node) // heal records written before IDs existed
		}
		s.records[r.ID] = &r
	}
	return nil
}

// persist writes the whole store atomically. Caller must hold s.mu.
func (s *Store) persist() error {
	doc := file{Version: schemaVersion, SavedAt: s.now()}
	doc.Records = make([]Record, 0, len(s.records))
	for _, r := range s.records {
		doc.Records = append(doc.Records, *r)
	}
	// Stable order keeps diffs readable and makes the file byte-comparable
	// between saves when nothing changed.
	sort.Slice(doc.Records, func(i, j int) bool { return doc.Records[i].ID < doc.Records[j].ID })

	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal: %w", err)
	}
	buf = append(buf, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("store: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".nodes-*.json")
	if err != nil {
		return fmt.Errorf("store: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	// 0600: records hold UUIDs and passwords.
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("store: chmod: %w", err)
	}
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("store: rename: %w", err)
	}
	return nil
}

// Save flushes the current state to disk. Mutating methods already persist, so
// this is only needed after direct manipulation via Update.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persist()
}

// UpsertNodes merges a freshly parsed subscription into the store.
//
// Existing records keep their CreatedAt and latency history; their node payload
// is refreshed in case the provider rotated a credential or moved a port.
// Returns the number added and updated.
//
// Nodes absent from the incoming set are NOT deleted -- a provider serving a
// truncated list during an outage would otherwise wipe the store. Use Prune for
// deliberate removal.
func (s *Store) UpsertNodes(nodes []subscription.Node) (added, updated int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for _, n := range nodes {
		id := NodeID(n)
		if existing, ok := s.records[id]; ok {
			existing.Node = n
			existing.UpdatedAt = now
			updated++
			continue
		}
		s.records[id] = &Record{
			ID:            id,
			Node:          n,
			CreatedAt:     now,
			UpdatedAt:     now,
			LastLatencyMS: LatencyUnmeasured,
			Enabled:       true,
		}
		added++
	}
	if err := s.persist(); err != nil {
		return added, updated, err
	}
	return added, updated, nil
}

// RecordLatency stores a successful measurement and clears the failure state.
func (s *Store) RecordLatency(id string, latency time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	now := s.now()
	ms := int(latency.Milliseconds())
	if ms < 0 {
		ms = 0
	}
	r.LastLatencyMS = ms
	r.LastCheckedAt = now
	r.UpdatedAt = now
	r.LastError = ""
	r.ConsecutiveFailures = 0
	return s.persist()
}

// RecordFailure marks a failed probe. The previous latency is cleared to the
// unmeasured sentinel so a stale-but-fast reading cannot keep a dead node at
// the top of a sorted list.
func (s *Store) RecordFailure(id string, cause error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	now := s.now()
	r.LastLatencyMS = LatencyUnmeasured
	r.LastCheckedAt = now
	r.UpdatedAt = now
	r.ConsecutiveFailures++
	if cause != nil {
		r.LastError = cause.Error()
	} else {
		r.LastError = "unknown failure"
	}
	return s.persist()
}

// SetEnabled toggles operator intent for a node.
func (s *Store) SetEnabled(id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	r.Enabled = enabled
	r.UpdatedAt = s.now()
	return s.persist()
}

// SetDetour sets (or clears, with an empty target) the chain hop for a node.
// The target is given as a node ID, not a tag, and is resolved to that node's
// current tag -- tags are provider-controlled and change between refreshes,
// so storing one as a chain reference would silently rot.
func (s *Store) SetDetour(id, detourID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	old := *r
	if detourID != "" {
		target, ok := s.records[detourID]
		if !ok {
			return fmt.Errorf("%w: detour target", ErrNotFound)
		}
		if !target.Enabled {
			return errors.New("store: detour target is disabled")
		}
		seen := map[string]bool{id: true}
		for next := detourID; next != ""; {
			if seen[next] {
				return errors.New("store: chain cycle")
			}
			seen[next] = true
			hop, ok := s.records[next]
			if !ok {
				return errors.New("store: missing chain hop")
			}
			next = hop.DetourID
		}
		r.Node.Detour = target.Node.Tag
	} else {
		r.Node.Detour = ""
	}
	r.DetourID = detourID
	r.UpdatedAt = s.now()
	if err := s.persist(); err != nil {
		*r = old
		return err
	}
	return nil
}

// Update applies fn to the record under lock, then persists. Use for edits the
// typed helpers do not cover.
func (s *Store) Update(id string, fn func(*Record) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err := fn(r); err != nil {
		return err
	}
	r.UpdatedAt = s.now()
	return s.persist()
}

// Get returns a copy of one record.
func (s *Store) Get(id string) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return Record{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return *r, nil
}

// All returns copies of every record, ordered by ID for stable output.
// Copies, not pointers: callers must not be able to mutate store state without
// going through a method that persists.
func (s *Store) All() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Len reports the record count.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// EnabledNodes returns the nodes to render into a config: enabled only,
// ordered fastest-measured first, with unmeasured nodes last.
//
// Unmeasured nodes sort last rather than first so a fresh subscription cannot
// push a never-tested node to the head of a urltest group before any probe has
// run.
func (s *Store) EnabledNodes() []subscription.Node {
	return EnabledRecords(s.All())
}

// EnabledRecords renders an uncommitted snapshot for validation before writes.
func EnabledRecords(recs []Record) []subscription.Node {
	filtered := make([]Record, 0, len(recs))
	for _, r := range recs {
		if r.Enabled {
			filtered = append(filtered, r)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		li, lj := filtered[i].LastLatencyMS, filtered[j].LastLatencyMS
		switch {
		case li < 0 && lj < 0:
			return filtered[i].ID < filtered[j].ID
		case li < 0:
			return false
		case lj < 0:
			return true
		case li != lj:
			return li < lj
		default:
			return filtered[i].ID < filtered[j].ID
		}
	})
	out := make([]subscription.Node, 0, len(filtered))
	for _, r := range filtered {
		out = append(out, r.Node)
	}
	subscription.DedupeTags(out)
	tags := map[string]string{}
	for _, n := range out {
		tags[NodeID(n)] = n.Tag
	}
	for i, r := range filtered {
		if r.DetourID != "" {
			tag, ok := tags[r.DetourID]
			if !ok {
				tag = "missing-detour-" + r.DetourID
			}
			out[i].Detour = tag
		}
	}
	ResolveBalanceMembers(out)
	return out
}

// Prune deletes records whose ID is not in keep. Returns the number removed.
// Call only when the incoming subscription is known-good.
func (s *Store) Prune(keep map[string]bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id := range s.records {
		if !keep[id] {
			delete(s.records, id)
			removed++
		}
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, s.persist()
}

// Delete removes one record.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	old := s.records[id]
	delete(s.records, id)
	if err := s.persist(); err != nil {
		s.records[id] = old
		return err
	}
	return nil
}
