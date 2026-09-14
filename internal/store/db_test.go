package store

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"hoolan/internal/subscription"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func testNode(tag, server string) subscription.Node {
	return subscription.Node{
		Protocol: subscription.ProtoVLESS, Tag: tag, Server: server, Port: 443,
		UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Security: subscription.SecTLS,
		SNI: server, Transport: subscription.TransportTCP,
	}
}

func TestUpsertAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "nodes.json")
	t0 := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	s, err := Open(path, WithClock(fixedClock(t0)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	added, updated, err := s.UpsertNodes([]subscription.Node{
		testNode("US", "a.example"), testNode("JP", "b.example"),
	})
	if err != nil {
		t.Fatalf("UpsertNodes: %v", err)
	}
	if added != 2 || updated != 0 {
		t.Errorf("added=%d updated=%d, want 2/0", added, updated)
	}

	// 0600: records hold UUIDs and passwords.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}

	// Reopen: state must survive.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if s2.Len() != 2 {
		t.Fatalf("after reopen Len = %d, want 2", s2.Len())
	}
	for _, r := range s2.All() {
		if !r.CreatedAt.Equal(t0) {
			t.Errorf("%s CreatedAt = %v, want %v", r.Node.Tag, r.CreatedAt, t0)
		}
		if r.LastLatencyMS != LatencyUnmeasured {
			t.Errorf("%s fresh latency = %d, want %d", r.Node.Tag, r.LastLatencyMS, LatencyUnmeasured)
		}
		if !r.Enabled {
			t.Errorf("%s not enabled by default", r.Node.Tag)
		}
	}
}

// A provider renaming a node must be an update, not a new row -- otherwise the
// store grows without bound and every rename discards latency history.
func TestRenameIsUpdateNotInsert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	t0 := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	s, err := Open(path, WithClock(fixedClock(t0)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertNodes([]subscription.Node{testNode("US", "a.example")}); err != nil {
		t.Fatal(err)
	}
	id := s.All()[0].ID
	if err := s.RecordLatency(id, 123*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// Same server/credential, new display tag.
	added, updated, err := s.UpsertNodes([]subscription.Node{testNode("🇺🇸 US | 2x", "a.example")})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || updated != 1 {
		t.Errorf("rename: added=%d updated=%d, want 0/1", added, updated)
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d after rename, want 1", s.Len())
	}
	r := s.All()[0]
	if r.LastLatencyMS != 123 {
		t.Errorf("latency history lost on rename: %d", r.LastLatencyMS)
	}
	if r.Node.Tag != "🇺🇸 US | 2x" {
		t.Errorf("tag not refreshed: %q", r.Node.Tag)
	}
	if !r.CreatedAt.Equal(t0) {
		t.Errorf("CreatedAt changed on update: %v", r.CreatedAt)
	}
}

func TestRecordLatencyAndFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertNodes([]subscription.Node{testNode("US", "a.example")}); err != nil {
		t.Fatal(err)
	}
	id := s.All()[0].ID

	if err := s.RecordLatency(id, 250*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	r, _ := s.Get(id)
	if r.LastLatencyMS != 250 {
		t.Errorf("latency = %d, want 250", r.LastLatencyMS)
	}
	if !r.Healthy() {
		t.Error("record should be healthy after a successful probe")
	}
	if r.LastCheckedAt.IsZero() {
		t.Error("LastCheckedAt not set")
	}

	// A failure must clear the stale-but-fast reading, or a dead node stays at
	// the top of a latency-sorted list forever.
	if err := s.RecordFailure(id, errors.New("i/o timeout")); err != nil {
		t.Fatal(err)
	}
	r, _ = s.Get(id)
	if r.LastLatencyMS != LatencyUnmeasured {
		t.Errorf("latency = %d after failure, want %d", r.LastLatencyMS, LatencyUnmeasured)
	}
	if r.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", r.ConsecutiveFailures)
	}
	if r.LastError != "i/o timeout" {
		t.Errorf("LastError = %q", r.LastError)
	}
	if r.Healthy() {
		t.Error("record must not be healthy after a failure")
	}

	// A later success clears the failure counter.
	if err := s.RecordLatency(id, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	r, _ = s.Get(id)
	if r.ConsecutiveFailures != 0 || r.LastError != "" {
		t.Errorf("failure state not cleared: n=%d err=%q", r.ConsecutiveFailures, r.LastError)
	}
}

func TestEnabledNodesOrdering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []subscription.Node{
		testNode("slow", "slow.example"),
		testNode("fast", "fast.example"),
		testNode("untested", "untested.example"),
		testNode("off", "off.example"),
	}
	if _, _, err := s.UpsertNodes(nodes); err != nil {
		t.Fatal(err)
	}
	byTag := map[string]string{}
	for _, r := range s.All() {
		byTag[r.Node.Tag] = r.ID
	}
	if err := s.RecordLatency(byTag["slow"], 400*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordLatency(byTag["fast"], 80*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnabled(byTag["off"], false); err != nil {
		t.Fatal(err)
	}

	got := s.EnabledNodes()
	if len(got) != 3 {
		t.Fatalf("got %d enabled nodes, want 3", len(got))
	}
	if got[0].Tag != "fast" || got[1].Tag != "slow" {
		t.Errorf("order = %q,%q,... want fast,slow first", got[0].Tag, got[1].Tag)
	}
	// Unmeasured last: a never-probed node must not head a urltest group.
	if got[2].Tag != "untested" {
		t.Errorf("unmeasured node should sort last, got %q", got[2].Tag)
	}
	for _, n := range got {
		if n.Tag == "off" {
			t.Error("disabled node leaked into EnabledNodes")
		}
	}
}

func TestSetDetourUsesIDsNotTags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertNodes([]subscription.Node{
		testNode("exit", "e.example"), testNode("hop", "h.example"),
	}); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, r := range s.All() {
		ids[r.Node.Tag] = r.ID
	}
	if err := s.SetDetour(ids["exit"], ids["hop"]); err != nil {
		t.Fatalf("SetDetour: %v", err)
	}
	r, _ := s.Get(ids["exit"])
	if r.Node.Detour != "hop" {
		t.Errorf("Detour = %q, want hop", r.Node.Detour)
	}
	// Self-detour must be refused: sing-box run FATALs on it.
	if err := s.SetDetour(ids["exit"], ids["exit"]); err == nil {
		t.Error("expected self-detour to be refused")
	}
	// Clearing works.
	if err := s.SetDetour(ids["exit"], ""); err != nil {
		t.Fatal(err)
	}
	r, _ = s.Get(ids["exit"])
	if r.Node.Detour != "" {
		t.Errorf("Detour = %q after clear", r.Node.Detour)
	}
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(missing) err = %v, want ErrNotFound", err)
	}
}

// Detour is local intent and must not change a node's identity, or setting a
// chain would orphan the node's latency history.
func TestDetourDoesNotChangeID(t *testing.T) {
	n := testNode("exit", "e.example")
	before := NodeID(n)
	n.Detour = "hop"
	if after := NodeID(n); after != before {
		t.Errorf("NodeID changed when Detour was set: %s -> %s", before, after)
	}
	// Tag must not affect identity either.
	n2 := testNode("renamed", "e.example")
	if NodeID(n2) != before {
		t.Error("NodeID changed on rename")
	}
	// A different server must produce a different ID.
	n3 := testNode("exit", "other.example")
	if NodeID(n3) == before {
		t.Error("different servers collided onto one ID")
	}
}

// Length-prefixed hashing: ("ab","c") must not collide with ("a","bc").
func TestNodeIDNoFieldBoundaryCollision(t *testing.T) {
	a := subscription.Node{Protocol: subscription.ProtoTrojan, Server: "ab", Port: 1, Password: "c"}
	b := subscription.Node{Protocol: subscription.ProtoTrojan, Server: "a", Port: 1, Password: "bc"}
	if NodeID(a) == NodeID(b) {
		t.Error("field boundary collision in NodeID")
	}
}

func TestPruneAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []subscription.Node{testNode("a", "a.example"), testNode("b", "b.example")}
	if _, _, err := s.UpsertNodes(nodes); err != nil {
		t.Fatal(err)
	}
	// A truncated subscription must not silently wipe the store: Upsert never
	// deletes, only Prune does.
	if _, _, err := s.UpsertNodes(nodes[:1]); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 {
		t.Errorf("Upsert with a short list deleted rows: Len = %d", s.Len())
	}

	removed, err := s.Prune(KeepSet(nodes[:1]))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 || s.Len() != 1 {
		t.Errorf("Prune removed=%d Len=%d, want 1/1", removed, s.Len())
	}
	id := s.All()[0].ID
	if err := s.Delete(id); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d after Delete", s.Len())
	}
	if err := s.Delete(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("double Delete err = %v, want ErrNotFound", err)
	}
}

func TestOpenMissingAndEmptyFile(t *testing.T) {
	dir := t.TempDir()
	// Absent file => empty store, not an error.
	s, err := Open(filepath.Join(dir, "absent.json"))
	if err != nil {
		t.Fatalf("Open(absent): %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d", s.Len())
	}
	// Zero-length file (an interrupted first write) must not be fatal.
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(empty); err != nil {
		t.Errorf("Open(empty): %v", err)
	}
	// A file from a future schema must be refused, not silently downgraded.
	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(future, []byte(`{"version":99,"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(future); err == nil {
		t.Error("expected a schema-version error")
	}
}

func TestConcurrentAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var nodes []subscription.Node
	for i := 0; i < 10; i++ {
		nodes = append(nodes, testNode(string(rune('a'+i)), string(rune('a'+i))+".example"))
	}
	if _, _, err := s.UpsertNodes(nodes); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, 10)
	for _, r := range s.All() {
		ids = append(ids, r.ID)
	}

	// Hammer reads and writes together; -race makes this meaningful.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = s.RecordLatency(ids[i], time.Duration(i+1)*time.Millisecond)
		}(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.All()
			_ = s.EnabledNodes()
			_ = s.Len()
		}()
	}
	wg.Wait()

	// Every write must be durable and readable after reopen.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if s2.Len() != 10 {
		t.Errorf("Len = %d after concurrent writes, want 10", s2.Len())
	}
	for _, r := range s2.All() {
		if r.LastLatencyMS < 0 {
			t.Errorf("%s lost its measurement", r.Node.Tag)
		}
	}
}

func TestUpdateHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertNodes([]subscription.Node{testNode("a", "a.example")}); err != nil {
		t.Fatal(err)
	}
	id := s.All()[0].ID
	if err := s.Update(id, func(r *Record) error {
		r.ConsecutiveFailures = 7
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r, _ := s.Get(id)
	if r.ConsecutiveFailures != 7 {
		t.Errorf("ConsecutiveFailures = %d", r.ConsecutiveFailures)
	}
	// An error from fn must abort the write.
	sentinel := errors.New("nope")
	if err := s.Update(id, func(r *Record) error {
		r.ConsecutiveFailures = 99
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Errorf("Update err = %v, want sentinel", err)
	}
}

// Get/All must hand out copies: a caller mutating a returned record must not
// change store state without going through a persisting method.
func TestReturnedRecordsAreCopies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertNodes([]subscription.Node{testNode("a", "a.example")}); err != nil {
		t.Fatal(err)
	}
	r := s.All()[0]
	r.LastLatencyMS = 9999
	r.Node.Tag = "mutated"

	fresh, _ := s.Get(r.ID)
	if fresh.LastLatencyMS == 9999 || fresh.Node.Tag == "mutated" {
		t.Error("store state was mutated through a returned copy")
	}
}
