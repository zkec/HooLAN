package store

import (
	"errors"
	"path/filepath"
	"hoolan/internal/subscription"
	"reflect"
	"testing"
	"time"
)

func TestSnapshotsOwnMutableNodeFields(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	n := testNode("one", "one.example")
	n.ALPN = []string{"h2"}
	n.BalanceMembers = []string{"member"}
	n.BalanceTags = []string{"tag"}
	_, _, err = s.UpsertNodes([]subscription.Node{n})
	if err != nil {
		t.Fatal(err)
	}
	id := NodeID(n)
	n.ALPN[0] = "input mutation"
	first, _ := s.Get(id)
	if first.Node.ALPN[0] != "h2" {
		t.Fatal("upsert retained caller storage")
	}
	first.Node.ALPN[0] = "output mutation"
	first.Node.BalanceMembers[0] = "bad"
	first.Node.BalanceTags[0] = "bad"
	all := s.All()
	all[0].Node.ALPN[0] = "all mutation"
	var retained *Record
	if err := s.Update(id, func(r *Record) error { retained = r; return nil }); err != nil {
		t.Fatal(err)
	}
	retained.Node.ALPN[0] = "retained callback mutation"
	current, _ := s.Get(id)
	if current.Node.ALPN[0] != "h2" || current.Node.BalanceMembers[0] != "member" || current.Node.BalanceTags[0] != "tag" {
		t.Fatal("mutable store alias escaped")
	}
	if err := s.Update(id, func(r *Record) error { r.Node.ALPN[0] = "failed callback"; return errors.New("reject") }); err == nil {
		t.Fatal("callback error swallowed")
	}
	current, _ = s.Get(id)
	if current.Node.ALPN[0] != "h2" {
		t.Fatal("rejected callback changed memory")
	}
}

func TestBatchMeasurementsAndPersistenceFailuresAreAtomic(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	s, err := Open(filepath.Join(dir, "nodes.json"), WithClock(func() time.Time { calls++; return time.Unix(int64(calls), 0) }))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.UpsertNodes([]subscription.Node{testNode("one", "one.example"), testNode("two", "two.example")})
	if err != nil {
		t.Fatal(err)
	}
	records := s.All()
	beforeCalls := calls
	results := []Measurement{{ID: records[0].ID, Latency: 25 * time.Millisecond}, {ID: records[1].ID, Err: errors.New("timeout")}}
	if err := s.RecordMeasurements(results); err != nil {
		t.Fatal(err)
	}
	after := s.All()
	if calls-beforeCalls != 2 || after[0].LastLatencyMS != 25 || after[1].LastLatencyMS != -1 || after[1].ConsecutiveFailures != 1 || after[0].LastCheckedAt != after[1].LastCheckedAt {
		t.Fatal("batch health update was not one consistent commit")
	}
	path := s.path
	s.path = dir // rename over directory fails, including when root.
	for _, mutate := range []func() error{
		func() error { return s.RecordMeasurements(results) },
		func() error { return s.SetEnabled(records[0].ID, false) },
		func() error {
			return s.Update(records[0].ID, func(r *Record) error { r.Node.Tag = "changed"; return nil })
		},
		func() error {
			_, _, err := s.UpsertNodes([]subscription.Node{testNode("new", "new.example")})
			return err
		},
		func() error { _, err := s.Prune(map[string]bool{}); return err },
	} {
		if mutate() == nil {
			t.Fatal("write failure accepted")
		}
		if !reflect.DeepEqual(s.All(), after) {
			t.Fatal("failed write changed in-memory state")
		}
	}
	s.path = path
	disk, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(disk.All(), after) {
		t.Fatal("failed writes changed disk state")
	}
}
