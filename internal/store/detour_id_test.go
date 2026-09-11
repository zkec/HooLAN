package store

import (
	"path/filepath"
	"proxy-manager/internal/subscription"
	"testing"
)

func TestDetourIdentitySurvivesProviderRename(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	nodes := []subscription.Node{{Tag: "duplicate", Protocol: subscription.ProtoVLESS, Server: "a.example", Port: 443, UUID: "a"}, {Tag: "duplicate", Protocol: subscription.ProtoVLESS, Server: "b.example", Port: 443, UUID: "b"}}
	if _, _, err := st.UpsertNodes(nodes); err != nil {
		t.Fatal(err)
	}
	a, b := NodeID(nodes[0]), NodeID(nodes[1])
	if err := st.SetDetour(a, b); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDetour(b, a); err == nil {
		t.Fatal("cycle accepted")
	}
	nodes[1].Tag = "renamed"
	st.UpsertNodes(nodes)
	live := st.EnabledNodes()
	if err := subscription.ValidateChains(live); err != nil {
		t.Fatal(err)
	}
	for _, n := range live {
		if NodeID(n) == a && n.Detour != "renamed" {
			t.Fatalf("stale target %q", n.Detour)
		}
	}
	loaded, err := Open(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	r, _ := loaded.Get(a)
	if r.DetourID != b {
		t.Fatal("ID not persisted")
	}
}
