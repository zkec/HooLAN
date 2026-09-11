package engine

import (
	"encoding/json"
	"proxy-manager/internal/store"
	"strings"
	"testing"
)

func TestDeviceRoutesOrderStableIDsAndFallback(t *testing.T) {
	nodes := testNodes()
	nodes[0].Tag = "Same"
	nodes[1].Tag = "Same"
	id := store.NodeID(nodes[1])
	m := NewManager(Options{Logger: quietLogger()})
	routes := map[string]string{"192.168.3.141": id, "192.168.3.142": "deleted-node"}
	m.ConfigureDeviceRoutes(routes)
	routes["192.168.3.141"] = "mutated"
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatal(err)
	}
	last := cfg.Route.Rules[len(cfg.Route.Rules)-1]
	if len(last.SourceIPCIDR) != 1 || last.SourceIPCIDR[0] != "192.168.3.141/32" || last.Outbound != nodes[1].Tag || last.Outbound == nodes[0].Tag || last.Action != "route" {
		t.Fatalf("wrong device route: %+v", last)
	}
	if len(last.Inbound) != 1 || last.Inbound[0] != DefaultTag || cfg.Route.Final != DefaultSelector {
		t.Fatal("inbound or fallback lost")
	}
	iranBefore := false
	for _, r := range cfg.Route.Rules[:len(cfg.Route.Rules)-1] {
		if len(r.RuleSet) > 0 {
			iranBefore = true
		}
		if len(r.SourceIPCIDR) > 0 {
			t.Fatal("missing-node route emitted")
		}
	}
	if !iranBefore {
		t.Fatal("Iran bypass not ahead of device routing")
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"source_ip":`) || !strings.Contains(string(raw), `"source_ip_cidr":["192.168.3.141/32"]`) {
		t.Fatal("wrong sing-box field")
	}
	m.ConfigureDeviceRoutes(nil)
	cfg, err = m.BuildConfig(nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range cfg.Route.Rules {
		if len(r.SourceIPCIDR) > 0 {
			t.Fatal("cleared route retained")
		}
	}
}
