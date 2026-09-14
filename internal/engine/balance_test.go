package engine

import (
	"encoding/json"
	"hoolan/internal/store"
	"hoolan/internal/subscription"
	"strings"
	"testing"
)

func balancedNodes() []subscription.Node {
	a := subscription.Node{Protocol: subscription.ProtoTrojan, Tag: "same", Server: "1.1.1.1", Port: 443, Password: "test", ChainInternal: true}
	b := a
	b.Server = "8.8.8.8"
	group := subscription.Node{Protocol: subscription.ProtoBalance, Tag: "Balanced", LocalVariant: "test-group", BalanceMembers: []string{store.NodeID(a), store.NodeID(b)}}
	return []subscription.Node{a, b, group}
}
func TestBalanceConfigUsesUpstreamListenersAndPreservesBypass(t *testing.T) {
	nodes := balancedNodes()
	m := NewManager(Options{Logger: quietLogger()})
	m.ConfigureDeviceRoutes(map[string]string{"192.168.3.15": store.NodeID(nodes[2])})
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 3 {
		t.Fatal("one listener per member missing")
	}
	raw, _ := json.Marshal(cfg)
	if strings.Contains(string(raw), `"type":"loadbalance"`) {
		t.Fatal("unsupported outbound emitted")
	}
	if !strings.Contains(string(raw), `"listen_port":7893`) || !strings.Contains(string(raw), `"listen_port":7894`) {
		t.Fatal("wrong port allocation")
	}
	var privateIndex, balanceIndex, deviceIndex, iranIndex int
	iranIndex = -1
	privateIndex = -1
	balanceIndex = -1
	deviceIndex = -1
	for i, r := range cfg.Route.Rules {
		if len(r.RuleSet) > 0 && r.Outbound == DefaultDirect {
			iranIndex = i
		}
		if r.IPIsPrivate && r.Outbound == DefaultDirect {
			privateIndex = i
		}
		if len(r.Inbound) > 0 && strings.HasPrefix(r.Inbound[0], "balance-") && r.Action == "route" && balanceIndex < 0 {
			balanceIndex = i
		}
		if len(r.SourceIPCIDR) > 0 {
			deviceIndex = i
			if r.Outbound != "Balanced" {
				t.Fatal("device group not resolved")
			}
		}
	}
	if privateIndex < 0 || iranIndex < 0 || balanceIndex <= iranIndex || balanceIndex <= privateIndex || deviceIndex <= balanceIndex {
		t.Fatal("wrong routing priority")
	}
	// Duplicate original names must resolve to the deduplicated outbound tags.
	plan, err := DistributionPlan(nodes, 7892)
	if err != nil {
		t.Fatal(err)
	}
	if plan[0].Members[0].Tag == plan[0].Members[1].Tag {
		t.Fatal("member tags not deduplicated")
	}
}
func TestBalancePlanRejectsMissingNestedAndOverflow(t *testing.T) {
	for _, kind := range []string{"missing", "nested", "detour", "overflow"} {
		t.Run(kind, func(t *testing.T) {
			nodes := balancedNodes()
			port := 7892
			switch kind {
			case "missing":
				nodes[2].BalanceMembers[0] = "absent"
			case "nested":
				nodes[2].BalanceMembers[0] = store.NodeID(nodes[2])
			case "detour":
				nodes[0].Detour = "Balanced"
			case "overflow":
				port = 65534
			}
			subscription.DedupeTags(nodes)
			store.ResolveBalanceMembers(nodes)
			if _, err := DistributionPlan(nodes, port); err == nil {
				t.Fatal("invalid distribution accepted")
			}
		})
	}
}

func TestLatencyGroupUsesURLTestWithoutHashListeners(t *testing.T) {
	nodes := balancedNodes()
	nodes[2].BalanceStrategy = "latency"
	m := NewManager(Options{Logger: quietLogger()})
	m.ConfigureDeviceRoutes(map[string]string{"192.168.3.15": store.NodeID(nodes[2])})
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 1 {
		t.Fatal("latency group must use ordinary TPROXY listener")
	}
	found := false
	for _, out := range cfg.Outbounds {
		if u, ok := out.(*URLTestOutbound); ok && u.Tag == "Balanced" {
			found = true
			if len(u.Outbounds) != 2 || u.InterruptExistConnections {
				t.Fatal("invalid URLTest")
			}
		}
	}
	if !found {
		t.Fatal("missing latency group")
	}
	plan, err := DistributionPlan(nodes, 7892)
	if err != nil || len(plan) != 0 {
		t.Fatalf("unexpected distribution: %v %v", plan, err)
	}
	nodes[2].BalanceStrategy = "invented"
	if _, err := m.BuildConfig(nodes); err == nil {
		t.Fatal("unknown strategy accepted")
	}
}
