package engine

import (
	"fmt"
	"proxy-manager/internal/store"
	"proxy-manager/internal/subscription"
	"sort"
)

type DistributionMember struct {
	Tag     string
	Inbound string
	Port    int
}
type DistributionGroup struct {
	ID      string
	Tag     string
	Members []DistributionMember
}

// DistributionPlan is deterministic for a saved inventory. Additional IPv4
// TPROXY listeners begin immediately after the main listener. It never emits
// the unsupported upstream outbound type "loadbalance".
func DistributionPlan(nodes []subscription.Node, basePort int) ([]DistributionGroup, error) {
	byTag := map[string]subscription.Node{}
	groups := []subscription.Node{}
	for _, n := range nodes {
		byTag[n.Tag] = n
		if n.Protocol == subscription.ProtoBalance {
			groups = append(groups, n)
		}
	}
	if len(groups) > 16 {
		return nil, fmt.Errorf("at most 16 load balancers are supported")
	}
	sort.Slice(groups, func(i, j int) bool { return store.NodeID(groups[i]) < store.NodeID(groups[j]) })
	plans := []DistributionGroup{}
	port := basePort
	for _, g := range groups {
		if err := g.Validate(); err != nil {
			return nil, err
		}
		if len(g.BalanceTags) != len(g.BalanceMembers) {
			return nil, fmt.Errorf("unresolved load balancer members")
		}
		plan := DistributionGroup{ID: store.NodeID(g), Tag: g.Tag}
		for i, tag := range g.BalanceTags {
			n, ok := byTag[tag]
			if !ok || n.Protocol == subscription.ProtoBalance {
				return nil, fmt.Errorf("missing or nested load balancer member")
			}
			port++
			if port > 65535 {
				return nil, fmt.Errorf("load balancer listener port exceeds 65535")
			}
			plan.Members = append(plan.Members, DistributionMember{Tag: tag, Inbound: fmt.Sprintf("balance-%s-%d", plan.ID, i), Port: port})
		}
		plans = append(plans, plan)
	}
	for _, n := range nodes {
		if target, ok := byTag[n.Detour]; ok && target.Protocol == subscription.ProtoBalance {
			return nil, fmt.Errorf("a detour cannot target a load balancer")
		}
	}
	return plans, nil
}

// AutomaticFallback identifies the selector's default when no ordinary node
// can belong to URLTest (for example, only saved groups/chains remain).
func AutomaticFallback(nodes []subscription.Node) string {
	for _, n := range nodes {
		if !n.ChainInternal && n.Detour == "" && n.Protocol != subscription.ProtoBalance {
			return ""
		}
	}
	for _, n := range nodes {
		if !n.ChainInternal {
			return store.NodeID(n)
		}
	}
	return ""
}
