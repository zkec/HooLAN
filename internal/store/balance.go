package store

import "proxy-manager/internal/subscription"

// ResolveBalanceMembers keeps persistent membership tied to IDs across tag
// deduplication. A missing member is retained as an invalid reference for the
// renderer to reject, rather than silently shrinking or bypassing the group.
func ResolveBalanceMembers(nodes []subscription.Node) {
	tags := map[string]string{}
	for _, n := range nodes {
		tags[NodeID(n)] = n.Tag
	}
	for i, n := range nodes {
		if n.Protocol != subscription.ProtoBalance {
			continue
		}
		nodes[i].BalanceTags = make([]string, 0, len(n.BalanceMembers))
		for _, id := range n.BalanceMembers {
			tag := tags[id]
			if tag == "" {
				tag = "missing-member-" + id
			}
			nodes[i].BalanceTags = append(nodes[i].BalanceTags, tag)
		}
	}
}
