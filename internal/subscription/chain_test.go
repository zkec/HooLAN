package subscription

import (
	"strings"
	"testing"
)

func chainNode(tag, detour string) Node {
	return Node{
		Protocol: ProtoTrojan, Tag: tag, Server: tag + ".example", Port: 443,
		Password: "p", Security: SecTLS, Detour: detour,
	}
}

func TestValidateChainsAcceptsValid(t *testing.T) {
	// exit -> mid -> hop -> (direct)
	nodes := []Node{
		chainNode("exit", "mid"),
		chainNode("mid", "hop"),
		chainNode("hop", ""),
		chainNode("standalone", ""),
	}
	if err := ValidateChains(nodes); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
}

func TestValidateChainsDetectsSelfLoop(t *testing.T) {
	nodes := []Node{chainNode("a", "a")}
	err := ValidateChains(nodes)
	if err == nil {
		t.Fatal("self-detour accepted")
	}
	if !strings.Contains(err.Error(), "itself") {
		t.Errorf("error should mention self-detour, got: %v", err)
	}
}

func TestValidateChainsDetectsMultiHopCycle(t *testing.T) {
	// Matches what sing-box run reports: "circular outbound dependency: a -> b -> c -> a"
	nodes := []Node{
		chainNode("a", "b"),
		chainNode("b", "c"),
		chainNode("c", "a"),
	}
	err := ValidateChains(nodes)
	if err == nil {
		t.Fatal("3-node cycle accepted")
	}
	if !strings.Contains(err.Error(), "circular") {
		t.Errorf("error should say circular, got: %v", err)
	}
	// The message must name the nodes so the operator can fix it.
	for _, tag := range []string{"a", "b", "c"} {
		if !strings.Contains(err.Error(), tag) {
			t.Errorf("error should name %q: %v", tag, err)
		}
	}
}

func TestValidateChainsDetectsDanglingTarget(t *testing.T) {
	nodes := []Node{chainNode("a", "ghost")}
	err := ValidateChains(nodes)
	if err == nil {
		t.Fatal("detour to unknown tag accepted")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should name the missing tag: %v", err)
	}
}

// Two independent chains sharing a tail must not be misreported as a cycle;
// this is the case a naive visited-set walk gets wrong.
func TestValidateChainsSharedTail(t *testing.T) {
	nodes := []Node{
		chainNode("a", "shared"),
		chainNode("b", "shared"),
		chainNode("shared", ""),
	}
	if err := ValidateChains(nodes); err != nil {
		t.Fatalf("shared tail misreported: %v", err)
	}
}

func TestValidateChainsNoDetours(t *testing.T) {
	nodes := []Node{chainNode("a", ""), chainNode("b", "")}
	if err := ValidateChains(nodes); err != nil {
		t.Fatalf("unchained nodes rejected: %v", err)
	}
	if err := ValidateChains(nil); err != nil {
		t.Fatalf("empty set rejected: %v", err)
	}
}

func TestChainOf(t *testing.T) {
	nodes := []Node{
		chainNode("exit", "mid"),
		chainNode("mid", "hop"),
		chainNode("hop", ""),
	}
	got := ChainOf(nodes, "exit")
	want := []string{"exit", "mid", "hop"}
	if len(got) != len(want) {
		t.Fatalf("ChainOf = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ChainOf = %v, want %v", got, want)
		}
	}
	if ChainOf(nodes, "nope") != nil {
		t.Error("ChainOf(unknown) should be nil")
	}
	if got := ChainOf(nodes, "hop"); len(got) != 1 || got[0] != "hop" {
		t.Errorf("ChainOf(hop) = %v, want [hop]", got)
	}
}

// ChainOf must terminate even on a cycle: callers may reach it with unvalidated
// data and an infinite loop would hang the daemon.
func TestChainOfTerminatesOnCycle(t *testing.T) {
	nodes := []Node{chainNode("a", "b"), chainNode("b", "a")}
	done := make(chan []string, 1)
	go func() { done <- ChainOf(nodes, "a") }()
	select {
	case got := <-done:
		if len(got) > len(nodes)+1 {
			t.Errorf("ChainOf returned %d hops for a 2-node cycle", len(got))
		}
	default:
		// Give it a moment; a hang would fail the test via the go test timeout.
		got := <-done
		if len(got) > len(nodes)+1 {
			t.Errorf("ChainOf returned %d hops", len(got))
		}
	}
}

// DedupeTags renames tags; detour references must follow the rename or the
// chain silently points at a tag that no longer exists.
func TestDedupeTagsRewritesDetours(t *testing.T) {
	nodes := []Node{
		{Protocol: ProtoTrojan, Tag: "US", Server: "a", Port: 443, Password: "p"},
		{Protocol: ProtoTrojan, Tag: "US", Server: "b", Port: 443, Password: "p"},
		{Protocol: ProtoTrojan, Tag: "exit", Server: "c", Port: 443, Password: "p", Detour: "US"},
	}
	DedupeTags(nodes)

	// The duplicate was renamed; "exit" must point at a tag that exists.
	tags := map[string]bool{}
	for _, n := range nodes {
		tags[n.Tag] = true
	}
	exit := nodes[2]
	if exit.Detour == "" {
		t.Fatal("detour was cleared instead of rewritten")
	}
	if !tags[exit.Detour] {
		t.Errorf("detour %q does not match any tag after dedupe; tags=%v", exit.Detour, tags)
	}
	// And the whole set must still validate.
	if err := ValidateChains(nodes); err != nil {
		t.Errorf("chains broken by dedupe: %v", err)
	}
}
