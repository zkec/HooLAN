package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy-manager/internal/subscription"
)

func TestIranRuleSetsEmitted(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger()})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if cfg.Route == nil || len(cfg.Route.RuleSet) != 2 {
		t.Fatalf("want 2 rule_sets (geosite-ir, geoip-ir), got %d", len(cfg.Route.RuleSet))
	}
	for _, rs := range cfg.Route.RuleSet {
		if rs.Type != "remote" {
			t.Errorf("%s: type = %q, want remote", rs.Tag, rs.Type)
		}
		// .srs files are compiled; "source" here is a startup failure.
		if rs.Format != "binary" {
			t.Errorf("%s: format = %q, want binary for .srs", rs.Tag, rs.Format)
		}
		if !strings.HasSuffix(rs.URL, ".srs") {
			t.Errorf("%s: url %q does not look like a .srs", rs.Tag, rs.URL)
		}
		// Downloading rule-sets through a proxy outbound is a bootstrap trap.
		// Default is the modern http_client form; the deprecated
		// download_detour must NOT also be set.
		if rs.HTTPClient == nil {
			t.Errorf("%s: no http_client", rs.Tag)
			continue
		}
		// Resolves via the bootstrap server, which is reached through the
		// dedicated fetch outbound rather than through route.final.
		if rs.HTTPClient.DomainResolver != DefaultBootstrapResolverTag {
			t.Errorf("%s: domain_resolver = %q, want %q",
				rs.Tag, rs.HTTPClient.DomainResolver, DefaultBootstrapResolverTag)
		}
		// Verified fatal on 1.14: detouring an http_client to a bare `direct`
		// outbound aborts startup even though `check` accepts it.
		if rs.HTTPClient.Detour == DefaultDirect {
			t.Errorf("%s: http_client.detour points at bare direct; this FATALs at runtime", rs.Tag)
		}
		if rs.DownloadDetour != "" {
			t.Errorf("%s: deprecated download_detour set alongside http_client: %q",
				rs.Tag, rs.DownloadDetour)
		}
	}

	// domain_resolver names a dns.servers[].tag, so that server must exist.
	if cfg.DNS == nil || len(cfg.DNS.Servers) == 0 {
		t.Error("http_client.domain_resolver set but no dns.servers emitted")
	}

	// The deprecated matchers must not appear anywhere.
	buf, _ := json.Marshal(cfg)
	for _, dead := range []string{`"geoip":`, `"geosite":`} {
		if strings.Contains(string(buf), dead) {
			t.Errorf("config uses removed matcher %s", dead)
		}
	}

	// Both bypass rules must route to direct.
	var direct int
	for _, r := range cfg.Route.Rules {
		if len(r.RuleSet) > 0 && r.Outbound == DefaultDirect {
			direct++
		}
	}
	if direct != 2 {
		t.Errorf("got %d rule_set->direct rules, want 2", direct)
	}
}

// The legacy spelling is opt-in for engines older than 1.14, and must be
// emitted alone -- never alongside http_client.
func TestLegacyDownloadDetourOptIn(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger(), LegacyDownloadDetour: true})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	for _, rs := range cfg.Route.RuleSet {
		if rs.DownloadDetour != DefaultFetchOutbound {
			t.Errorf("%s: download_detour = %q, want %q",
				rs.Tag, rs.DownloadDetour, DefaultFetchOutbound)
		}
		if rs.HTTPClient != nil {
			t.Errorf("%s: http_client set alongside legacy download_detour", rs.Tag)
		}
	}
	// In legacy mode the download_detour target must still exist as an outbound,
	// or startup fails with "dependency not found".
	var found bool
	for _, ob := range cfg.Outbounds {
		if d, ok := ob.(*DirectOutbound); ok && d.Tag == DefaultFetchOutbound {
			found = true
		}
	}
	if !found {
		t.Errorf("legacy mode references %q but does not emit it", DefaultFetchOutbound)
	}
}

func TestIranBypassDisabled(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger(), DisableIranBypass: true})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if len(cfg.Route.RuleSet) != 0 {
		t.Errorf("rule_set emitted despite DisableIranBypass")
	}
}

func TestIranAdsRuleOrdering(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger(), BlockIranAds: true})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if len(cfg.Route.RuleSet) != 3 {
		t.Fatalf("want 3 rule_sets with BlockIranAds, got %d", len(cfg.Route.RuleSet))
	}
	// The reject must come before the geosite-ir bypass: an Iranian ad domain
	// is in both lists and first match wins.
	rejectIdx, bypassIdx := -1, -1
	for i, r := range cfg.Route.Rules {
		if len(r.RuleSet) == 0 {
			continue
		}
		switch r.RuleSet[0] {
		case TagGeositeAdsIR:
			rejectIdx = i
		case TagGeositeIR:
			bypassIdx = i
		}
	}
	if rejectIdx < 0 || bypassIdx < 0 {
		t.Fatalf("missing rules: reject=%d bypass=%d", rejectIdx, bypassIdx)
	}
	if rejectIdx > bypassIdx {
		t.Errorf("ads reject at %d must precede geosite-ir bypass at %d", rejectIdx, bypassIdx)
	}
}

func TestSniffPrecedesRuleSetRules(t *testing.T) {
	// Domain-based rule-sets only work on a sniffed domain, so EVERY rule_set
	// rule must come after sniff. This is the invariant most likely to break
	// silently in a refactor.
	//
	// Asserted by relative position, not as "sniff is rules[0]": the loop
	// breaker (see TestLoopBreakerIsFirstRule) legitimately precedes sniff, and
	// it matches on IP and port only, so it needs no sniffed domain.
	m := NewManager(Options{Logger: quietLogger()})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	sniffIdx := -1
	for i, r := range cfg.Route.Rules {
		if r.Action == "sniff" {
			sniffIdx = i
			break
		}
	}
	if sniffIdx < 0 {
		t.Fatal("no rule with action=sniff")
	}
	for i, r := range cfg.Route.Rules {
		if len(r.RuleSet) > 0 && i < sniffIdx {
			t.Errorf("rule_set rule at %d must not precede sniff at %d", i, sniffIdx)
		}
	}
	// Anything ahead of sniff must not depend on a sniffed domain.
	for i, r := range cfg.Route.Rules[:sniffIdx] {
		if len(r.RuleSet) > 0 {
			t.Errorf("rule %d before sniff uses a domain rule_set", i)
		}
	}
}

// TestLoopBreakerIsFirstRule pins the fix for the TPROXY self-connection loop:
// a dial to a local address on the tproxy port must be rejected before any
// other rule can route it to `direct` and re-enter the inbound. Without this
// rule the `ip_is_private` -> direct rule matched 127.0.0.1:7892 and the engine
// spun forever dialling its own listener.
func TestLoopBreakerIsFirstRule(t *testing.T) {
	const port = 7892
	m := NewManager(Options{Logger: quietLogger(), TProxyPort: port})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	got := cfg.Route.Rules[0]
	if got.Action != "reject" {
		t.Errorf("rules[0].action = %q, want reject", got.Action)
	}
	if !got.IPIsPrivate {
		t.Error("rules[0] must match ip_is_private so loopback and the Pi's LAN IP are both covered")
	}
	if len(got.Port) != 1 || got.Port[0] != port {
		t.Errorf("rules[0].port = %v, want [%d]", got.Port, port)
	}
	// A port-only reject would break LAN clients reaching a public host on
	// 7892, so the address matcher must not be dropped.
	if len(got.RuleSet) != 0 || len(got.Protocol) != 0 {
		t.Errorf("loop breaker should match on ip+port alone, got %+v", got)
	}
	// The rule must precede the ip_is_private -> direct rule that caused the
	// loop, otherwise first-match-wins sends the packet to direct again.
	for i, r := range cfg.Route.Rules {
		if r.Action == "route" && r.IPIsPrivate && r.Outbound == DefaultDirect {
			if i == 0 {
				t.Error("ip_is_private -> direct must not be the first rule")
			}
			break
		}
	}
}

func TestAutoSwitchGroup(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger()})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	var auto *URLTestOutbound
	var sel *SelectorOutbound
	for _, ob := range cfg.Outbounds {
		switch o := ob.(type) {
		case *URLTestOutbound:
			auto = o
		case *SelectorOutbound:
			sel = o
		}
	}
	if auto == nil {
		t.Fatal("no urltest outbound emitted")
	}
	if auto.Tag != DefaultURLTest {
		t.Errorf("urltest tag = %q, want %q", auto.Tag, DefaultURLTest)
	}
	if auto.URL != DefaultProbeURL {
		t.Errorf("urltest url = %q, want %q", auto.URL, DefaultProbeURL)
	}
	if auto.Tolerance != 50 {
		t.Errorf("tolerance = %d, want 50", auto.Tolerance)
	}
	// urltest must not contain direct or the selector: either makes the group's
	// health depend on something that is not a proxy node.
	for _, mem := range auto.Outbounds {
		if mem == DefaultDirect || mem == DefaultSelector {
			t.Errorf("urltest must not contain %q", mem)
		}
	}
	if sel == nil {
		t.Fatal("no selector emitted")
	}
	if sel.Outbounds[0] != DefaultURLTest {
		t.Errorf("selector[0] = %q, want the urltest group first", sel.Outbounds[0])
	}
}

func TestAutoSwitchDisabled(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger(), DisableAutoSwitch: true})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	for _, ob := range cfg.Outbounds {
		if _, ok := ob.(*URLTestOutbound); ok {
			t.Fatal("urltest emitted despite DisableAutoSwitch")
		}
	}
	for _, ob := range cfg.Outbounds {
		if sel, ok := ob.(*SelectorOutbound); ok {
			if sel.Outbounds[0] == DefaultURLTest {
				t.Error("selector still references the absent urltest group")
			}
		}
	}
}

// TestAutoSwitchOmittedWhenAllChained covers the empty-urltest startup failure:
// sing-box 1.14 FATALs with "missing tags" on an empty outbounds list, so the
// group must be omitted rather than emitted empty.
func TestAutoSwitchOmittedWhenAllChained(t *testing.T) {
	nodes := []subscription.Node{
		{Protocol: subscription.ProtoTrojan, Tag: "hop", Server: "h.example", Port: 443,
			Password: "p", Security: subscription.SecTLS, SNI: "h.example"},
		{Protocol: subscription.ProtoTrojan, Tag: "exit", Server: "e.example", Port: 443,
			Password: "p", Security: subscription.SecTLS, SNI: "e.example", Detour: "hop"},
	}
	// Chain both so no unchained node remains.
	nodes[0].Detour = ""
	nodes[1].Detour = "hop"
	m := NewManager(Options{Logger: quietLogger()})
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	// "hop" is unchained, so a group IS expected here with exactly one member.
	for _, ob := range cfg.Outbounds {
		if auto, ok := ob.(*URLTestOutbound); ok {
			if len(auto.Outbounds) == 0 {
				t.Fatal("emitted an empty urltest group (sing-box FATALs on this)")
			}
			if len(auto.Outbounds) != 1 || auto.Outbounds[0] != "hop" {
				t.Errorf("urltest members = %v, want [hop] (chained node excluded)",
					auto.Outbounds)
			}
		}
	}
}

func TestDetourRendered(t *testing.T) {
	nodes := []subscription.Node{
		{Protocol: subscription.ProtoTrojan, Tag: "hop", Server: "h.example", Port: 443,
			Password: "p", Security: subscription.SecTLS, SNI: "h.example"},
		{Protocol: subscription.ProtoVLESS, Tag: "exit", Server: "e.example", Port: 443,
			UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Security: subscription.SecTLS,
			SNI: "e.example", Detour: "hop"},
	}
	m := NewManager(Options{Logger: quietLogger(), RoutingMark: 1})
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	var exit *VLESSOutbound
	var hop *TrojanOutbound
	for _, ob := range cfg.Outbounds {
		switch o := ob.(type) {
		case *VLESSOutbound:
			exit = o
		case *TrojanOutbound:
			hop = o
		}
	}
	if exit == nil || hop == nil {
		t.Fatal("missing rendered outbounds")
	}
	if exit.Detour != "hop" {
		t.Errorf("exit.detour = %q, want hop", exit.Detour)
	}
	// detour makes every other dial field a no-op, so routing_mark must be
	// dropped rather than silently ignored by the engine.
	if exit.RoutingMark != 0 {
		t.Errorf("exit.routing_mark = %d; must be 0 when detour is set", exit.RoutingMark)
	}
	// The unchained hop keeps the mark.
	if hop.RoutingMark != 1 {
		t.Errorf("hop.routing_mark = %d, want 1", hop.RoutingMark)
	}
}

func TestBuildConfigRejectsDetourCycle(t *testing.T) {
	// sing-box `check` accepts this; `run` FATALs. BuildConfig must catch it
	// before Apply stops a working engine.
	nodes := []subscription.Node{
		{Protocol: subscription.ProtoTrojan, Tag: "a", Server: "a.example", Port: 443,
			Password: "p", Security: subscription.SecTLS, Detour: "b"},
		{Protocol: subscription.ProtoTrojan, Tag: "b", Server: "b.example", Port: 443,
			Password: "p", Security: subscription.SecTLS, Detour: "a"},
	}
	m := NewManager(Options{Logger: quietLogger()})
	if _, err := m.BuildConfig(nodes); err == nil {
		t.Fatal("expected a cycle error")
	} else if !strings.Contains(err.Error(), "circular") {
		t.Errorf("error should name the cycle, got: %v", err)
	}
}

func TestBuildConfigRejectsDanglingDetour(t *testing.T) {
	nodes := []subscription.Node{
		{Protocol: subscription.ProtoTrojan, Tag: "a", Server: "a.example", Port: 443,
			Password: "p", Security: subscription.SecTLS, Detour: "ghost"},
	}
	m := NewManager(Options{Logger: quietLogger()})
	if _, err := m.BuildConfig(nodes); err == nil {
		t.Fatal("expected an unknown-detour-tag error")
	}
}

func TestCacheFileEmitted(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger(), CacheFilePath: "/var/lib/pm/cache.db"})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if cfg.Experimental == nil || cfg.Experimental.CacheFile == nil {
		t.Fatal("cache_file not emitted")
	}
	if !cfg.Experimental.CacheFile.Enabled {
		t.Error("cache_file.enabled = false")
	}
	if cfg.Experimental.CacheFile.Path != "/var/lib/pm/cache.db" {
		t.Errorf("cache_file.path = %q", cfg.Experimental.CacheFile.Path)
	}
}

// --- validation against the real engine -------------------------------------

// TestRuleSetDownloadPrerequisites locks in the three things a remote rule-set
// needs on sing-box 1.14, every one of which `sing-box check` accepts when
// wrong and only `run` rejects:
//
//  1. http_client.detour must not be a bare `direct` outbound
//     -> FATAL "detour to an empty direct outbound makes no sense"
//  2. route.default_domain_resolver must be set
//     -> FATAL "missing route.default_domain_resolver ..."
//  3. the fetch path must not resolve through route.final (the proxy), or
//     lookups time out before any proxy is reachable
func TestRuleSetDownloadPrerequisites(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger()})
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	// (2) default_domain_resolver present and pointing at a real dns tag.
	if cfg.Route.DefaultDomainResolver == nil {
		t.Fatal("route.default_domain_resolver missing; 1.14 aborts startup without it")
	}
	dnsTags := map[string]bool{}
	if cfg.DNS != nil {
		for _, s := range cfg.DNS.Servers {
			if mm, ok := s.(map[string]any); ok {
				if tag, _ := mm["tag"].(string); tag != "" {
					dnsTags[tag] = true
				}
			}
		}
	}
	if !dnsTags[cfg.Route.DefaultDomainResolver.Server] {
		t.Errorf("default_domain_resolver.server = %q but no dns server has that tag (have %v)",
			cfg.Route.DefaultDomainResolver.Server, dnsTags)
	}

	// (1)+(3) the fetch outbound must exist, be non-empty, and be the detour
	// for the bootstrap DNS server.
	var fetch *DirectOutbound
	for _, ob := range cfg.Outbounds {
		if d, ok := ob.(*DirectOutbound); ok && d.Tag == DefaultFetchOutbound {
			fetch = d
		}
	}
	if fetch == nil {
		t.Fatalf("no %q outbound; rule-set fetches would have to detour to bare direct",
			DefaultFetchOutbound)
	}
	if fetch.DomainResolver == "" {
		t.Error("fetch outbound has no dial settings; 1.14 rejects it as a detour target")
	}

	// The bootstrap resolver must be reached through the fetch outbound, not
	// through route.final.
	var bootFound bool
	for _, s := range cfg.DNS.Servers {
		mm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if mm["tag"] == DefaultBootstrapResolverTag {
			bootFound = true
			if mm["detour"] != DefaultFetchOutbound {
				t.Errorf("bootstrap dns detour = %v, want %q", mm["detour"], DefaultFetchOutbound)
			}
		}
	}
	if !bootFound {
		t.Errorf("no %q dns server; rule-set lookups would route through the proxy and time out",
			DefaultBootstrapResolverTag)
	}
	// And the rule-sets must resolve through it.
	for _, rs := range cfg.Route.RuleSet {
		if rs.HTTPClient == nil || rs.HTTPClient.DomainResolver != DefaultBootstrapResolverTag {
			t.Errorf("%s: http_client.domain_resolver = %v, want %q",
				rs.Tag, rs.HTTPClient, DefaultBootstrapResolverTag)
		}
	}
}

// TestRealSingBoxAcceptsFullFeatureConfig is the load-bearing test for this
// layer: Iran rule-sets + urltest + a detour chain + cache_file, all validated
// by the binary that will run it.
func TestRealSingBoxAcceptsFullFeatureConfig(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()

	nodes := allProtocolNodes()
	// Chain the last node through the first to exercise detour.
	nodes[len(nodes)-1].Detour = nodes[0].Tag

	m := NewManager(Options{
		BinaryPath:    bin,
		ConfigPath:    filepath.Join(dir, "config.json"),
		Logger:        quietLogger(),
		BlockIranAds:  true,
		CacheFilePath: filepath.Join(dir, "cache.db"),
	})
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if err := m.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	if err := m.Check(context.Background()); err != nil {
		raw, _ := os.ReadFile(m.ConfigPath())
		t.Fatalf("real sing-box rejected the config: %v\n--- config ---\n%s", err, raw)
	}
}

// TestRealSingBoxRunsFullFeatureConfig actually STARTS the engine. This exists
// because `sing-box check` was observed to accept configs that die at startup:
// a detour to a bare direct outbound, a missing default_domain_resolver, and a
// bootstrap resolver reachable only through the proxy all pass check and FATAL
// on run. Only a real start proves the generated config works.
//
// The tproxy inbound is swapped for a loopback mixed inbound because binding
// TPROXY needs CAP_NET_ADMIN; everything else (rule-sets, urltest, detour
// chain, DNS, cache_file) is exactly what BuildConfig produced.
func TestRealSingBoxRunsFullFeatureConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("downloads remote rule-sets; skipped in -short")
	}
	bin := findSingBox(t)
	dir := t.TempDir()

	nodes := allProtocolNodes()
	nodes[len(nodes)-1].Detour = nodes[0].Tag

	m := NewManager(Options{
		BinaryPath:    bin,
		ConfigPath:    filepath.Join(dir, "config.json"),
		Logger:        quietLogger(),
		BlockIranAds:  true,
		CacheFilePath: filepath.Join(dir, "cache.db"),
	})
	cfg, err := m.BuildConfig(nodes)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	// Swap in a non-privileged inbound so the test does not require root.
	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Inbounds = []any{map[string]any{
		"type": "mixed", "tag": m.opts.InboundTag,
		"listen": "127.0.0.1", "listen_port": port,
	}}
	if err := m.WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "-c", m.ConfigPath(), "-D", dir)
	// exec's io copier writes from its own goroutine while this test reads, and
	// bytes.Buffer is not safe for concurrent use -- guard it.
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	// Wait for the inbound to accept, which only happens after rule-sets load.
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(75 * time.Second)
	var up bool
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			c.Close()
			up = true
			break
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	log := out.String()
	if !up {
		t.Fatalf("engine never started.\n--- engine output ---\n%s", log)
	}
	// Startup-fatal conditions and deprecations must both be absent.
	for _, bad := range []string{"FATAL", "makes no sense", "default_domain_resolver", "deprecated"} {
		if strings.Contains(log, bad) {
			t.Errorf("engine log contains %q:\n%s", bad, log)
		}
	}
	if !strings.Contains(log, "sing-box started") {
		t.Errorf("no start confirmation in log:\n%s", log)
	}
	t.Logf("engine started cleanly; rule-set lines:\n%s", ruleSetLines(log))
}

func ruleSetLines(log string) string {
	var keep []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "rule-set") || strings.Contains(line, "started") {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// lockedBuffer is a mutex-guarded sink for child-process output.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
