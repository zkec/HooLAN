package netfilter

import (
	"math"
	"os"
	"path/filepath"
	"proxy-manager/internal/engine"
	"strings"
	"testing"
)

func TestDeviceQoSUnitsDirectionsAndValidation(t *testing.T) {
	raw, err := RenderDeviceLimits("eth0", map[string]DeviceLimits{"192.168.3.141": UniformLimits(8), "192.168.3.142": UniformLimits(0.01)})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"priority -149", "priority 99", "192.168.3.141 : jump device_0_up", "192.168.3.141 : jump device_0_down", "limit rate over 1000000 bytes/second burst 100000 bytes", "1250 bytes/second burst 1500 bytes", "fib daddr type { local, broadcast, multicast } return", "ip daddr vmap @devices_down"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, rate := range []float64{-1, math.Inf(1), math.NaN(), 0.001, 10001} {
		if _, err := RenderDeviceLimits("eth0", map[string]DeviceLimits{"192.168.3.1": UniformLimits(rate)}); err == nil {
			t.Errorf("accepted bad rate %v", rate)
		}
	}
	for _, ip := range []string{"8.8.8.8", "192.168.1.1;flush ruleset", "192.168.1.0/24", "::ffff:192.168.1.1"} {
		if _, err := RenderDeviceLimits("eth0", map[string]DeviceLimits{ip: UniformLimits(1)}); err == nil {
			t.Error("accepted bad IP")
		}
	}
	if _, err := RenderDeviceLimits("eth0; drop", nil); err == nil {
		t.Fatal("interface injection accepted")
	}
	raw, err = RenderDeviceLimits("eth0", map[string]DeviceLimits{"192.168.3.1": {}})
	if err != nil || string(raw) != "add table inet proxy_qos\ndelete table inet proxy_qos\n" {
		t.Fatal("zero must remove QoS table")
	}
}
func distributionFixture() []engine.DistributionGroup {
	return []engine.DistributionGroup{{ID: strings.Repeat("a", 32), Members: []engine.DistributionMember{{Port: 7893}, {Port: 7894}}}, {ID: strings.Repeat("b", 32), Members: []engine.DistributionMember{{Port: 7895}, {Port: 7896}}}}
}
func TestDistributionTupleAndDevicePrecedence(t *testing.T) {
	groups := distributionFixture()
	raw, err := RenderDistribution(groups, groups[0].ID, map[string]string{"192.168.3.1": groups[1].ID, "192.168.3.2": "direct", "192.168.3.3": "normal"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"jhash ip saddr . ip daddr . meta l4proto . th sport . th dport mod 2 seed 0xaaaaaaaa", "0 : jump balance_g0_m0, 1 : jump balance_g0_m1", "tproxy ip to :7896 meta mark set {{TPROXY_FWMARK}}", "ip saddr 192.168.3.2 return", "ip saddr 192.168.3.3 return"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Index(s, "ip saddr 192.168.3.1 jump balance_g1") > strings.LastIndex(s, "jump balance_g0") {
		t.Fatal("global dispatch precedes device assignment")
	}
	if strings.Contains(s, "ct mark") || strings.Contains(s, "numgen") {
		t.Fatal("per-packet rotation or conntrack mark clobber")
	}
	again, _ := RenderDistribution(groups, groups[0].ID, map[string]string{"192.168.3.3": "normal", "192.168.3.2": "direct", "192.168.3.1": groups[1].ID})
	if string(again) != s {
		t.Fatal("reload changed hash or rule order")
	}
}
func TestScriptIncludesQoSAndDistributionAtomically(t *testing.T) {
	f := newScriptFixture(t)
	qos, _ := RenderDeviceLimits("eth0", map[string]DeviceLimits{"192.168.3.141": UniformLimits(5)})
	groups := distributionFixture()
	balance, _ := RenderDistribution(groups, groups[0].ID, nil)
	qp, bp := filepath.Join(f.dir, "qos.nft"), filepath.Join(f.dir, "balance.nft")
	if err := os.WriteFile(qp, qos, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bp, balance, 0600); err != nil {
		t.Fatal(err)
	}
	f.env = append(f.env, "PROXY_QOS_FILE="+qp, "PROXY_BALANCE_FILE="+bp)
	f.run(t, "apply.sh", false)
	active := f.read(t, "active.nft")
	if !strings.Contains(active, "table inet proxy_qos {") || !strings.Contains(active, "chain balance_dispatch {") || strings.Contains(active, "{{") {
		t.Fatal("missing or unexpanded fragments")
	}
	if strings.Index(active, "ip daddr @bypass_daddrs") > strings.Index(active, "jump balance_dispatch") {
		t.Fatal("distribution bypasses local exclusions")
	}
	if strings.Count(f.read(t, "calls"), "nft -f ") != 1 {
		t.Fatal("tables were not loaded in one transaction")
	}
	before := active
	f.env = append(f.env, "MOCK_NFT_CHECK_FAIL=1")
	f.run(t, "apply.sh", true)
	if f.read(t, "active.nft") != before {
		t.Fatal("rejected batch changed live firewall")
	}
}
