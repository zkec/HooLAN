package netfilter

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestQoSMigrationAndIndependentRates(t *testing.T) {
	var limits map[string]DeviceLimits
	if err := json.Unmarshal([]byte(`{"192.168.3.141":8.5}`), &limits); err != nil {
		t.Fatal(err)
	}
	if limits["192.168.3.141"] != UniformLimits(8.5) {
		t.Fatal("legacy cap lost")
	}
	for _, raw := range []string{`null`, `{"proxy_upload_mbsp":5}`, `"5"`} {
		var l DeviceLimits
		if json.Unmarshal([]byte(raw), &l) == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for field := 0; field < 4; field++ {
		for _, rate := range []float64{-1, math.NaN(), math.Inf(1), 0.001, 10001} {
			var l DeviceLimits
			ptrs := []*float64{&l.ProxyUpload, &l.ProxyDownload, &l.DirectUpload, &l.DirectDownload}
			*ptrs[field] = rate
			if ValidateDeviceLimits(map[string]DeviceLimits{"192.168.3.141": l}) == nil {
				t.Fatalf("accepted field %d value %v", field, rate)
			}
		}
	}
	l := DeviceLimits{ProxyUpload: 8, ProxyDownload: 16, DirectUpload: 4, DirectDownload: 0}
	raw, err := renderDeviceLimits("eth0", "0x21", map[string]DeviceLimits{"192.168.3.141": l})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"limit rate over 1000000 bytes/second", "limit rate over 2000000 bytes/second", "limit rate over 500000 bytes/second",
		"meta mark != 0x21 goto device_0_up_direct", "meta iif != 0 goto device_0_down_direct",
		"ip saddr . meta l4proto . th sport . ip daddr . th dport @direct_flows",
		"ip daddr . meta l4proto . th dport . ip saddr . th sport @proxy_flows",
		`counter goto device_0_up_direct comment "qos-unclassified-up-192.168.3.141"`,
		`counter goto device_0_down_proxy comment "qos-unclassified-down-192.168.3.141"`,
		"chain device_0_down_direct {\n  return\n }",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(s, "limit rate over") != 3 || strings.Contains(s, "mark set") || strings.Contains(s, "local_networks") {
		t.Fatal("extra buckets, routing mark mutation, or private bypass")
	}
}

func TestQoSFlowTuplesBoundedAtomicAndNoBucketReset(t *testing.T) {
	limits := map[string]DeviceLimits{"192.168.3.141": UniformLimits(1)}
	proxy := QoSFlow{SourceIP: "192.168.3.141", DestinationIP: "8.8.8.8", SourcePort: 2000, DestinationPort: 443, Network: "tcp"}
	direct := proxy
	direct.SourcePort = 2001
	direct.Direct = true
	raw, err := renderQoSFlows([]QoSFlow{proxy, proxy, direct}, limits)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Count(s, "192.168.3.141 . tcp . 2000 . 8.8.8.8 . 443") != 1 || strings.Count(s, "flush set") != 2 || strings.Contains(s, "table inet") || strings.Contains(s, "limit rate") {
		t.Fatalf("unexpected flow transaction: %s", s)
	}
	conflict := proxy
	conflict.Direct = true
	raw, _ = renderQoSFlows([]QoSFlow{proxy, conflict}, limits)
	if strings.Contains(string(raw), "add element") {
		t.Fatal("ambiguous tuple must use conservative fallback")
	}
	invalid := proxy
	invalid.Network = "tcp;flush ruleset"
	if _, err := renderQoSFlows([]QoSFlow{invalid}, limits); err == nil {
		t.Fatal("accepted invalid network")
	}
	if _, err := renderQoSFlows(make([]QoSFlow, 8193), limits); err == nil {
		t.Fatal("unbounded sample")
	}
}

// Opt-in real kernel validation, always in a new user + network namespace.
// This never reads or modifies the host firewall. No sudo is needed when
// unprivileged user namespaces are allowed by the host/sandbox.
func TestQoSIsolatedNamespace(t *testing.T) {
	if os.Getenv("PROXY_MANAGER_TEST_NFT_NAMESPACE") != "1" {
		t.Skip("set PROXY_MANAGER_TEST_NFT_NAMESPACE=1 for isolated nft kernel validation")
	}
	dir := t.TempDir()
	limits := map[string]DeviceLimits{"192.168.3.141": {8, 16, 4, 32}, "192.168.3.142": {0, 1, 2, 0}}
	raw, err := RenderDeviceLimits("eth0", limits)
	if err != nil {
		t.Fatal(err)
	}
	flows, err := renderQoSFlows([]QoSFlow{{"192.168.3.141", "8.8.8.8", "tcp", 2000, 443, false}, {"192.168.3.141", "1.1.1.1", "udp", 2001, 53, true}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	clear, _ := RenderDeviceLimits("eth0", nil)
	for name, data := range map[string][]byte{"qos.nft": raw, "flows.nft": flows, "clear.nft": clear} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--net", "sh", "-eu", "-c", `
 nft --check -f "$1/qos.nft"
 nft -f "$1/qos.nft"
 nft -f "$1/flows.nft"
 nft -f "$1/flows.nft"
 nft list table inet proxy_qos
 nft -f "$1/qos.nft"
 nft -f "$1/clear.nft"
 nft -f "$1/clear.nft"
 `, "validate-qos", dir)
	cmd.Env = append(os.Environ(), "PATH=/usr/sbin:/usr/bin:/sbin:/bin")
	output, err := cmd.CombinedOutput()
	if err != nil && strings.Count(string(output), "Error:") == 2 && strings.Contains(string(output), "fib daddr type") && strings.Contains(string(output), "fib saddr type") && strings.Count(string(output), "No such file or directory") == 2 {
		// Some development kernels omit nft_fib. Existing Pi interception already
		// requires it. Validate all NEW expressions without loading host modules.
		t.Log("kernel lacks nft_fib; omitting the two host-service guards in this isolated test only")
		testRaw := strings.ReplaceAll(string(raw), "  fib daddr type { local, broadcast, multicast } return\n", "")
		testRaw = strings.ReplaceAll(testRaw, "  fib saddr type local return\n", "")
		if err := os.WriteFile(filepath.Join(dir, "qos.nft"), []byte(testRaw), 0600); err != nil {
			t.Fatal(err)
		}
		retry := exec.Command(cmd.Path, cmd.Args[1:]...)
		retry.Env = cmd.Env
		output, err = retry.CombinedOutput()
	}
	if err != nil {
		t.Fatalf("isolated nft validation: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "elements = { 192.168.3.141 . tcp . 2000 . 8.8.8.8 . 443 expires") {
		t.Fatalf("flow missing: %s", output)
	}
}

func TestQoSFlowSyncUsesOnlyElementTransaction(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "nft")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat > \"$QOS_BATCH\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	batch := filepath.Join(dir, "batch")
	t.Setenv("QOS_BATCH", batch)
	m := &Manager{deviceLimits: map[string]DeviceLimits{"192.168.3.141": UniformLimits(1)}}
	if err := m.SyncQoSFlows(context.Background(), []QoSFlow{{"192.168.3.141", "8.8.8.8", "tcp", 2000, 443, false}}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(batch)
	if strings.Contains(string(raw), "limit rate") || !strings.Contains(string(raw), "add element") {
		t.Fatalf("bad update: %s", raw)
	}
	if err := m.SyncQoSFlows(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(batch)
	if strings.Contains(string(raw), "add element") {
		t.Fatal("closed flows retained")
	}
}
