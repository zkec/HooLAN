package netfilter

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFakeDNSQoSObservationsAndAmbiguity(t *testing.T) {
	raw := []byte(`{"nftables":[{"metainfo":{}},{"set":{"name":"fakedns_flows","elem":[{"elem":{"val":{"concat":["192.168.3.141","tcp",2000,"198.18.0.1",443]},"expires":4500}},{"concat":["192.168.3.141",17,2001,"198.18.0.2",443]}]}}]}`)
	observed, err := parseFakeDNSFlows(raw)
	if err != nil {
		t.Fatal(err)
	}
	direct := QoSFlow{SourceIP: "192.168.3.141", Network: "tcp", SourcePort: 2000, DestinationPort: 443, Direct: true}
	proxy := QoSFlow{SourceIP: "192.168.3.141", Network: "udp", SourcePort: 2001, DestinationPort: 443}
	real := direct
	real.SourcePort = 2002
	real.DestinationIP = "8.8.8.8"
	got := recoverFakeDNSFlows([]QoSFlow{direct, proxy, real}, observed)
	wantDirect := direct
	wantDirect.DestinationIP = "198.18.0.1"
	wantProxy := proxy
	wantProxy.DestinationIP = "198.18.0.2"
	if !reflect.DeepEqual(got, []QoSFlow{wantDirect, wantProxy, real}) {
		t.Fatalf("lost original destinations/classes: %+v", got)
	}
	collision := observed[0]
	collision.DestinationIP = "198.18.0.3"
	if got := recoverFakeDNSFlows([]QoSFlow{direct}, append(observed, collision)); len(got) != 0 {
		t.Fatal("ambiguous socket guessed a destination")
	}
	conflict := direct
	conflict.Direct = false
	if got := recoverFakeDNSFlows([]QoSFlow{direct, conflict}, observed); len(got) != 0 {
		t.Fatal("conflicting classes guessed a destination")
	}
	if got := recoverFakeDNSFlows([]QoSFlow{direct}, nil); len(got) != 0 {
		t.Fatal("missing observation guessed a destination")
	}
	for _, bad := range []string{`{}`, strings.Replace(string(raw), "198.18.0.1", "8.8.8.8", 1), strings.Replace(string(raw), "2000", "999999", 1)} {
		if _, err := parseFakeDNSFlows([]byte(bad)); err == nil {
			t.Fatal("invalid observations accepted")
		}
	}
}

func TestFakeDNSQoSRecordsBothDirectionsOnlyForLimitedDevices(t *testing.T) {
	raw, err := renderDeviceLimits("eth0", "0x1", map[string]DeviceLimits{"192.168.3.141": UniformLimits(1)})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"flags dynamic,timeout; timeout 5s; size 8192",
		"ip daddr 198.18.0.0/15 meta l4proto { tcp, udp } update @fakedns_flows { ip saddr . meta l4proto . th sport . ip daddr . th dport timeout 5s }",
		"ip saddr 198.18.0.0/15 meta l4proto { tcp, udp } update @fakedns_flows { ip daddr . meta l4proto . th dport . ip saddr . th sport timeout 5s }",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Count(s, "update @fakedns_flows") != 2 {
		t.Fatal("observations not confined to device chains")
	}
	empty, _ := renderDeviceLimits("eth0", "0x1", nil)
	if strings.Contains(string(empty), "fakedns_flows") {
		t.Fatal("allocated observations without limits")
	}
}

// Optional kernel validation in a NEW user/network namespace. Never load rules
// into the host firewall. Enable with HOOLAN_CHECK_NFT=1 on a capable Linux host.
// Omit the existing fib service exclusions: some development kernels lack
// nft_fib_inet. The new tuple set, updates and classifier are unchanged.
func TestFakeDNSQoSIsolatedNftCheck(t *testing.T) {
	if os.Getenv("HOOLAN_CHECK_NFT") != "1" {
		t.Skip("set HOOLAN_CHECK_NFT=1 for isolated nft syntax checking")
	}
	raw, err := renderDeviceLimits("eth0", "0x1", map[string]DeviceLimits{"192.168.3.141": UniformLimits(1)})
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.ReplaceAll(strings.ReplaceAll(string(raw), "  fib daddr type { local, broadcast, multicast } return\n", ""), "  fib saddr type local return\n", ""))
	f := newScriptFixture(t)
	f.env = append(f.env, "HOOLAN_FAKEDNS=true")
	f.run(t, "apply.sh", false)
	rendered := f.read(t, "active.nft")
	guardStart := strings.Index(rendered, "add table inet hoolan_fakedns")
	if guardStart < 0 {
		t.Fatal("generated FakeDNS guard missing")
	}
	raw = append(raw, rendered[guardStart:]...)
	path := filepath.Join(t.TempDir(), "qos.nft")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "unshare", "-Urn", "sh", "-c", `set -e
/usr/sbin/nft -f "$1"
/usr/sbin/nft add element inet proxy_qos fakedns_flows '{ 192.168.3.141 . tcp . 2000 . 198.18.0.1 . 443 }'
/usr/sbin/nft -j list set inet proxy_qos fakedns_flows
`, "nft-test", path).CombinedOutput()
	if err != nil {
		t.Fatalf("isolated nft check: %v: %s", err, out)
	}
	observed, err := parseFakeDNSFlows(out)
	if err != nil || len(observed) != 1 || observed[0].DestinationIP != "198.18.0.1" {
		t.Fatalf("real nft JSON: %+v %v: %s", observed, err, out)
	}
}
