package netfilter

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerOptInProtectsPublishedReplies(t *testing.T) {
	bindings := []ContainerBinding{{IP: "172.18.0.3", Bridge: "br-stack", Owner: "app", Proxy: true}, {IP: "172.18.0.4", Bridge: "br-stack", Owner: "direct", Proxy: false}}
	m := new(Manager)
	if err := m.ConfigureContainers(bindings); err != nil {
		t.Fatal(err)
	}
	raw := string(renderContainers(bindings))
	for _, want := range []string{`"br-stack" . 172.18.0.3`, "ct direction reply return", "fib daddr type { local, broadcast, multicast } accept", "ip daddr @bypass_daddrs accept", "jump intercept"} {
		if !strings.Contains(raw, want) {
			t.Error("missing " + want)
		}
	}
	if strings.Contains(raw, "172.18.0.4") {
		t.Fatal("direct container intercepted")
	}
	if err := m.ConfigureContainers([]ContainerBinding{{IP: "8.8.8.8", Bridge: "br-stack", Owner: "app"}}); err == nil {
		t.Fatal("public address accepted")
	}
	if err := m.ConfigureContainers([]ContainerBinding{{IP: "172.18.0.3", Bridge: `bad";drop`, Owner: "app"}}); err == nil {
		t.Fatal("interface injection accepted")
	}
}
func TestContainerEndpointsShareBuckets(t *testing.T) {
	l := DeviceLimits{ProxyUpload: 8, ProxyDownload: 16, DirectUpload: 4, DirectDownload: 12}
	limits := map[string]DeviceLimits{"172.18.0.3": l, "172.19.0.3": l, "192.168.3.141": UniformLimits(10)}
	bindings := []ContainerBinding{{IP: "172.18.0.3", Bridge: "br-stack", Owner: "app", Proxy: true}, {IP: "172.19.0.3", Bridge: "br-other", Owner: "app", Proxy: true}}
	raw, err := renderEndpointLimits("eth0", "0x1", limits, bindings)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"172.18.0.3 : jump device_0_up", "172.19.0.3 : jump device_0_up", "192.168.3.141 : jump device_1_up", `iifname != { "br-other", "br-stack", "eth0" } return`, `oifname != { "br-other", "br-stack", "eth0" } return`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(s, "limit rate over") != 8 {
		t.Fatal("one container gained duplicate rate buckets")
	}
	limits["172.19.0.3"] = UniformLimits(1)
	if _, err := renderEndpointLimits("eth0", "0x1", limits, bindings); err == nil {
		t.Fatal("inconsistent aggregate limit accepted")
	}
}

// Validate new expressions in an isolated namespace, never the host firewall.
func TestContainerIsolatedNamespace(t *testing.T) {
	if os.Getenv("HOOLAN_CHECK_NFT") != "1" {
		t.Skip("set HOOLAN_CHECK_NFT=1 for isolated nft kernel checks")
	}
	bindings := []ContainerBinding{{IP: "172.18.0.3", Bridge: "br-stack", Owner: "app", Proxy: true}, {IP: "172.19.0.3", Bridge: "br-other", Owner: "app", Proxy: true}}
	qos, err := renderEndpointLimits("eth0", "0x1", map[string]DeviceLimits{"172.18.0.3": UniformLimits(8), "172.19.0.3": UniformLimits(8)}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	raw := `table inet proxy_tproxy {
 set lan_cidrs {type ipv4_addr;flags interval;elements={192.168.3.0/24};}
 set bypass_daddrs {type ipv4_addr;flags interval;elements={10.0.0.0/8,172.16.0.0/12};}
 chain intercept { counter accept; }
 ` + string(renderContainers(bindings)) + `chain prerouting {type filter hook prerouting priority -150;policy accept;meta nfproto ipv4 jump container_dispatch;}
 }
 ` + string(qos)
	// nft_fib is already required by the host gateway. This development kernel
	// may omit it; this check exercises container concat sets, conntrack direction
	// and shared-bucket interface dispatch without touching host kernel modules.
	for _, line := range []string{" fib daddr type { local, broadcast, multicast } accept\n", "  fib daddr type { local, broadcast, multicast } return\n", "  fib saddr type local return\n"} {
		raw = strings.ReplaceAll(raw, line, "")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "container.nft")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-Urn", "sh", "-eu", "-c", `/usr/sbin/nft --check -f "$1"
 /usr/sbin/nft -f "$1"
 /usr/sbin/nft list table inet proxy_tproxy
 /usr/sbin/nft list table inet proxy_qos`, "container-check", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated nft check: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ct direction reply return") || !strings.Contains(string(out), "172.19.0.3 : jump device_0_up") {
		t.Fatalf("missing kernel rules: %s", out)
	}
}
