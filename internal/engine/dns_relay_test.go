package engine

import (
	"net"
	"testing"
)

func TestDNSPolicyFollowsIntentInsteadOfLiveness(t *testing.T) {
	m := NewManager(Options{ManagedDNS: true, DirectDNS: "192.168.3.1", Logger: quietLogger()})
	m.ConfigureDeviceRoutes(map[string]string{"192.168.3.141": DefaultDirect})
	client := net.ParseIP("192.168.3.142")
	if p := m.dnsPolicy(client); p.Primary != "" || p.Direct != "192.168.3.1:53" {
		t.Fatal(p)
	}
	m.ConfigureDNSProxy(true)
	// No process is running: this covers startup, crash and restart gaps.
	if m.Running() {
		t.Fatal("unexpected process")
	}
	if p := m.dnsPolicy(client); p.Primary != "127.0.0.1:1054" || p.Direct != "" {
		t.Fatal("proxy DNS leaked while engine absent", p)
	}
	if p := m.dnsPolicy(net.ParseIP("192.168.3.141")); p.Primary != "" || p.Direct != "192.168.3.1:53" {
		t.Fatal("explicit Direct device broken", p)
	}
	m.ConfigureDNSProxy(false)
	if p := m.dnsPolicy(client); p.Primary != "" || p.Direct != "192.168.3.1:53" {
		t.Fatal("OFF DNS unavailable", p)
	}
}
