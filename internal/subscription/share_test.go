package subscription

import (
	"strings"
	"testing"
)

func TestShareLinksRoundTrip(t *testing.T) {
	for _, raw := range []string{
		"vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=reality&sni=example.com&pbk=key&sid=ab&fp=chrome&flow=xtls-rprx-vision#name",
		"trojan://secret%3Apw@example.com:443?type=ws&host=cdn.example&path=%2Fws&allowInsecure=1#name",
		"ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#name",
	} {
		n, err := ParseLink(raw)
		if err != nil {
			t.Fatal(err)
		}
		n.Tag = "تهران + 50%"
		link, err := ShareLink(n)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseLink(link)
		if err != nil {
			t.Fatal(err)
		}
		if got.Tag != n.Tag || got.Password != n.Password || got.UUID != n.UUID || got.Flow != n.Flow || got.PublicKey != n.PublicKey || got.Insecure != n.Insecure || got.Path != n.Path {
			t.Fatalf("round trip lost settings: %+v", got)
		}
	}
	n := Node{Protocol: ProtoVMess, Tag: "فارسی", Server: "vm.example", Port: 443, UUID: "a", Security: SecTLS, Transport: TransportGRPC, ServiceName: "grpc", Insecure: true}
	link, err := ShareLink(n)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseLink(link)
	if err != nil || !got.Insecure || got.ServiceName != n.ServiceName {
		t.Fatal("VMess settings lost")
	}
	n.Detour = "hop"
	if _, err := ShareLink(n); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatal("chain silently exported")
	}
}
