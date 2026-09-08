package subscription

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	link := "vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443" +
		"?security=reality&sni=www.microsoft.com&fp=chrome&pbk=abc123XYZ&sid=0123" +
		"&flow=xtls-rprx-vision&type=tcp#US%20Node"
	n, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Protocol != ProtoVLESS {
		t.Errorf("Protocol = %q, want vless", n.Protocol)
	}
	if n.UUID != "bf000d23-0752-40b4-affe-68f7707a9661" {
		t.Errorf("UUID = %q", n.UUID)
	}
	if n.Server != "example.com" || n.Port != 443 {
		t.Errorf("addr = %s", n.Addr())
	}
	if n.Security != SecReality {
		t.Errorf("Security = %q, want reality", n.Security)
	}
	if n.SNI != "www.microsoft.com" || n.PublicKey != "abc123XYZ" || n.ShortID != "0123" {
		t.Errorf("reality fields: sni=%q pbk=%q sid=%q", n.SNI, n.PublicKey, n.ShortID)
	}
	if n.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q", n.Flow)
	}
	if n.Tag != "US Node" {
		t.Errorf("Tag = %q, want %q (fragment must be percent-decoded)", n.Tag, "US Node")
	}
}

func TestParseTrojanWS(t *testing.T) {
	// Password contains reserved chars, and security=tls is omitted — both
	// common in real subscriptions.
	link := "trojan://p%40ss%3Aword@gw.example.net:8443?type=ws&path=%2Fws&host=cdn.example.net#T1"
	n, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Password != "p@ss:word" {
		t.Errorf("Password = %q, want %q", n.Password, "p@ss:word")
	}
	if n.Security != SecTLS {
		t.Errorf("Security = %q, want tls (trojan implies TLS)", n.Security)
	}
	if n.Transport != TransportWS || n.Path != "/ws" || n.Host != "cdn.example.net" {
		t.Errorf("ws fields: transport=%q path=%q host=%q", n.Transport, n.Path, n.Host)
	}
}

func TestParseVMessBase64(t *testing.T) {
	// port and aid as JSON strings — the awkward variant real clients emit.
	raw := `{"v":"2","ps":"JP","add":"1.2.3.4","port":"443","id":"ffffffff-0000-0000-0000-000000000001","aid":"0","net":"ws","path":"/x","host":"h.example","tls":"tls","scy":"auto"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(raw))
	n, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Port != 443 {
		t.Errorf("Port = %d, want 443 (string port must parse)", n.Port)
	}
	if n.Security != SecTLS || n.Transport != TransportWS || n.Path != "/x" {
		t.Errorf("got security=%q transport=%q path=%q", n.Security, n.Transport, n.Path)
	}
	if n.Method != "auto" {
		t.Errorf("Method = %q, want auto", n.Method)
	}
}

func TestParseShadowsocksBothForms(t *testing.T) {
	// SIP002: only userinfo is base64.
	sip002 := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret")) + "@1.1.1.1:8388#SS1"
	n, err := ParseLink(sip002)
	if err != nil {
		t.Fatalf("SIP002: %v", err)
	}
	if n.Method != "aes-256-gcm" || n.Password != "secret" || n.Port != 8388 {
		t.Errorf("SIP002 got method=%q pass=%q port=%d", n.Method, n.Password, n.Port)
	}
	if n.Tag != "SS1" {
		t.Errorf("Tag = %q", n.Tag)
	}

	// Legacy: the whole body is base64.
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@2.2.2.2:9999"))
	n2, err := ParseLink(legacy)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if n2.Method != "chacha20-ietf-poly1305" || n2.Password != "pw" || n2.Port != 9999 {
		t.Errorf("legacy got method=%q pass=%q port=%d", n2.Method, n2.Password, n2.Port)
	}
}

func TestParseSubscriptionBase64AndPlain(t *testing.T) {
	links := strings.Join([]string{
		"vless://uuid-1111@a.example:443?security=tls&sni=a.example#A",
		"trojan://pw@b.example:443#B",
		"garbage-not-a-link",
		"ssh://unsupported.example:22",
	}, "\n")

	// Base64-wrapped (the normal provider case).
	nodes, errs := ParseSubscription(base64.StdEncoding.EncodeToString([]byte(links)))
	if len(nodes) != 2 {
		t.Fatalf("base64: got %d nodes, want 2 (errs: %v)", len(nodes), errs)
	}
	if len(errs) != 2 {
		t.Errorf("base64: got %d errs, want 2 (bad line + unsupported scheme)", len(errs))
	}

	// Plain text must work with no flag.
	nodes2, _ := ParseSubscription(links)
	if len(nodes2) != 2 {
		t.Fatalf("plain: got %d nodes, want 2", len(nodes2))
	}
	if nodes2[0].Tag != "A" || nodes2[1].Tag != "B" {
		t.Errorf("tags = %q, %q", nodes2[0].Tag, nodes2[1].Tag)
	}
}

func TestValidateRejectsIncomplete(t *testing.T) {
	// A VLESS link with no UUID must not silently produce a broken outbound.
	if _, err := ParseLink("vless://@example.com:443"); err == nil {
		t.Error("expected error for vless with no uuid")
	}
	if _, err := ParseLink("vless://uuid@example.com:0"); err == nil {
		t.Error("expected error for port 0")
	}
	// reality without pbk is unusable.
	if _, err := ParseLink("vless://uuid@e.com:443?security=reality"); err == nil {
		t.Error("expected error for reality with no public key")
	}
}

func TestDedupeTags(t *testing.T) {
	nodes := []Node{
		{Protocol: ProtoVLESS, Tag: "US", Server: "a"},
		{Protocol: ProtoVLESS, Tag: "US", Server: "b"},
		{Protocol: ProtoVLESS, Tag: "", Server: "c"},
		{Protocol: ProtoVLESS, Tag: "US", Server: "d"},
	}
	DedupeTags(nodes)
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.Tag == "" {
			t.Error("empty tag survived dedupe")
		}
		if seen[n.Tag] {
			t.Errorf("duplicate tag %q survived dedupe", n.Tag)
		}
		seen[n.Tag] = true
	}
}
