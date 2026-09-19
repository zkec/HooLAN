package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeSplitDNS(t *testing.T) {
	for _, s := range []string{"http://1.1.1.1/dns-query", "https://u:p@example.org/dns-query", "https://example.org/#x", "https://example.org:0/dns-query"} {
		if _, _, e := NormalizeSplitDNS(s, ""); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	if _, _, e := NormalizeSplitDNS("https://dns.example.org/dns-query", "router.example"); e == nil {
		t.Fatal("direct resolver must not depend on DNS")
	}
	doh, direct, e := NormalizeSplitDNS("", "")
	if e != nil || doh != DefaultTunneledDoH || direct != DefaultDirectDNS {
		t.Fatal(doh, direct, e)
	}
}

func TestSplitDNSConfiguration(t *testing.T) {
	for _, fake := range []bool{false, true} {
		t.Run(fmt.Sprint(fake), func(t *testing.T) {
			m := NewManager(Options{Logger: quietLogger(), CacheFilePath: filepath.Join(t.TempDir(), "cache.db")})
			if e := m.ConfigureSplitDNS("https://dns.example.org:8443/lookup?x=1", "192.168.3.1:5353"); e != nil {
				t.Fatal(e)
			}
			if e := m.ConfigureFakeDNS(FakeDNSOptions{Enabled: fake}); e != nil {
				t.Fatal(e)
			}
			p := DefaultRulePolicy()
			p.Rules = []UserRule{{Name: "exception", Enabled: true, Match: "domain", Values: []string{"proxy.local.example"}, Action: "proxy"}, {Name: "local", Enabled: true, Match: "domain_suffix", Values: []string{"local.example"}, Action: "direct"}}
			if e := m.ConfigureRulePolicy(p, nil); e != nil {
				t.Fatal(e)
			}
			cfg, e := m.BuildConfig(testNodes())
			if e != nil {
				t.Fatal(e)
			}
			if cfg.DNS.Final != secureDNSServer {
				t.Fatal("client default must be encrypted")
			}
			count := 0
			for _, i := range cfg.Inbounds {
				if v, ok := i.(map[string]any); ok && v["tag"] == FakeDNSInbound {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("DNS listener count %d", count)
			}
			if cfg.Route.Rules[0].Action != "hijack-dns" {
				t.Fatal("missing early DNS action")
			}
			for _, v := range cfg.DNS.Servers {
				s := v.(map[string]any)
				if s["tag"] == secureDNSServer && (s["detour"] != DefaultSelector || s["domain_resolver"] != directDNSTag || s["path"] != "/lookup?x=1") {
					t.Fatal(s)
				}
			}
			var exceptions []string
			evaluated := false
			for _, v := range cfg.DNS.Rules {
				r := v.(map[string]any)
				if r["action"] == "evaluate" {
					evaluated = true
				}
				if r["ip_is_private"] == true && !evaluated {
					t.Fatal("response rule without evaluation")
				}
				if r["domain"] != nil {
					exceptions = append(exceptions, "proxy")
				}
				if r["domain_suffix"] != nil {
					if d, ok := r["domain_suffix"].([]string); ok && d[0] == "local.example" {
						exceptions = append(exceptions, "direct")
					}
				}
			}
			if exceptions[len(exceptions)-1] != "direct" || exceptions[0] != "proxy" {
				t.Fatal(exceptions)
			}
		})
	}
}

// Uses real sing-box, a local UDP resolver, a local DoH endpoint and an HTTP
// CONNECT proxy. No public DNS query or third-party Go package is required.
func TestRealSplitDNS(t *testing.T) {
	for _, fake := range []bool{false, true} {
		t.Run(fmt.Sprintf("fake=%v", fake), func(t *testing.T) { testRealSplitDNS(t, fake) })
	}
}
func testRealSplitDNS(t *testing.T, fake bool) {
	bin := findSingBox(t)
	var directQueries, remoteQueries, proxyConnections atomic.Int32
	var failRemote atomic.Bool
	var failedRequests atomic.Int32
	answer := func(q []byte, ip [4]byte) []byte {
		if len(q) < 12 {
			return nil
		}
		r := append([]byte(nil), q...)
		r[2] = 0x81
		r[3] = 0x80
		r[6] = 0
		r[7] = 1
		r[10] = 0
		r[11] = 0
		return append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ip[0], ip[1], ip[2], ip[3])
	}
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, a, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			directQueries.Add(1)
			udp.WriteTo(answer(buf[:n], [4]byte{192, 168, 3, 99}), a)
		}
	}()
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failRemote.Load() {
			failedRequests.Add(1)
			http.Error(w, "test failure", http.StatusServiceUnavailable)
			return
		}
		q, e := io.ReadAll(r.Body)
		if e != nil {
			return
		}
		remoteQueries.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		ip := [4]byte{8, 8, 4, 4}
		if strings.Contains(string(q), "geoip") {
			ip = [4]byte{203, 0, 113, 9}
		}
		w.Write(answer(q, ip))
	}))
	defer doh.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "CONNECT required", 405)
			return
		}
		target, e := net.DialTimeout("tcp", r.Host, time.Second)
		if e != nil {
			http.Error(w, e.Error(), 502)
			return
		}
		c, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			target.Close()
			return
		}
		proxyConnections.Add(1)
		fmt.Fprint(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { defer c.Close(); defer target.Close(); go io.Copy(target, c); io.Copy(c, target) }()
	}))
	defer proxy.Close()
	dir := t.TempDir()
	m := NewManager(Options{BinaryPath: bin, Logger: quietLogger(), ConfigPath: filepath.Join(dir, "config.json"), CacheFilePath: filepath.Join(dir, "cache.db"), DisableAutoSwitch: true})
	if e = m.ConfigureSplitDNS(doh.URL+"/dns-query", udp.LocalAddr().String()); e != nil {
		t.Fatal(e)
	}
	if e = m.ConfigureFakeDNS(FakeDNSOptions{Enabled: fake}); e != nil {
		t.Fatal(e)
	}
	policy := DefaultRulePolicy()
	policy.Rules = []UserRule{{Name: "force proxy", Enabled: true, Match: "domain", Values: []string{"remote.example"}, Action: "proxy"}, {Name: "direct", Enabled: true, Match: "domain_suffix", Values: []string{"example"}, Action: "direct"}}
	if e = m.ConfigureRulePolicy(policy, nil); e != nil {
		t.Fatal(e)
	}
	cfg, e := m.BuildConfig(testNodes())
	if e != nil {
		t.Fatal(e)
	}
	// Local source rule sets make Iran policy deterministic and offline.
	for i := range cfg.Route.RuleSet {
		rs := &cfg.Route.RuleSet[i]
		path := filepath.Join(dir, rs.Tag+".json")
		rule := `{"version":3,"rules":[{"domain_suffix":["ir"]}]}`
		if rs.Tag == TagGeoIPIR {
			rule = `{"version":3,"rules":[{"ip_cidr":["203.0.113.0/24"]}]}`
		}
		if e = os.WriteFile(path, []byte(rule), 0600); e != nil {
			t.Fatal(e)
		}
		*rs = RuleSet{Type: "local", Tag: rs.Tag, Format: "source", Path: path}
	}
	if e = m.WriteConfig(cfg); e != nil {
		t.Fatal(e)
	}
	if e = m.Check(context.Background()); e != nil {
		t.Fatal(e)
	}
	dnsPort, e := freeTCPPort()
	if e != nil {
		t.Fatal(e)
	}
	cfg.Inbounds = []any{map[string]any{"type": "direct", "tag": FakeDNSInbound, "listen": "127.0.0.1", "listen_port": dnsPort}}
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(proxy.URL, "http://"))
	pn, _ := strconv.Atoi(port)
	cfg.Outbounds = []any{map[string]any{"type": "http", "tag": DefaultSelector, "server": host, "server_port": pn}, map[string]any{"type": "direct", "tag": DefaultDirect}, map[string]any{"type": "direct", "tag": DefaultFetchOutbound, "connect_timeout": "5s"}}
	for _, v := range cfg.DNS.Servers {
		s := v.(map[string]any)
		if s["tag"] == secureDNSServer {
			s["tls"].(map[string]any)["insecure"] = true
		}
	} // Only trust this test's ephemeral certificate.
	if e = m.WriteConfig(cfg); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "-c", m.ConfigPath())
	logFile, e := os.Create(filepath.Join(dir, "log"))
	if e != nil {
		t.Fatal(e)
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cancel(); cmd.Wait() }()
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	for deadline := time.Now().Add(5 * time.Second); ; {
		c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(logFile.Name())
			t.Fatalf("DNS start: %s", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	query := func(domain string) []byte {
		t.Helper()
		q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, s := range strings.Split(domain, ".") {
			q = append(q, byte(len(s)))
			q = append(q, s...)
		}
		q = append(q, 0, 0, 1, 0, 1)
		c, e := net.Dial("tcp", addr)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(4 * time.Second))
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(len(q)))
		c.Write(append(b, q...))
		if _, e = io.ReadFull(c, b); e != nil {
			if failRemote.Load() {
				return nil
			}
			t.Fatal(e)
		}
		r := make([]byte, int(binary.BigEndian.Uint16(b)))
		if _, e = io.ReadFull(c, r); e != nil {
			t.Fatal(e)
		}
		if failRemote.Load() {
			// FakeDNS may still allocate a synthetic answer; the later real lookup
			// fails when the client connects. It must never query Direct DNS instead.
			if fake && len(r) >= 16 && r[3]&15 == 0 {
				ip := net.IP(r[len(r)-4:]).String()
				if !strings.HasPrefix(ip, "198.18.") && !strings.HasPrefix(ip, "198.19.") {
					t.Fatal("unexpected fallback answer", ip)
				}
				return nil
			}
			if len(r) < 12 || r[3]&15 == 0 {
				t.Fatalf("failure should return DNS error, got %x", r)
			}
			return nil
		}
		if len(r) < 16 || r[3]&15 != 0 {
			t.Fatalf("bad DNS response %x", r)
		}
		return r[len(r)-4:]
	}
	for _, name := range []string{"printer.lan", "direct.example", "domestic.ir"} {
		if ip := net.IP(query(name)).String(); ip != "192.168.3.99" {
			t.Fatal(name, ip)
		}
	}
	if remoteQueries.Load() != 0 || directQueries.Load() != 3 {
		t.Fatal("known bypass leaked to remote resolver", remoteQueries.Load(), directQueries.Load())
	}
	for _, name := range []string{"remote.example", "public.test"} {
		ip := net.IP(query(name)).String()
		if fake {
			if !strings.HasPrefix(ip, "198.18.") && !strings.HasPrefix(ip, "198.19.") {
				t.Fatal("expected FakeIP", name, ip)
			}
		} else if ip != "8.8.4.4" {
			t.Fatal(name, ip)
		}
	}
	if proxyConnections.Load() == 0 {
		t.Fatal("DoH bypassed the proxy")
	}
	if ip := net.IP(query("geoip.test")).String(); ip != "192.168.3.99" {
		t.Fatal("GeoIP response did not select Direct DNS", ip)
	}
	expectedRemote := int32(3)
	if fake {
		expectedRemote = 2
	}
	if directQueries.Load() != 4 || remoteQueries.Load() != expectedRemote {
		t.Fatal("unexpected query counts", directQueries.Load(), remoteQueries.Load())
	}
	failRemote.Store(true)
	query("failure.test")
	if directQueries.Load() != 4 || failedRequests.Load() == 0 {
		t.Fatal("remote error fell back to Direct DNS or failure was not exercised")
	}
}
