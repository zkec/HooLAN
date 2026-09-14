package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFakeDNSConfiguration(t *testing.T) {
	for _, iran := range []bool{false, true} {
		m := NewManager(Options{Logger: quietLogger(), CacheFilePath: filepath.Join(t.TempDir(), "cache.db"), DisableIranBypass: !iran})
		if err := m.ConfigureFakeDNS(FakeDNSOptions{Enabled: true, Listen: "192.168.3.5"}); err != nil {
			t.Fatal(err)
		}
		cfg, err := m.BuildConfig(testNodes())
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Experimental.CacheFile.StoreFakeIP {
			t.Fatal("FakeIP mappings will be lost on restart")
		}
		if cfg.DNS.Final == fakeIPServer || cfg.Route.DefaultDomainResolver.Server == fakeIPServer {
			t.Fatal("bootstrap must never use synthetic answers")
		}
		for _, s := range cfg.DNS.Servers {
			v := s.(map[string]any)
			if v["type"] == "udp" || v["type"] == "local" {
				t.Fatal("plaintext resolver retained")
			}
		}
		resolve, private := -1, -1
		for i, r := range cfg.Route.Rules {
			if r.Action == "resolve" {
				resolve = i
			}
			if r.IPIsPrivate && r.Outbound == DefaultDirect {
				private = i
			}
		}
		if resolve < 0 || private <= resolve {
			t.Fatal("IP bypass rules evaluated before real resolution")
		}
		guard := cfg.Route.Rules[resolve+1]
		if guard.Action != "reject" || !guard.IPIsPrivate || len(guard.Port) == 0 {
			t.Fatal("resolved private domains bypass the self-dial guard")
		}
		if cfg.Route.Rules[0].Action != "hijack-dns" || cfg.Route.Rules[1].Port[0] != 53 {
			t.Fatal("DNS must precede sniff/routing")
		}
		for _, r := range cfg.DNS.Rules {
			if len(r.(map[string]any)["inbound"].([]string)) < 2 {
				t.Fatal("client DNS rule is not scoped to client inbounds")
			}
		}
	}
}

func TestFakeDNSValidation(t *testing.T) {
	for _, ip := range []string{"0.0.0.0", "::", "8.8.8.8", "192.168.3.5:53", "192.168.3.5; drop", "fe80::1", ""} {
		_, err := NormalizeFakeDNS(FakeDNSOptions{Listen: ip})
		if (err == nil) != (ip == "") {
			t.Fatalf("validation %q: %v", ip, err)
		}
	}
	m := NewManager(Options{Logger: quietLogger()})
	if err := m.ConfigureFakeDNS(FakeDNSOptions{Enabled: true}); err == nil {
		t.Fatal("missing persistent cache accepted")
	}
}

// Run the real DNS engine on loopback with no privileged TPROXY binding and
// no upstream network requests. Check the original generated schema first.
func TestRealSingBoxFakeDNSAnswersPersist(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()
	m := NewManager(Options{BinaryPath: bin, Logger: quietLogger(), ConfigPath: filepath.Join(dir, "config.json"), CacheFilePath: filepath.Join(dir, "cache.db"), DisableIranBypass: true, DisableAutoSwitch: true})
	if err := m.ConfigureFakeDNS(FakeDNSOptions{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatal(err)
	}
	if err = m.WriteConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err = m.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	clashPort, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Experimental.ClashAPI = &ClashAPIOptions{ExternalController: fmt.Sprintf("127.0.0.1:%d", clashPort)}
	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	// Dedicated DNS is an ordinary direct inbound. Keep all DNS/route rules.
	mixedPort, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Inbounds = []any{
		map[string]any{"type": "direct", "tag": FakeDNSInbound, "listen": "127.0.0.1", "listen_port": port},
		map[string]any{"type": "mixed", "tag": m.opts.InboundTag, "listen": "127.0.0.1", "listen_port": mixedPort},
	}
	// Substitute only the real-lookup transport with an offline hosts server.
	// The config check above covered the production TLS/DoH shape. This fixture
	// verifies recovery of a FakeIP destination and private-IP bypass routing.
	for i, server := range cfg.DNS.Servers {
		if server.(map[string]any)["tag"] == secureDNSServer {
			cfg.DNS.Servers[i] = map[string]any{"type": "hosts", "tag": secureDNSServer, "predefined": map[string]any{"mapped.example": []string{"127.0.0.1"}}}
		}
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.Copy(c, c)
	}()

	if err = m.WriteConfig(cfg); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	start := func() func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		out := &lockedBuffer{}
		cmd := exec.CommandContext(ctx, bin, "run", "-c", m.ConfigPath(), "-D", dir)
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		stop := func() {
			_ = cmd.Process.Signal(os.Interrupt)
			err := cmd.Wait()
			cancel()
			if err != nil {
				t.Errorf("engine exit: %v: %s", err, out.String())
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err == nil {
				c.Close()
				return stop
			}
			time.Sleep(25 * time.Millisecond)
		}
		stop()
		t.Fatalf("DNS did not start: %s", out.String())
		return nil
	}
	query := func(name string, typ uint16, tcp bool) []byte {
		t.Helper()
		msg := []byte{0x42, 0x10, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, label := range strings.Split(name, ".") {
			msg = append(msg, byte(len(label)))
			msg = append(msg, label...)
		}
		msg = append(msg, 0, byte(typ>>8), byte(typ), 0, 1)
		network := "udp"
		if tcp {
			network = "tcp"
		}
		c, err := net.DialTimeout(network, addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		wire := msg
		if tcp {
			wire = append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)
		}
		if _, err = c.Write(wire); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 4096)
		var n int
		if tcp {
			header := make([]byte, 2)
			if _, err = io.ReadFull(c, header); err != nil {
				t.Fatal(err)
			}
			n = int(binary.BigEndian.Uint16(header))
			if n > len(response) {
				t.Fatal("oversized DNS response")
			}
			_, err = io.ReadFull(c, response[:n])
		} else {
			n, err = c.Read(response)
		}
		if err != nil {
			t.Fatal(err)
		}
		response = response[:n]
		if n < 12 || binary.BigEndian.Uint16(response[:2]) != 0x4210 || response[3]&15 != 0 {
			t.Fatalf("DNS error: %x", response)
		}
		return response
	}
	var first [4]byte
	func() {
		stop := start()
		defer stop()
		// Allocate another address first so restarting the allocator from scratch
		// cannot accidentally pass the mapping persistence assertion.
		query("first.example", 1, false)
		r := query("mapped.example", 1, false)
		if binary.BigEndian.Uint16(r[6:8]) != 1 {
			t.Fatalf("missing A record: %x", r)
		}
		copy(first[:], r[len(r)-4:])
		if !netip.MustParsePrefix(FakeDNSRange).Contains(netip.AddrFrom4(first)) {
			t.Fatalf("not FakeIP: %v", first)
		}
		for _, typ := range []uint16{28, 64, 65} {
			r = query("mapped.example", typ, true)
			if binary.BigEndian.Uint16(r[6:8]) != 0 {
				t.Fatal("IPv6 or address hints escaped")
			}
		}
	}()
	stop := start()
	defer stop()
	r := query("mapped.example", 1, true)
	var second [4]byte
	copy(second[:], r[len(r)-4:])
	if first != second {
		t.Fatalf("restart lost mapping: %v -> %v", first, second)
	}
	// Connect to the cached synthetic address after restart. A plain payload has
	// no SNI/Host to rescue routing if FakeIP domain recovery is broken.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", mixedPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 2)
	if _, err = io.ReadFull(c, auth); err != nil || !bytes.Equal(auth, []byte{5, 0}) {
		t.Fatalf("SOCKS auth: %x %v", auth, err)
	}
	dstPort := echo.Addr().(*net.TCPAddr).Port
	request := append([]byte{5, 1, 0, 1}, first[:]...)
	request = append(request, byte(dstPort>>8), byte(dstPort))
	if _, err = c.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err = io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		t.Fatalf("FakeIP connect: %x %v", reply, err)
	}
	payload := []byte("hoolan-fakeip-roundtrip")
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(c, received); err != nil || !bytes.Equal(payload, received) {
		t.Fatalf("recovered domain did not reach direct target: %q %v", received, err)
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/connections", clashPort))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Connections []struct {
			Metadata struct {
				DestinationIP string `json:"destinationIP"`
				Host          string `json:"host"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	err = json.NewDecoder(response.Body).Decode(&snapshot)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Connections) != 1 || snapshot.Connections[0].Metadata.Host != "mapped.example" {
		t.Fatalf("missing connection metadata: %+v", snapshot)
	}
	// Upstream reports a domain without destinationIP for a FakeIP connection.
	// Keep the kernel-observation QoS fallback covered against this real schema.
	if snapshot.Connections[0].Metadata.DestinationIP != "" {
		t.Log("engine now exposes destinationIP; review whether QoS fallback is still needed")
	}

}
