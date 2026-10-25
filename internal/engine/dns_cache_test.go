package engine

import (
	"bytes"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the generated evaluate/respond policy with the installed engine,
// rather than assuming that cache options imply working cache behaviour.
func TestRealSplitDNSCacheExpiryAndRestart(t *testing.T) {
	bin := findSingBox(t)
	var calls atomic.Int32
	var blockRefresh, offline atomic.Bool
	refreshStarted := make(chan struct{}, 1)
	releaseRefresh := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		q, err := io.ReadAll(r.Body)
		if err != nil || len(q) < 12 {
			return
		}
		if offline.Load() {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		if blockRefresh.Load() {
			select {
			case refreshStarted <- struct{}{}:
			default:
			}
			select {
			case <-releaseRefresh:
			case <-r.Context().Done():
				return
			}
		}
		ttl := uint32(60)
		if strings.Contains(string(q), "expiry") {
			ttl = 1
		}
		answer := append([]byte(nil), q...)
		answer[2], answer[3], answer[7] = 0x81, 0x80, 1
		answer[10], answer[11] = 0, 0
		answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 8, 8, 4, 4)
		binary.BigEndian.PutUint32(answer[len(q)+6:], ttl)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answer)
	}))
	defer doh.Close()
	// Unblock handlers before httptest closes them if an assertion fails.
	defer release()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		target, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			target.Close()
			return
		}
		defer client.Close()
		defer target.Close()
		fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go io.Copy(target, client)
		io.Copy(client, target)
	}))
	defer proxy.Close()
	dir := t.TempDir()
	m := NewManager(Options{BinaryPath: bin, ConfigPath: filepath.Join(dir, "config.json"), CacheFilePath: filepath.Join(dir, "cache.db"), DisableIranBypass: true, DisableAutoSwitch: true, Logger: quietLogger()})
	if err := m.ConfigureSplitDNS(doh.URL+"/dns-query", "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	policy := DefaultRulePolicy()
	policy.Rules = []UserRule{{Name: "address check", Enabled: true, Match: "ip_cidr", Values: []string{"203.0.113.0/24"}, Action: "direct"}}
	if err := m.ConfigureRulePolicy(policy, nil); err != nil {
		t.Fatal(err)
	}
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Log.Level = "debug"
	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Inbounds = []any{map[string]any{"type": "direct", "tag": FakeDNSInbound, "listen": "127.0.0.1", "listen_port": port}}
	host, portString, _ := net.SplitHostPort(strings.TrimPrefix(proxy.URL, "http://"))
	proxyPort, _ := strconv.Atoi(portString)
	cfg.Outbounds = []any{map[string]any{"type": "http", "tag": DefaultSelector, "server": host, "server_port": proxyPort}, map[string]any{"type": "direct", "tag": DefaultDirect}}
	for _, value := range cfg.DNS.Servers {
		s := value.(map[string]any)
		if s["tag"] == secureDNSServer {
			s["tls"].(map[string]any)["insecure"] = true // Ephemeral local test certificate only.
		}
	}
	if err := m.WriteConfig(cfg); err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	start := func() func() {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		log, err := os.CreateTemp(dir, "engine-log-")
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, bin, "run", "-c", m.ConfigPath())
		cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
		cmd.WaitDelay = 3 * time.Second
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			cancel()
			log.Close()
			t.Fatal(err)
		}
		var once sync.Once
		stop := func() { once.Do(func() { cancel(); cmd.Wait(); log.Close() }) }
		t.Cleanup(stop)
		t.Cleanup(func() {
			if t.Failed() {
				output, _ := os.ReadFile(log.Name())
				t.Logf("engine: %s", output)
			}
		})
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err == nil {
				c.Close()
				return stop
			}
			if time.Now().After(deadline) {
				output, _ := os.ReadFile(log.Name())
				t.Fatalf("DNS listener did not start: %s", output)
			}
		}
	}
	query := func(name string) ([]byte, error) {
		q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, label := range strings.Split(name, ".") {
			q = append(q, byte(len(label)))
			q = append(q, label...)
		}
		q = append(q, 0, 0, 1, 0, 1)
		c, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		frame := make([]byte, len(q)+2)
		binary.BigEndian.PutUint16(frame, uint16(len(q)))
		copy(frame[2:], q)
		if _, err := c.Write(frame); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c, frame[:2]); err != nil {
			return nil, err
		}
		r := make([]byte, binary.BigEndian.Uint16(frame[:2]))
		_, err = io.ReadFull(c, r)
		return r, err
	}
	check := func(name string) {
		t.Helper()
		r, err := query(name)
		if err != nil || len(r) < 16 || r[3]&15 != 0 || net.IP(r[len(r)-4:]).String() != "8.8.4.4" {
			t.Fatalf("DNS answer for %s: %x, %v", name, r, err)
		}
	}
	stop := start()
	check("expiry.test")
	check("expiry.test")
	if calls.Load() != 1 {
		t.Fatal("ordinary cache hit queried the upstream again")
	}
	blockRefresh.Store(true)
	time.Sleep(1100 * time.Millisecond)
	// This call must return while the upstream refresh remains blocked.
	check("expiry.test")
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("expired answer did not start a background refresh")
	}
	release()
	blockRefresh.Store(false)
	check("persist.test")
	// sing-box queues disk writes asynchronously; shutdown does not wait for
	// that queue. Wait for this fixture's record before testing a restart.
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		data, err := os.ReadFile(filepath.Join(dir, "cache.db"))
		if err == nil && bytes.Contains(data, []byte("persist.test.")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DNS answer was not written to the persistent cache")
		}
	}
	stop()
	before := calls.Load()
	offline.Store(true)
	start()
	check("persist.test")
	if calls.Load() != before {
		t.Fatal("engine restart discarded the persisted DNS answer")
	}
}
