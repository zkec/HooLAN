package netfilter

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLANNeighborStates(t *testing.T) {
	neighbors, err := parseDeviceNeighbors([]byte(`[{"dst":"192.168.3.2","state":["REACHABLE"]},{"dst":"192.168.3.3","state":["STALE"]},{"dst":"192.168.3.4","state":["FAILED"]},{"dst":"192.168.3.5","state":["PERMANENT"]},{"dst":"8.8.8.8","state":["REACHABLE"]},{"dst":"fe80::1","state":["REACHABLE"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(neighbors) != 4 || !neighbors["192.168.3.2"] || neighbors["192.168.3.3"] || neighbors["192.168.3.4"] || neighbors["192.168.3.5"] {
		t.Fatal("cached neighbours mistaken for confirmed online")
	}
	if _, err := parseDeviceNeighbors([]byte("bad")); err == nil {
		t.Fatal("malformed JSON accepted")
	}
}
func TestDeviceNeighborsUsesLANAndBoundedOutput(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "tproxy.conf")
	args := filepath.Join(dir, "args")
	if err := os.WriteFile(conf, []byte("LAN_IF=eth0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PRESENCE_ARGS\"\nprintf '%s' '[{\"dst\":\"192.168.3.2\",\"state\":[\"REACHABLE\"]}]'\n"
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("PRESENCE_ARGS", args)
	m := NewWithPaths("", "", conf)
	neighbors, err := m.DeviceNeighbors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !neighbors["192.168.3.2"] {
		t.Fatal("reachable neighbour missing")
	}
	raw, err := os.ReadFile(args)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "-j\n-4\nneigh\nshow\ndev\neth0\n" {
		t.Fatalf("unexpected commands: %s", raw)
	}
	if err := os.WriteFile(conf, []byte("LAN_IF='eth0;false'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DeviceNeighbors(context.Background()); err == nil {
		t.Fatal("interface injection accepted")
	}
	var output cappedOutput
	output.limit = 4
	n, err := output.Write([]byte(strings.Repeat("x", 100)))
	if err != nil || n != 100 || !output.overflow || output.Len() != 4 {
		t.Fatal("command output unbounded")
	}
	if _, bypassesWrite := any(&output).(io.ReaderFrom); bypassesWrite {
		t.Fatal("io.Copy can bypass the output limit")
	}
	var copied cappedOutput
	copied.limit = 4
	if _, err := io.Copy(&copied, struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 100))}); err != nil || copied.Len() != 4 || !copied.overflow {
		t.Fatal("pipe draining bypassed output limit")
	}
}
