package api

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestReadinessScansAllPortsAndPreservesSocketContract(t *testing.T) {
	var table strings.Builder
	for _, v := range []struct {
		port               int
		addr, state, inode string
	}{
		{7892, "00000000", "0A", "123"},
		{7893, "00000000", "0A", "123"},
		{7894, "0100007F", "0A", "123"},
		{7895, "00000000", "0A", "456"},
		{7896, "00000000", "07", "123"},
	} {
		fmt.Fprintf(&table, "0: %s:%04X 00000000:0000 %s 0:0 00:0 0 0 0 %s 1\n", v.addr, v.port, v.state, v.inode)
	}
	ready, err := scanOwnedIPv4Sockets(strings.NewReader(table.String()), []int{7892, 7893, 7894, 7895, 7896}, "0A", map[string]bool{"123": true})
	if err != nil || len(ready) != 2 || !ready[7892] || !ready[7893] {
		t.Fatalf("wrong listener membership: %v %v", ready, err)
	}
}

func TestFakeDNSReadinessRequiresOwnedExactBindAndBothProtocols(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	port := tcp.Addr().(*net.TCPAddr).Port
	if ready, err := fakeDNSSocketsReady(os.Getpid(), "127.0.0.1", port); err != nil || ready {
		t.Fatalf("TCP alone passed: %v %v", ready, err)
	}
	udp, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if ready, err := fakeDNSSocketsReady(os.Getpid(), "127.0.0.1", port); err != nil || !ready {
		t.Fatalf("owned DNS listener missed: %v %v", ready, err)
	}
	if ready, err := fakeDNSSocketsReady(os.Getpid(), "192.168.3.5", port); err != nil || ready {
		t.Fatalf("wrong bind passed: %v %v", ready, err)
	}
	if ready, err := tproxySocketsReady(os.Getpid(), port); err != nil || ready {
		t.Fatalf("FakeDNS change weakened TPROXY wildcard requirement: %v %v", ready, err)
	}
}
