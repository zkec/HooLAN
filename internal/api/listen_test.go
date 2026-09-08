package api

// Tests for the readiness probe that replaced the old dial-based check.
//
// The dial version connected to 127.0.0.1:TPROXY_PORT, which the tproxy inbound
// accepts as a real client connection and then routes -- seeding the
// self-connection loop this project spent a long time chasing. These tests pin
// the replacement: prove the listener is bound by reading the kernel socket
// table, and generate no traffic doing it.

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestTCPPortIsListeningFindsRealListener(t *testing.T) {
	// A real bound socket, so the parser is tested against the kernel's actual
	// /proc format rather than a fixture that could drift from it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	listening, err := tcpPortIsListening(port)
	if err != nil {
		t.Fatalf("tcpPortIsListening: %v", err)
	}
	if !listening {
		t.Errorf("port %d is bound but was reported as not listening", port)
	}
}

func TestTCPPortIsListeningIgnoresClosedPort(t *testing.T) {
	// Bind then release: the port is almost certainly free, and a false positive
	// here would make waitEngineListening return before the engine is ready,
	// loading nftables rules against a closed port and blackholing the LAN.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	listening, err := tcpPortIsListening(port)
	if err != nil {
		t.Fatalf("tcpPortIsListening: %v", err)
	}
	if listening {
		t.Errorf("port %d was closed but reported as listening", port)
	}
}

func TestTCPPortIsListeningToleratesMissingTCP6(t *testing.T) {
	// ipv6.disable=1 removes /proc/net/tcp6. That is an absence, not a failure,
	// and must not break enable() on such a kernel.
	orig := procTCPFiles
	procTCPFiles = []string{"/proc/net/tcp", "/proc/net/does-not-exist"}
	defer func() { procTCPFiles = orig }()

	if _, err := tcpPortIsListening(9); err != nil {
		t.Errorf("missing socket table should be skipped, got %v", err)
	}
}

func TestScanProcTCPListen(t *testing.T) {
	// 0x1ED4 == 7892, the default TPROXY port. Column layout copied from a live
	// /proc/net/tcp; only the columns the parser reads have to be faithful.
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1ED4 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 0100007F:1F40 0100007F:C001 01 00000000:00000000 00:00000000 00000000     0        0 12346 1
`
	// The v6 form of listening on "::" -- what the engine's default Listen
	// produces, and the case a loopback-only check would miss.
	const table6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1ED4 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1
`
	tests := []struct {
		name string
		in   string
		port int
		want bool
	}{
		{"listening v4", table, 7892, true},
		{"listening v6 wildcard", table6, 7892, true},
		// 0x1F40 == 8000, present in the table but in state 01 (ESTABLISHED).
		// An established connection to a port is not a listener on it.
		{"established is not listening", table, 8000, false},
		{"absent port", table, 9999, false},
		{"header only", "  sl  local_address rem_address   st\n", 7892, false},
		{"empty", "", 7892, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanProcTCPListen(strings.NewReader(tc.in),
				fmt.Sprintf("%04X", tc.port), "0A")
			if err != nil {
				t.Fatalf("scanProcTCPListen: %v", err)
			}
			if got != tc.want {
				t.Errorf("port %d: got %v, want %v", tc.port, got, tc.want)
			}
		})
	}
}

func TestScanProcTCPListenPortMatchIsExact(t *testing.T) {
	// A substring match on the hex port would confuse 0x1ED4 (7892) with
	// 0x11ED4, and matching the address half would be worse still: 0x1ED4 also
	// appears inside plenty of addresses.
	const table = `  sl  local_address rem_address   st
   0: 1ED40000:0050 00000000:0000 0A
`
	got, err := scanProcTCPListen(strings.NewReader(table), fmt.Sprintf("%04X", 7892), "0A")
	if err != nil {
		t.Fatalf("scanProcTCPListen: %v", err)
	}
	if got {
		t.Error("matched 1ED4 in the address column; only the port may be compared")
	}
}
