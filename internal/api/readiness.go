package api

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TPROXY is IPv4 and targets whichever local address belongs to ingress. A
// loopback-only or IPv6-only listener cannot satisfy that contract. Inodes
// also prevent an unrelated process on the same port from passing readiness.
func tproxySocketsReady(pid, port int) (bool, error) {
	ready, _, err := tproxyPortsReady(pid, []int{port})
	return ready, err
}

// Read descriptors and each protocol table once per readiness poll, regardless
// of how many load-balancer listeners exist.
func tproxyPortsReady(pid int, ports []int) (bool, int, error) {
	return ipv4PortsReady(pid, ports, "00000000")
}
func ipv4PortsReady(pid int, ports []int, address string) (bool, int, error) {
	if len(ports) == 0 {
		return true, 0, nil
	}
	port := ports[0]
	if pid <= 0 {
		return false, port, nil
	}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	fds, err := os.ReadDir(filepath.Join(base, "fd"))
	if errors.Is(err, os.ErrNotExist) {
		return false, port, nil
	}
	if err != nil {
		return false, port, fmt.Errorf("read sing-box sockets: %w", err)
	}
	owned := make(map[string]bool)
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") {
			owned[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	for _, table := range []struct{ name, state string }{{"tcp", "0A"}, {"udp", "07"}} {
		f, err := os.Open(filepath.Join(base, "net", table.name))
		if errors.Is(err, os.ErrNotExist) {
			return false, port, nil
		}
		if err != nil {
			return false, port, err
		}
		ready, scanErr := scanOwnedIPv4BoundSockets(f, ports, table.state, owned, address)
		f.Close()
		if scanErr != nil {
			return false, port, scanErr
		}
		for _, candidate := range ports {
			if !ready[candidate] {
				return false, candidate, nil
			}
		}
	}
	return true, 0, nil
}

func scanOwnedIPv4Socket(r io.Reader, port int, state string, owned map[string]bool) (bool, error) {
	ready, err := scanOwnedIPv4Sockets(r, []int{port}, state, owned)
	return ready[port], err
}
func scanOwnedIPv4Sockets(r io.Reader, ports []int, state string, owned map[string]bool) (map[int]bool, error) {
	return scanOwnedIPv4BoundSockets(r, ports, state, owned, "00000000")
}
func scanOwnedIPv4BoundSockets(r io.Reader, ports []int, state string, owned map[string]bool, address string) (map[int]bool, error) {
	wanted := make(map[string]int, len(ports))
	for _, port := range ports {
		wanted[fmt.Sprintf("%s:%04X", address, port)] = port
	}
	ready := make(map[int]bool, len(ports))
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) <= 9 || fields[3] != state || !owned[fields[9]] {
			continue
		}
		if port, ok := wanted[strings.ToUpper(fields[1])]; ok {
			ready[port] = true
		}
	}
	return ready, scan.Err()
}

func fakeDNSSocketsReady(pid int, listen string, port int) (bool, error) {
	ip, err := netip.ParseAddr(listen)
	if err != nil || !ip.Is4() {
		return false, fmt.Errorf("invalid FakeDNS listener address")
	}
	raw := ip.As4()
	address := fmt.Sprintf("%08X", binary.NativeEndian.Uint32(raw[:]))
	ready, _, err := ipv4PortsReady(pid, []int{port}, address)
	return ready, err
}
