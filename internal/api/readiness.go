package api

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TPROXY is IPv4 and targets whichever local address belongs to ingress. A
// loopback-only or IPv6-only listener cannot satisfy that contract. Inodes
// also prevent an unrelated process on the same port from passing readiness.
func tproxySocketsReady(pid, port int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	fds, err := os.ReadDir(filepath.Join(base, "fd"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read sing-box sockets: %w", err)
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
			return false, nil
		}
		if err != nil {
			return false, err
		}
		ready, scanErr := scanOwnedIPv4Socket(f, port, table.state, owned)
		f.Close()
		if scanErr != nil {
			return false, scanErr
		}
		if !ready {
			return false, nil
		}
	}
	return true, nil
}

func scanOwnedIPv4Socket(r io.Reader, port int, state string, owned map[string]bool) (bool, error) {
	want := fmt.Sprintf("00000000:%04X", port)
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) > 9 && strings.EqualFold(fields[1], want) && fields[3] == state && owned[fields[9]] {
			return true, nil
		}
	}
	return false, scan.Err()
}
