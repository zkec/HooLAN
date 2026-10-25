package netfilter

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// ContainerBinding is a validated opt-in endpoint. Owner groups all addresses
// of one container into the same four rate buckets, even on multiple bridges.
type ContainerBinding struct {
	IP, Bridge, Owner string
	Proxy             bool
}

func (m *Manager) ConfigureContainers(bindings []ContainerBinding) error {
	seen := map[string]ContainerBinding{}
	if len(bindings) > 256 {
		return fmt.Errorf("at most 256 managed container endpoints are supported")
	}
	for _, b := range bindings {
		if !interfacePattern.MatchString(b.Bridge) || b.Bridge == "lo" || b.Owner == "" {
			return fmt.Errorf("invalid container bridge or identity")
		}
		if err := ValidateDeviceLimits(map[string]DeviceLimits{b.IP: {}}); err != nil {
			return err
		}
		if old, ok := seen[b.IP]; ok && old.Owner != b.Owner {
			return fmt.Errorf("ambiguous container IP")
		}
		seen[b.IP] = b
	}
	m.qosMu.Lock()
	defer m.qosMu.Unlock()
	m.containerBindings = append([]ContainerBinding(nil), bindings...)
	return nil
}
func renderContainers(bindings []ContainerBinding) []byte {
	var entries []string
	seen := map[string]bool{}
	for _, b := range bindings {
		key := fmt.Sprintf("%q . %s", b.Bridge, b.IP)
		if b.Proxy && !seen[key] {
			entries = append(entries, key)
			seen[key] = true
		}
	}
	sort.Strings(entries)
	if len(entries) == 0 {
		return []byte("chain container_dispatch {}\n")
	}
	return []byte(`set container_sources {
 type ifname . ipv4_addr;
 elements = { ` + strings.Join(entries, ", ") + ` }
}
chain container_dispatch {
 # Replies from published container services must keep Docker's normal path.
 ct direction reply return
 iifname . ip saddr @container_sources jump container_intercept
}
chain container_intercept {
 fib daddr type { local, broadcast, multicast } accept
 ip daddr @lan_cidrs accept
 ip daddr @bypass_daddrs accept
 jump intercept
 accept
}
`)
}
func (m *Manager) containerFile() (string, func(), error) {
	f, err := os.CreateTemp("", "hoolan-containers-*.nft")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { os.Remove(f.Name()) }
	_, err = f.Write(renderContainers(m.containerBindings))
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return f.Name(), cleanup, nil
}
