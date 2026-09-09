package engine

import "testing"

func TestManualSelectionRemovesBackgroundProbes(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		m := NewManager(Options{Logger: quietLogger(), DisableAutoSwitch: disabled})
		for _, auto := range []bool{true, false, true} {
			m.ConfigureAutoSelection(auto)
			cfg, err := m.BuildConfig(testNodes())
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, outbound := range cfg.Outbounds {
				if _, ok := outbound.(*URLTestOutbound); ok {
					found = true
				}
				if selector, ok := outbound.(*SelectorOutbound); ok {
					for _, member := range selector.Outbounds {
						if member == DefaultURLTest && (!auto || disabled) {
							t.Fatal("selector references disabled URLTest group")
						}
					}
				}
			}
			if found != (auto && !disabled) {
				t.Fatalf("auto=%v disabled=%v: URLTest present=%v", auto, disabled, found)
			}
		}
	}
}

func TestRuntimeDNSAndIranSettings(t *testing.T) {
	m := NewManager(Options{Logger: quietLogger()})
	if err := m.ConfigureRouting("9.9.9.9:5353", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := m.BuildConfig(testNodes())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Route.RuleSet) != 0 {
		t.Fatal("Iran sets retained when disabled")
	}
	if cfg.Route.DefaultDomainResolver == nil || cfg.Route.DefaultDomainResolver.Server != DefaultResolverTag {
		t.Fatal("disabling Iran removed outbound DNS resolver")
	}
	server := cfg.DNS.Servers[0].(map[string]any)
	if server["type"] != "udp" || server["server"] != "9.9.9.9" || server["server_port"] != 5353 {
		t.Fatalf("DNS: %+v", server)
	}
	if err := m.ConfigureRouting("", true); err != nil {
		t.Fatal(err)
	}
	cfg, err = m.BuildConfig(testNodes())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Route.RuleSet) == 0 || cfg.DNS.Servers[0].(map[string]any)["type"] != "local" {
		t.Fatal("settings could not be restored")
	}
}

func TestNormalizeDNSAddress(t *testing.T) {
	for _, input := range []string{"", "1.1.1.1", "127.0.0.1:53", "2606:4700:4700::1111", "[2606:4700:4700::1111]:5353"} {
		if _, err := NormalizeDNSServer(input); err != nil {
			t.Errorf("%q: %v", input, err)
		}
	}
	for _, input := range []string{"1.1.1.1:0", "1.1.1.1:65536", "example.com", "https://1.1.1.1", "0.0.0.0", "::", "224.0.0.1", "[fe80::1%eth0]:53"} {
		if _, err := NormalizeDNSServer(input); err == nil {
			t.Errorf("invalid %q accepted", input)
		}
	}
}
