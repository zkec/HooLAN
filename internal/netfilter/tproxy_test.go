package netfilter

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePort(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		port         int
		wantErr      bool
	}{
		{"quoted", "TPROXY_PORT=\"7892\"\n", 7892, false},
		{"last assignment", "TPROXY_PORT=7891\nTPROXY_PORT='7892'\n", 7892, false},
		{"mismatch", "TPROXY_PORT=7893\n", 7892, true},
		{"missing", "# TPROXY_PORT=7892\n", 7892, true},
		{"shell expansion", "TPROXY_PORT=\"$PORT\"\n", 7892, true},
		{"invalid", "TPROXY_PORT=70000\n", 7892, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := filepath.Join(t.TempDir(), "tproxy.conf")
			writeTestFile(t, conf, tc.config, 0600)
			m := NewWithPaths("", "", conf)
			if err := m.ValidatePort(tc.port); (err != nil) != tc.wantErr {
				t.Fatalf("ValidatePort error = %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// These tests execute the actual lifecycle scripts with isolated command mocks.
// They never invoke the host nft/ip/sysctl or modify a real firewall. Kernel
// socket assignment still requires an integration check on a Linux gateway.
func TestScriptApplyReplaceAndRemove(t *testing.T) {
	f := newScriptFixture(t)
	f.run(t, "apply.sh", false)
	active := f.read(t, "active.nft")
	if !strings.Contains(active, "add table inet proxy_tproxy\ndelete table inet proxy_tproxy\ntable inet proxy_tproxy") {
		t.Fatal("apply must replace its table and sets within one nft transaction")
	}
	for _, want := range []string{
		`iifname != "eth0" accept`, "priority mangle", "fib daddr type { local, broadcast, multicast }",
		"ip daddr 10.42.42.0/24", "tproxy ip to :7892 meta mark set 0x1 counter name tproxy_assigned_tcp accept",
		"tproxy_attempt_udp", "tproxy_failed_udp", "marked_input", "marked_output",
	} {
		if !strings.Contains(active, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, forbidden := range []string{"ct state", "masquerade", "\nflush ruleset", "{{"} {
		if strings.Contains(active, forbidden) {
			t.Errorf("unsafe or incomplete rendered content: %q", forbidden)
		}
	}
	// A second apply must neither append rules nor duplicate policy routes.
	f.run(t, "apply.sh", false)
	if f.read(t, "active.nft") != active {
		t.Fatal("second apply appended or changed rules")
	}
	if got := strings.Count(f.read(t, "rules"), "fwmark"); got != 1 {
		t.Fatalf("policy rule count = %d", got)
	}
	// Live subnet changes must replace set elements, rather than merge old ones.
	f.env = append(f.env, "MOCK_LAN_PREFIX=192.168.44.5/23")
	f.run(t, "apply.sh", false)
	updated := f.read(t, "active.nft")
	if strings.Contains(updated, "192.168.3.5/24") || !strings.Contains(updated, "192.168.44.5/23") {
		t.Fatal("reload did not replace LAN address set")
	}
	f.run(t, "remove.sh", false)
	if _, err := os.Stat(filepath.Join(f.dir, "active.nft")); !os.IsNotExist(err) {
		t.Fatal("owned firewall table remains after remove")
	}
	if strings.Contains(f.read(t, "rules"), "fwmark") {
		t.Fatal("owned policy rules remain after remove")
	}
	f.run(t, "remove.sh", false)
	calls := f.read(t, "calls")
	if strings.Contains(calls, "flush") || strings.Contains(calls, "delete table inet docker") {
		t.Fatal("lifecycle touched unrelated network state")
	}
}

func TestScriptValidationFailureKeepsActiveRules(t *testing.T) {
	f := newScriptFixture(t)
	f.run(t, "apply.sh", false)
	before := f.read(t, "active.nft")
	rules := f.read(t, "rules")
	f.env = append(f.env, "MOCK_NFT_CHECK_FAIL=1")
	f.run(t, "apply.sh", true)
	if f.read(t, "active.nft") != before || f.read(t, "rules") != rules {
		t.Fatal("validation failure changed live firewall or routing")
	}
}

func TestScriptRemoveFailurePreservesRouting(t *testing.T) {
	f := newScriptFixture(t)
	f.run(t, "apply.sh", false)
	rules := f.read(t, "rules")
	f.env = append(f.env, "MOCK_NFT_LIST_FAIL=1")
	f.run(t, "remove.sh", true)
	if f.read(t, "rules") != rules {
		t.Fatal("remove discarded local routing without verifying firewall removal")
	}
}

func TestDiagnoseIsReadOnly(t *testing.T) {
	f := newScriptFixture(t)
	f.run(t, "diagnose.sh", false)
	calls := f.read(t, "calls")
	for _, forbidden := range []string{"rule add", "rule del", "route replace", "route del", "sysctl -w", "nft -f", "delete table"} {
		if strings.Contains(calls, forbidden) {
			t.Errorf("diagnostics performed mutation %q", forbidden)
		}
	}
}

type scriptFixture struct {
	dir, scripts string
	env          []string
}

func newScriptFixture(t *testing.T) *scriptFixture {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ip", "nft", "sysctl", "id", "ss", "iptables", "nstat", "systemctl", "sing-box"} {
		writeTestFile(t, filepath.Join(bin, name), mockNetworkCommand, 0700)
	}
	writeTestFile(t, filepath.Join(dir, "rules"), "0: from all lookup 255\n32766: from all lookup 254\n", 0600)
	conf := filepath.Join(dir, "tproxy.conf")
	writeTestFile(t, conf, "LAN_IF=\"eth0\"\nTPROXY_PORT=\"7892\"\nTPROXY_FWMARK=\"0x1\"\nTPROXY_TABLE=\"100\"\nPI_LAN_IP=\"192.168.3.5\"\nWG_RP_FILTER=\"no\"\n", 0600)
	scripts, err := filepath.Abs("../../scripts/tproxy")
	if err != nil {
		t.Fatal(err)
	}
	return &scriptFixture{dir: dir, scripts: scripts, env: append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"), "CONF_FILE="+conf,
		"RUNTIME_DIR="+filepath.Join(dir, "run"), "MOCK_NETWORK_DIR="+dir,
		"CLIENT_IP=192.168.3.50", "NODE_IP=8.8.8.8")}
}

func (f *scriptFixture) run(t *testing.T, script string, wantErr bool) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join(f.scripts, script))
	cmd.Env = f.env
	out, err := cmd.CombinedOutput()
	if (err != nil) != wantErr {
		t.Fatalf("%s error=%v wantErr=%v\n%s", script, err, wantErr, out)
	}
}

func (f *scriptFixture) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeTestFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

const mockNetworkCommand = `#!/usr/bin/env bash
set -eu
name="${0##*/}"
printf '%s %s\n' "$name" "$*" >> "$MOCK_NETWORK_DIR/calls"
case "$name $*" in
  'id -u') echo 0 ;;
  'nft --check -f '*) [[ "${MOCK_NFT_CHECK_FAIL:-0}" != 1 ]] ;;
  'nft -f '*)
    if grep -q '^delete table inet proxy_tproxy$' "$2"; then
      cp "$2" "$MOCK_NETWORK_DIR/active.nft"
    else cat "$2" >> "$MOCK_NETWORK_DIR/active.nft"; fi ;;
  'nft list tables')
    [[ "${MOCK_NFT_LIST_FAIL:-0}" != 1 ]] || exit 1
    echo 'table inet docker'
    if [[ -f "$MOCK_NETWORK_DIR/active.nft" ]]; then echo 'table inet proxy_tproxy'; fi ;;
  'nft delete table inet proxy_tproxy') rm "$MOCK_NETWORK_DIR/active.nft" ;;
  'ip -4 -o addr show dev eth0 scope global') echo "2: eth0 inet ${MOCK_LAN_PREFIX:-192.168.3.5/24} brd 192.168.3.255 scope global eth0" ;;
  'ip -4 -N rule show') cat "$MOCK_NETWORK_DIR/rules" ;;
  'ip -4 rule add priority '*)
    printf '%s: from all fwmark %s lookup %s\n' "$5" "$7" "$9" >> "$MOCK_NETWORK_DIR/rules" ;;
  'ip -4 rule del '*)
    pref=''; mark=''; table=''
    while [[ $# -gt 0 ]]; do
      case "$1" in priority) pref="$2"; shift;; fwmark) mark="$2"; shift;; lookup) table="$2"; shift;; esac
      shift
    done
    if ! grep -q "fwmark $mark lookup $table" "$MOCK_NETWORK_DIR/rules"; then exit 2; fi
    awk -v pref="$pref" -v mark="$mark" -v table="$table" '
      !removed && (pref=="" || $1==pref ":") && $4=="fwmark" && $5==mark && $7==table { removed=1; next } {print}' \
      "$MOCK_NETWORK_DIR/rules" > "$MOCK_NETWORK_DIR/rules.new"
    mv "$MOCK_NETWORK_DIR/rules.new" "$MOCK_NETWORK_DIR/rules" ;;
  'sysctl -n net.ipv4.ip_forward') echo 1 ;;
  *) : ;;
esac
`
