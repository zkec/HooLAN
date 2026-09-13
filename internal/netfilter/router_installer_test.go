package netfilter

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run only the embedded renderer against temporary UFW fixtures, never reload
// UFW or write any host configuration. This exercises the installed script's
// mark validation and managed-block replacement, not a duplicate renderer.
func TestRouterInstallerUsesValidatedConfiguredMark(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python 3 not installed")
	}
	raw, err := os.ReadFile("../../scripts/tproxy/install-router.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok := strings.Cut(string(raw), "<<'PY'\n")
	if !ok {
		t.Fatal("missing renderer")
	}
	body, _, ok = strings.Cut(body, "\nPY\n")
	if !ok {
		t.Fatal("missing renderer end")
	}
	dir := t.TempDir()
	ufw := filepath.Join(dir, "ufw")
	sysctl := filepath.Join(dir, "sysctl.d")
	for _, path := range []string{ufw, sysctl} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	before := filepath.Join(ufw, "before.rules")
	settings := filepath.Join(ufw, "sysctl.conf")
	for path, data := range map[string]string{before: "*filter\n:ufw-before-input - [0:0]\n:ufw-before-forward - [0:0]\n-A ufw-before-input -i lo -j ACCEPT\nCOMMIT\n", settings: "# site settings\n"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	body = strings.ReplaceAll(body, "/etc/ufw/", ufw+"/")
	body = strings.ReplaceAll(body, "/etc/sysctl.d/", sysctl+"/")
	for i := 0; i < 2; i++ {
		output, err := exec.Command(python, "-c", body, "eth0", "192.168.3.0/24", "0x21").CombinedOutput()
		if err != nil {
			t.Fatalf("render: %v %s", err, output)
		}
	}
	installed, err := os.ReadFile(before)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(installed), "--mark 0x21/0xffffffff") != 2 || strings.Count(string(installed), "-j MASQUERADE") != 1 {
		t.Fatalf("wrong mark or duplicate blocks: %s", installed)
	}
	if output, err := exec.Command(python, "-c", body, "eth0", "192.168.3.0/24", "0x1; bad").CombinedOutput(); err == nil {
		t.Fatalf("accepted invalid mark: %s", output)
	}
	after, _ := os.ReadFile(before)
	if string(after) != string(installed) {
		t.Fatal("invalid mark changed configuration")
	}
}
