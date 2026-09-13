package netfilter

import (
	"strings"
	"testing"
)

func TestRestoreConfigRejectsExecutableShell(t *testing.T) {
	valid := "LAN_IF=eth0\nTPROXY_PORT=7892\nTPROXY_FWMARK=0x1\nTPROXY_TABLE=100\nPI_LAN_IP=192.168.3.5\n"
	if err := ValidateBackupConfig([]byte(valid), 7892); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{valid + "LD_PRELOAD=/tmp/x\n", valid + "SELF_ORIGIN_NETS=\"$(id)\"\n", strings.Replace(valid, "LAN_IF=eth0", "LAN_IF=eth0;id", 1), strings.Replace(valid, "TPROXY_TABLE=100", "TPROXY_TABLE=254", 1), strings.Replace(valid, "TPROXY_FWMARK=0x1", "TPROXY_FWMARK=0", 1), valid + "TPROXY_PORT=7892\n"} {
		if err := ValidateBackupConfig([]byte(bad), 7892); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
}
