package api

import (
	"fmt"
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
