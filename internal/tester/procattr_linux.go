//go:build linux

package tester

import "syscall"

// Probe engines get their own process group so stop() can signal the whole
// group. A probe that outlived the sweep would keep its SOCKS port bound and
// make the next sweep's port allocation flaky.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

func killGroup(pid int) {
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}
