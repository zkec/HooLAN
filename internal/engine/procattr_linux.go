//go:build linux

package engine

import (
	"errors"
	"os"
	"syscall"
)

// Clean child termination has three layers here, because no single one is
// sufficient on Linux:
//
//  1. Setpgid — puts sing-box in its own process group so Stop can signal the
//     whole group. Without it, helpers sing-box spawns survive a leader-only
//     signal and keep the TPROXY port bound, making the next Start fail with
//     "address already in use".
//
//  2. Pdeathsig — the kernel sends SIGTERM to the child when the *thread* that
//     called clone(2) exits. Caveat: that is the OS thread, not the process.
//     Go's scheduler can retire an idle thread at any time, which would kill
//     sing-box spuriously. Guarding against that properly requires
//     runtime.LockOSThread() on the goroutine that calls cmd.Start() and never
//     releasing it — which costs a permanently pinned thread. We accept the
//     small risk instead, because layer 3 is the real guarantee and Pdeathsig
//     here is just a best-effort net for a SIGKILLed parent (where no Go code
//     runs at all, so Stop never gets a chance).
//
//  3. systemd cgroup kill — the actual guarantee. The unit must use
//     KillMode=control-group (the default) so systemd kills every process in
//     the unit's cgroup, including sing-box, regardless of how the Go parent
//     died. Do NOT set KillMode=process: that leaves sing-box running with the
//     nftables rules still loaded, which is the worst state to be in.
//
// Suggested unit:
//
//	[Service]
//	ExecStart=/usr/local/bin/hoolan
//	KillMode=control-group
//	Restart=on-failure
//	AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGTERM,
	}
}

func sigTerm() os.Signal { return syscall.SIGTERM }

// terminateGroup sends SIGTERM to the child's entire process group.
// The negative pid is the group-signal convention: kill(-pgid, sig).
func terminateGroup(pid int) error {
	return syscall.Kill(-pid, syscall.SIGTERM)
}

// killGroup sends an unignorable SIGKILL to the child's process group.
func killGroup(pid int) error {
	if pid <= 0 {
		return errors.New("engine: invalid pid")
	}
	return syscall.Kill(-pid, syscall.SIGKILL)
}
