//go:build !linux

package tester

import "syscall"

// Non-Linux stub so the package builds on a dev machine. Without Setpgid,
// stop() falls back to killing only the leader.
func sysProcAttr() *syscall.SysProcAttr { return nil }

func killGroup(int) {}
