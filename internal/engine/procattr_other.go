//go:build !linux

package engine

import (
	"errors"
	"os"
	"syscall"
)

// Non-Linux stubs so the package still builds on a dev laptop (macOS/Windows).
// Pdeathsig is Linux-only; on other platforms Stop falls back to signalling the
// process leader, and there is no cgroup-kill backstop. The deployment target
// is a bare-metal Debian host, so this path is for `go build`/`go test` convenience only.

func sysProcAttr() *syscall.SysProcAttr { return nil }

func sigTerm() os.Signal { return os.Interrupt }

func terminateGroup(int) error {
	return errors.ErrUnsupported
}

func killGroup(int) error {
	return errors.ErrUnsupported
}
