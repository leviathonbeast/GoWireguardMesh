//go:build !windows

package hidecmd

import "os/exec"

func hideWindow(*exec.Cmd) {}
