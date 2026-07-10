//go:build windows

package hidecmd

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// hideWindow keeps the child from creating or showing a console.
// CREATE_NO_WINDOW prevents console allocation outright; HideWindow
// (STARTF_USESHOWWINDOW + SW_HIDE) covers children that show a window
// anyway.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
}
