// Package hidecmd builds exec.Cmds that never flash a console window.
//
// On Windows, a console subprocess (netsh, powershell) spawned from a
// GUI-subsystem process pops up its own console for the duration of
// the call — alarming when the agent GUI re-syncs DNS every report
// tick. The Windows variant hides that window; elsewhere this is
// exec.Command unchanged. Elevation is unaffected: UAC prompts come
// from ShellExecute("runas"), never from these child processes.
package hidecmd

import "os/exec"

// Command returns an exec.Cmd whose child console window is hidden on
// Windows.
func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd
}
