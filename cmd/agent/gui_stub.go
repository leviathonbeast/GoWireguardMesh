//go:build !windows || !gui

package main

import "errors"

// wantGUI reports whether the user asked for the desktop GUI. Builds
// without the gui tag only recognize the explicit subcommand, so they
// can point at the right binary instead of silently parsing "gui" as a
// flag error.
func wantGUI(args []string) bool {
	return len(args) > 1 && args[1] == "gui"
}

func launchGUI() error {
	return errors.New(`this build does not include the GUI; use agent-gui.exe (or build one with: go build -tags gui -ldflags "-H windowsgui" ./cmd/agent)`)
}
