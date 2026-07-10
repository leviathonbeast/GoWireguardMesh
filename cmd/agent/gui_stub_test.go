//go:build !windows || !gui

package main

import "testing"

// The non-gui build recognizes only the explicit subcommand, so plain
// invocations still run the console agent.
func TestWantGUIStub(t *testing.T) {
	if wantGUI([]string{"agent"}) {
		t.Fatal("bare invocation must not open the GUI in a non-gui build")
	}
	if !wantGUI([]string{"agent", "gui"}) {
		t.Fatal("explicit gui subcommand not recognized")
	}
	if wantGUI([]string{"agent", "--server", "x"}) {
		t.Fatal("flag invocation misrouted to GUI")
	}
}
