//go:build linux

package main

import (
	"fmt"
	"strings"
	"testing"
)

// captureRun swaps gatewayRun for a recorder, treating "-C" (check)
// calls per checkErr so tests can simulate rules absent or present.
func captureRun(t *testing.T, checkErr error) *[]string {
	t.Helper()
	var cmds []string
	old := gatewayRun
	t.Cleanup(func() { gatewayRun = old })

	gatewayRun = func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		for _, a := range args {
			if a == "-C" {
				return checkErr
			}
		}
		return nil
	}
	return &cmds
}

func TestEnableMSSClampInstallsV4Only(t *testing.T) {
	cmds := captureRun(t, fmt.Errorf("not present")) // checks fail => insert

	cleanup := enableMSSClamp("wg-int", false)

	joined := strings.Join(*cmds, "\n")

	// Both chains clamped on v4, none on v6.
	for _, chain := range []string{"FORWARD", "OUTPUT"} {
		want := "iptables -t mangle -I " + chain + " -o wg-int -p tcp --tcp-flags SYN,RST SYN -m comment --comment wgmesh-mss -j TCPMSS --clamp-mss-to-pmtu"
		if !strings.Contains(joined, want) {
			t.Fatalf("missing v4 %s insert:\n%s", chain, joined)
		}
	}
	if strings.Contains(joined, "ip6tables") {
		t.Fatalf("v6 clamp installed when overlay has no IPv6:\n%s", joined)
	}

	// Teardown deletes what was installed (delete loop ends when -D errors).
	*cmds = nil
	gatewayRun = func(name string, args ...string) error {
		*cmds = append(*cmds, name+" "+strings.Join(args, " "))
		return fmt.Errorf("nothing to delete") // stop the delete loop after one try
	}
	cleanup()
	if !strings.Contains(strings.Join(*cmds, "\n"), "iptables -t mangle -D FORWARD") {
		t.Fatalf("teardown did not delete rules:\n%s", strings.Join(*cmds, "\n"))
	}
}

func TestEnableMSSClampInstallsV6WhenOverlayHasV6(t *testing.T) {
	cmds := captureRun(t, fmt.Errorf("not present"))

	enableMSSClamp("wg-int", true)

	joined := strings.Join(*cmds, "\n")
	if !strings.Contains(joined, "ip6tables -t mangle -I FORWARD -o wg-int") {
		t.Fatalf("v6 clamp not installed:\n%s", joined)
	}
	if !strings.Contains(joined, "iptables -t mangle -I FORWARD -o wg-int") {
		t.Fatalf("v4 clamp not installed:\n%s", joined)
	}
}

func TestEnableMSSClampIdempotentWhenPresent(t *testing.T) {
	cmds := captureRun(t, nil) // checks succeed => already present => no insert

	enableMSSClamp("wg-int", false)

	if strings.Contains(strings.Join(*cmds, "\n"), "-I ") {
		t.Fatalf("inserted a rule that already existed:\n%s", strings.Join(*cmds, "\n"))
	}
}
