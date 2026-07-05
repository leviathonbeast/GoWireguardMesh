//go:build linux

package firewall

import (
	"strings"
	"testing"
)

// fakeRunner records commands and returns canned success.
type fakeRunner struct {
	cmds []string
}

func (f *fakeRunner) run(name string, args ...string) (string, error) {
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	return "", nil
}

func managerWith(b backend, f *fakeRunner) *Manager {
	return &Manager{tag: "wgmesh-test", backend: b, run: f.run}
}

func TestIptablesSinglePortAddAndRemove(t *testing.T) {
	f := &fakeRunner{}
	m := managerWith(iptablesBackend{}, f)

	if err := m.AllowUDP(51820); err != nil {
		t.Fatalf("AllowUDP: %v", err)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	want := []string{
		"iptables -I INPUT -p udp --dport 51820 -j ACCEPT -m comment --comment wgmesh-test",
		"iptables -D INPUT -p udp --dport 51820 -j ACCEPT -m comment --comment wgmesh-test",
	}

	if len(f.cmds) != len(want) {
		t.Fatalf("got %d commands, want %d: %v", len(f.cmds), len(want), f.cmds)
	}

	for i := range want {
		if f.cmds[i] != want[i] {
			t.Fatalf("cmd %d = %q, want %q", i, f.cmds[i], want[i])
		}
	}
}

func TestFirewalldRangeSyntax(t *testing.T) {
	f := &fakeRunner{}
	m := managerWith(firewalldBackend{}, f)

	if err := m.AllowUDPRange(51900, 51909); err != nil {
		t.Fatalf("AllowUDPRange: %v", err)
	}

	if got, want := f.cmds[0], "firewall-cmd --add-port=51900-51909/udp"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUfwRangeUsesColon(t *testing.T) {
	f := &fakeRunner{}
	m := managerWith(ufwBackend{}, f)

	if err := m.AllowUDPRange(51900, 51909); err != nil {
		t.Fatalf("AllowUDPRange: %v", err)
	}

	if got, want := f.cmds[0], "ufw allow 51900:51909/udp comment wgmesh-test"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNftablesTeardownDeletesOwnTableOnly(t *testing.T) {
	f := &fakeRunner{}
	m := managerWith(nftablesBackend{}, f)

	if err := m.AllowTCP(8443); err != nil {
		t.Fatalf("AllowTCP: %v", err)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	last := f.cmds[len(f.cmds)-1]
	if want := "nft delete table inet wgmesh-test"; last != want {
		t.Fatalf("teardown = %q, want %q", last, want)
	}
}

func TestNoBackendIsSafeNoop(t *testing.T) {
	m := &Manager{tag: "wgmesh-test", run: nil} // backend nil, runner unused

	if err := m.AllowUDP(51820); err != nil {
		t.Fatalf("AllowUDP on nil backend: %v", err)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close on nil backend: %v", err)
	}
}
