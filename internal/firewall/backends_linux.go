//go:build linux

package firewall

import (
	"fmt"
	"strings"
)

// detect probes for an ACTIVE firewall, in order of how opinionated
// the tool is: firewalld and ufw are full managers that get upset
// when bypassed, so they win over raw nftables/iptables. A merely
// installed-but-inactive tool must not match — that is why firewalld
// and ufw are probed by state, not by binary presence.
func detect(run runner) backend {
	if out, err := run("firewall-cmd", "--state"); err == nil && strings.Contains(out, "running") {
		return firewalldBackend{}
	}

	if out, err := run("ufw", "status"); err == nil && strings.Contains(out, "Status: active") {
		return ufwBackend{}
	}

	if _, err := run("nft", "list", "tables"); err == nil {
		return nftablesBackend{}
	}

	if _, err := run("iptables", "-S", "INPUT"); err == nil {
		return iptablesBackend{}
	}

	return nil
}

// --- firewalld ---
//
// Runtime rules only, on purpose: they vanish on reload/reboot, and
// the component re-adds them at startup. Persistent rules would
// outlive the component and leave holes.

type firewalldBackend struct{}

func (firewalldBackend) name() string { return "firewalld" }

func firewalldPort(r Rule) string {
	if r.PortMin == r.PortMax {
		return fmt.Sprintf("%d/%s", r.PortMin, r.Proto)
	}

	return fmt.Sprintf("%d-%d/%s", r.PortMin, r.PortMax, r.Proto)
}

func (firewalldBackend) allowCmds(_ string, r Rule) [][]string {
	return [][]string{{"firewall-cmd", "--add-port=" + firewalldPort(r)}}
}

func (firewalldBackend) removeCmds(_ string, r Rule) [][]string {
	return [][]string{{"firewall-cmd", "--remove-port=" + firewalldPort(r)}}
}

func (firewalldBackend) teardownCmds(string) [][]string { return nil }

// --- ufw ---

type ufwBackend struct{}

func (ufwBackend) name() string { return "ufw" }

func ufwPort(r Rule) string {
	if r.PortMin == r.PortMax {
		return fmt.Sprintf("%d/%s", r.PortMin, r.Proto)
	}

	return fmt.Sprintf("%d:%d/%s", r.PortMin, r.PortMax, r.Proto)
}

func (ufwBackend) allowCmds(tag string, r Rule) [][]string {
	return [][]string{{"ufw", "allow", ufwPort(r), "comment", tag}}
}

func (ufwBackend) removeCmds(_ string, r Rule) [][]string {
	return [][]string{{"ufw", "--force", "delete", "allow", ufwPort(r)}}
}

func (ufwBackend) teardownCmds(string) [][]string { return nil }

// --- nftables ---
//
// Owns one table per component tag; teardown deletes the whole table,
// which removes every rule the component added in one shot and cannot
// touch anything else on the host.

type nftablesBackend struct{}

func (nftablesBackend) name() string { return "nftables" }

func nftPort(r Rule) string {
	if r.PortMin == r.PortMax {
		return fmt.Sprintf("%d", r.PortMin)
	}

	return fmt.Sprintf("%d-%d", r.PortMin, r.PortMax)
}

func (nftablesBackend) allowCmds(tag string, r Rule) [][]string {
	return [][]string{
		// Both "add"s are idempotent; repeating them per rule is fine.
		{"nft", "add", "table", "inet", tag},
		{"nft", "add", "chain", "inet", tag, "input",
			"{", "type", "filter", "hook", "input", "priority", "-10", ";", "}"},
		{"nft", "add", "rule", "inet", tag, "input", r.Proto, "dport", nftPort(r), "accept"},
	}
}

func (nftablesBackend) removeCmds(string, Rule) [][]string { return nil }

func (nftablesBackend) teardownCmds(tag string) [][]string {
	return [][]string{{"nft", "delete", "table", "inet", tag}}
}

// --- iptables ---

type iptablesBackend struct{}

func (iptablesBackend) name() string { return "iptables" }

func iptablesPort(r Rule) string {
	if r.PortMin == r.PortMax {
		return fmt.Sprintf("%d", r.PortMin)
	}

	return fmt.Sprintf("%d:%d", r.PortMin, r.PortMax)
}

func iptablesCmd(action, tag string, r Rule) []string {
	return []string{
		"iptables", action, "INPUT",
		"-p", r.Proto, "--dport", iptablesPort(r),
		"-j", "ACCEPT",
		"-m", "comment", "--comment", tag,
	}
}

func (iptablesBackend) allowCmds(tag string, r Rule) [][]string {
	return [][]string{iptablesCmd("-I", tag, r)}
}

func (iptablesBackend) removeCmds(tag string, r Rule) [][]string {
	return [][]string{iptablesCmd("-D", tag, r)}
}

func (iptablesBackend) teardownCmds(string) [][]string { return nil }
