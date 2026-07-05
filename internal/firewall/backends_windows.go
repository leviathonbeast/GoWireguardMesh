//go:build windows

package firewall

import (
	"fmt"
	"strings"
)

// detect probes Windows Defender Firewall via netsh. When the
// firewall service is off entirely, no rules are needed and no
// backend is returned.
func detect(run runner) backend {
	out, err := run("netsh", "advfirewall", "show", "currentprofile", "state")
	if err != nil || !strings.Contains(out, "ON") {
		return nil
	}

	return netshBackend{}
}

// netshBackend manages Windows Defender Firewall rules, named by the
// component tag so teardown can delete exactly ours.
type netshBackend struct{}

func (netshBackend) name() string { return "windows-defender" }

func netshPort(r Rule) string {
	if r.PortMin == r.PortMax {
		return fmt.Sprintf("%d", r.PortMin)
	}

	return fmt.Sprintf("%d-%d", r.PortMin, r.PortMax)
}

func (netshBackend) allowCmds(tag string, r Rule) [][]string {
	return [][]string{{
		"netsh", "advfirewall", "firewall", "add", "rule",
		"name=" + tag,
		"dir=in", "action=allow",
		"protocol=" + strings.ToUpper(r.Proto),
		"localport=" + netshPort(r),
	}}
}

func (netshBackend) removeCmds(tag string, r Rule) [][]string {
	return [][]string{{
		"netsh", "advfirewall", "firewall", "delete", "rule",
		"name=" + tag,
		"protocol=" + strings.ToUpper(r.Proto),
		"localport=" + netshPort(r),
	}}
}

func (netshBackend) teardownCmds(string) [][]string { return nil }
