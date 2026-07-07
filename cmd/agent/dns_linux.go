//go:build linux

package main

import (
	"fmt"
	"os/exec"

	"gowireguard/internal/proto"
)

func applyDNSConfig(iface string, cfg proto.DNSConfig) error {
	resolvectl, err := exec.LookPath("resolvectl")
	if err != nil {
		return fmt.Errorf("resolvectl not found; install/use systemd-resolved or configure DNS manually")
	}

	if !cfg.Enabled {
		return runDNSCommand(resolvectl, "revert", iface)
	}

	if len(cfg.Nameservers) == 0 {
		return nil
	}

	args := append([]string{"dns", iface}, cfg.Nameservers...)
	if err := runDNSCommand(resolvectl, args...); err != nil {
		return err
	}

	domains := dnsResolvedDomains(cfg)
	if len(domains) > 0 {
		args = append([]string{"domain", iface}, domains...)
		if err := runDNSCommand(resolvectl, args...); err != nil {
			return err
		}
	}

	// Route only configured domains to the mesh DNS by default. Older
	// resolvectl versions may not support this verb; DNS still works
	// without it, so ignore failures here.
	_ = runDNSCommand(resolvectl, "default-route", iface, "false")

	return nil
}

func dnsResolvedDomains(cfg proto.DNSConfig) []string {
	seen := map[string]bool{}
	var out []string
	add := func(domain string) {
		if domain == "" || seen[domain] {
			return
		}
		seen[domain] = true
		out = append(out, domain)
	}

	for _, domain := range cfg.SearchDomains {
		add(domain)
		if cfg.MagicDNS {
			add("~" + domain)
		}
	}
	if cfg.MagicDNS && cfg.Domain != "" {
		add(cfg.Domain)
		add("~" + cfg.Domain)
	}

	return out
}

func runDNSCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}

	return nil
}
