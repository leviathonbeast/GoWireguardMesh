package main

import (
	"errors"
	"fmt"
	"strings"
)

var errDNSUnsupported = errors.New("dns configuration unsupported on this system")

// dnsMode selects how pushed DNS settings are applied to the host.
// Linux honors all four modes; Windows manages DNS natively (NRPT) and
// only distinguishes off. Parsed once at startup into dnsApplyMode so
// the platform applyDNSConfig implementations can stay flag-agnostic.
type dnsMode int

const (
	dnsModeAuto dnsMode = iota
	dnsModeResolved
	dnsModeResolvConf
	dnsModeOff
)

var dnsApplyMode = dnsModeAuto

func parseDNSMode(s string) (dnsMode, error) {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "", "auto":
		return dnsModeAuto, nil
	case "resolved", "systemd-resolved":
		return dnsModeResolved, nil
	case "resolv-conf", "resolvconf", "resolv.conf":
		return dnsModeResolvConf, nil
	case "off", "none":
		return dnsModeOff, nil
	}
	return 0, fmt.Errorf("invalid --dns-mode %q: want auto, resolved, resolv-conf, or off", s)
}
