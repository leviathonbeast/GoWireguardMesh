// Package firewall opens the ports a wgmesh component binds, on the
// host firewall it finds running, and closes them again on shutdown.
//
// Each component manages only its own host: the agent opens its
// WireGuard listen port, the server its API port, the relay its
// forwarding range. Rules are added at startup and removed in Close —
// deliberately runtime-only where the backend distinguishes (a
// wgmesh component that is not running should not leave holes).
//
// Failure is never fatal: a host without a supported firewall, or a
// component without privileges, gets a warning and keeps running.
package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"gowireguard/internal/hidecmd"
)

// ErrNoBackend means no supported, active firewall was detected.
var ErrNoBackend = errors.New("no supported firewall backend detected")

// Rule is one allowed port span on one protocol.
type Rule struct {
	Proto   string // "udp" or "tcp"
	PortMin int
	PortMax int // == PortMin for single ports
}

// runner executes one command and returns its combined output.
// Swapped for a fake in tests.
type runner func(name string, args ...string) (string, error)

func execRunner(name string, args ...string) (string, error) {
	// hidecmd: on Windows the agent may run from a GUI-subsystem
	// process, where a plain console child (netsh) flashes a window.
	out, err := hidecmd.Command(name, args...).CombinedOutput()
	return string(out), err
}

// backend translates rules into CLI invocations for one firewall.
type backend interface {
	name() string
	allowCmds(tag string, r Rule) [][]string
	removeCmds(tag string, r Rule) [][]string
	// teardownCmds, when non-nil, replaces per-rule removal in Close
	// (e.g. nftables drops the whole component-owned table at once).
	teardownCmds(tag string) [][]string
}

// Manager tracks the rules one component added so Close can undo
// exactly those and nothing else.
type Manager struct {
	tag       string
	backend   backend
	run       runner
	rules     []Rule
	stateFile string // persisted open rules, for startup reconciliation
}

// Open detects the active firewall and returns a manager tagged with
// the component name (used to label rules where the backend supports
// it). The error is ErrNoBackend when nothing usable was found; the
// returned manager is still safe to use and no-ops everywhere.
func Open(tag string) (*Manager, error) {
	m := &Manager{tag: tag, run: execRunner}
	m.backend = detect(m.run)

	if m.backend == nil {
		return m, ErrNoBackend
	}

	return m, nil
}

// OpenWithReconcile is Open plus a state file. On startup it removes
// any rules a previous run left behind (crash, kill -9, or a rule the
// backend cannot self-identify — firewalld ports have no owner tag),
// then tracks new rules there. This closes the leak where an
// ungraceful exit left ports open forever.
func OpenWithReconcile(tag, stateFile string) (*Manager, error) {
	m, err := Open(tag)
	m.stateFile = stateFile

	if m.backend != nil {
		m.reconcile()
	}

	return m, err
}

// reconcile removes rules recorded in the state file from a prior run.
func (m *Manager) reconcile() {
	data, rerr := os.ReadFile(m.stateFile)
	if rerr != nil {
		return // no prior state, nothing to clean
	}

	var prior []Rule
	if err := json.Unmarshal(data, &prior); err != nil {
		return
	}

	for _, r := range prior {
		for _, cmd := range m.backend.removeCmds(m.tag, r) {
			// Best effort: a rule already gone (e.g. after a reboot
			// that cleared runtime rules) just errors harmlessly.
			m.run(cmd[0], cmd[1:]...)
		}
	}

	if teardown := m.backend.teardownCmds(m.tag); teardown != nil {
		for _, cmd := range teardown {
			m.run(cmd[0], cmd[1:]...)
		}
	}

	os.Remove(m.stateFile)
}

// persist writes the current rule set so a future run can reconcile.
func (m *Manager) persist() {
	if m.stateFile == "" {
		return
	}

	if data, err := json.Marshal(m.rules); err == nil {
		os.WriteFile(m.stateFile, data, 0600)
	}
}

// Backend names the detected firewall, or "none".
func (m *Manager) Backend() string {
	if m.backend == nil {
		return "none"
	}

	return m.backend.name()
}

func (m *Manager) AllowUDP(port int) error {
	return m.allow(Rule{Proto: "udp", PortMin: port, PortMax: port})
}

func (m *Manager) AllowUDPRange(min, max int) error {
	return m.allow(Rule{Proto: "udp", PortMin: min, PortMax: max})
}

func (m *Manager) AllowTCP(port int) error {
	return m.allow(Rule{Proto: "tcp", PortMin: port, PortMax: port})
}

func (m *Manager) allow(r Rule) error {
	if m.backend == nil {
		return nil
	}

	for _, cmd := range m.backend.allowCmds(m.tag, r) {
		if out, err := m.run(cmd[0], cmd[1:]...); err != nil {
			return fmt.Errorf("%s: %q: %w: %s",
				m.backend.name(), strings.Join(cmd, " "), err, strings.TrimSpace(out))
		}
	}

	m.rules = append(m.rules, r)
	m.persist()

	return nil
}

// Close removes every rule this manager added. Best effort: errors
// are collected, not fatal — shutdown must proceed regardless.
func (m *Manager) Close() error {
	if m.backend == nil || len(m.rules) == 0 {
		return nil
	}

	var errs []error

	if teardown := m.backend.teardownCmds(m.tag); teardown != nil {
		for _, cmd := range teardown {
			if out, err := m.run(cmd[0], cmd[1:]...); err != nil {
				errs = append(errs, fmt.Errorf("%q: %w: %s", strings.Join(cmd, " "), err, strings.TrimSpace(out)))
			}
		}

		m.clearState()

		return errors.Join(errs...)
	}

	// Remove in reverse of addition.
	for i := len(m.rules) - 1; i >= 0; i-- {
		for _, cmd := range m.backend.removeCmds(m.tag, m.rules[i]) {
			if out, err := m.run(cmd[0], cmd[1:]...); err != nil {
				errs = append(errs, fmt.Errorf("%q: %w: %s", strings.Join(cmd, " "), err, strings.TrimSpace(out)))
			}
		}
	}

	m.clearState()

	return errors.Join(errs...)
}

func (m *Manager) clearState() {
	m.rules = nil

	if m.stateFile != "" {
		os.Remove(m.stateFile)
	}
}
