package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Agent lifecycle states published to the status hub. The GUI owns the
// starting/stopping/stopped/error transitions around agentRunner.run;
// the runner itself only reports the moment the data path is up.
const (
	stateStopped  = "stopped"
	stateStarting = "starting"
	stateRunning  = "running"
	stateStopping = "stopping"
	stateError    = "error"
)

// peerStatus is one WireGuard peer as shown in the GUI: identity,
// current path, and kernel counters. Snapshots, not live references.
type peerStatus struct {
	PublicKey     string
	AllowedIPs    []string // host routes shown bare, wider CIDRs as-is
	Endpoint      string
	PathState     string // direct, ws-relay, udp-relay, probing-direct
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// agentStatus is the full GUI-visible agent state. Copied out on every
// snapshot so readers never share memory with publishers.
type agentStatus struct {
	State        string
	Err          string
	PublicKey    string
	ListenPort   int
	Server       string
	OverlayAddr  string
	OverlayAddr6 string
	Peers        []peerStatus
}

// statusHub is a versioned mailbox between the agent loop and the GUI.
// It is disabled (all publishes are dropped before taking the lock)
// unless the GUI enables it at startup, so console and service runs pay
// one atomic load per publish site and nothing else.
type statusHub struct {
	on      atomic.Bool
	mu      sync.Mutex
	version uint64
	status  agentStatus
}

// statusPub is the process-wide hub. The agent loop publishes into it
// from wherever it learns something; the GUI polls snapshots.
var statusPub = &statusHub{}

func (h *statusHub) enable() {
	h.on.Store(true)
}

func (h *statusHub) enabled() bool {
	return h.on.Load()
}

func (h *statusHub) update(fn func(*agentStatus)) {
	if !h.on.Load() {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	fn(&h.status)
	h.version++
}

// snapshot returns a deep copy plus the hub version, so pollers can
// skip redraws when nothing changed.
func (h *statusHub) snapshot() (agentStatus, uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	s := h.status
	s.Peers = append([]peerStatus(nil), h.status.Peers...)

	return s, h.version
}

// logRingMax bounds the GUI log view; older lines fall off the front.
const logRingMax = 500

// logRing is a concurrency-safe io.Writer holding the last logRingMax
// log lines for the GUI. slog and agentPrintf write whole lines, but a
// partial-write buffer keeps split writes intact anyway.
type logRing struct {
	mu      sync.Mutex
	lines   []string
	partial strings.Builder
	version uint64
}

func (r *logRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.partial.Write(p)

	text := r.partial.String()
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		for _, line := range strings.Split(text[:i], "\n") {
			r.lines = append(r.lines, strings.TrimSuffix(line, "\r"))
		}
		r.partial.Reset()
		r.partial.WriteString(text[i+1:])

		if len(r.lines) > logRingMax {
			r.lines = append([]string(nil), r.lines[len(r.lines)-logRingMax:]...)
		}
		r.version++
	}

	return len(p), nil
}

func (r *logRing) snapshot() (string, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return strings.Join(r.lines, "\n"), r.version
}

func (r *logRing) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lines = nil
	r.version++
}

// logMirror, when non-nil, receives a copy of everything the agent
// prints or logs. The GUI sets it (to its logRing) once at startup,
// before any agent loop runs; it is never mutated afterwards.
var logMirror io.Writer

// agentPrintf is fmt.Printf plus the GUI log mirror, with a short
// clock-time prefix so relay/probe progress lines can be timed (how
// long a pair takes to go direct) at a glance. These are human-facing
// status lines, so the prefix is a compact local HH:MM:SS rather than
// the full RFC3339 stamp the machine-parsed slog stream carries.
func agentPrintf(format string, args ...any) {
	line := timestampLine(fmt.Sprintf(format, args...))

	fmt.Print(line)

	if logMirror != nil {
		fmt.Fprint(logMirror, line)
	}
}

// timestampLine prefixes a log line with a compact local time,
// e.g. "[17:54:35] ". Leading newlines (blank-line separators) stay
// ahead of the timestamp, and an empty message is passed through
// untouched.
func timestampLine(s string) string {
	lead := 0
	for lead < len(s) && s[lead] == '\n' {
		lead++
	}
	if lead == len(s) {
		return s
	}

	return s[:lead] + time.Now().Format("[15:04:05] ") + s[lead:]
}
