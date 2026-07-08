# wgmesh Architecture

This document tracks the staged readability refactor. The guiding rule is
that every stage must keep the project buildable, testable, and deployable.

## Current Boundaries

- `cmd/server`: control-plane executable, flag parsing, dependency wiring, and
  domain HTTP handlers.
- `internal/httpx`: shared HTTP infrastructure for the server: response JSON,
  request body limits, security headers, server lifecycle, and public endpoint
  rate limiting.
- `internal/store`: SQLite persistence and schema migration.
- `internal/proto`: wire protocol structs shared by server and agent.
- `internal/relay`: UDP and WebSocket relay core.
- `cmd/agent`: agent executable, interface setup, enrollment, reporting, DNS,
  ACL sync, signal sync, and relay fallback.

## Stage 1 Result

Stage 1 extracts generic HTTP infrastructure out of `cmd/server`. Domain
handlers still use local adapter helpers during the transition, but the
implementations now live in `internal/httpx`. This keeps the first refactor
low-risk while giving later stages a clear place for shared HTTP behavior.

## Stage 2 Result

Stage 2 makes the agent startup lifecycle explicit. `cmd/agent/main.go` now
parses flags and delegates to an `agentRunner`; `agentConfig` captures runtime
inputs, and `runner.go` owns the ordered lifecycle: identity, optional
enrollment, interface setup, WireGuard configuration, telemetry/signal startup,
shutdown, and cleanup. The split stays inside `cmd/agent` for now because the
agent still has platform-specific backend and interface implementations there.

## Next Stage

Stage 3 should split the web UI into API modules, shared UI primitives, and
page-level components so `App.tsx` stops carrying the whole dashboard.
