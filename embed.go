// Package gowireguard exposes repo-root assets to the binaries.
package gowireguard

import "embed"

// SchemaSQL is the canonical database schema. It lives at the repo root
// (schema.sql) and is embedded here because go:embed cannot reach outside
// the package directory.
//
//go:embed schema.sql
var SchemaSQL string

// WebUI is the compiled admin interface (web/, React + TypeScript).
// Run `npm run build` in web/ before `go build` — the dist output is
// committed so plain `go build` works without a Node toolchain.
//
//go:embed all:web/dist
var WebUI embed.FS
