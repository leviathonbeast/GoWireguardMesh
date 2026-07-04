// Package gowireguard exposes repo-root assets to the binaries.
package gowireguard

import _ "embed"

// SchemaSQL is the canonical database schema. It lives at the repo root
// (schema.sql) and is embedded here because go:embed cannot reach outside
// the package directory.
//
//go:embed schema.sql
var SchemaSQL string
