// Package buildinfo exposes the source revision embedded in wgmesh binaries.
package buildinfo

import "runtime/debug"

// GitCommit is set by release and container builds using -ldflags. Direct
// `go build` invocations fall back to Go's VCS build settings below.
var GitCommit string

func Commit() string {
	if GitCommit != "" && GitCommit != "unknown" {
		return GitCommit
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	revision := ""
	dirty := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if revision == "" {
		return "unknown"
	}
	if dirty {
		return revision + "-dirty"
	}
	return revision
}
