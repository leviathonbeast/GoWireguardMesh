// Package buildinfo exposes the source revision embedded in wgmesh binaries.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// GitCommit is set by release and container builds using -ldflags. Direct
// `go build` invocations fall back to Go's VCS build settings below.
var GitCommit string

// Version is the release tag (e.g. "v0.9.1"), set by release and
// container builds using -ldflags. Empty for a plain `go build`, where
// there is no tag to speak of — Version() falls back to the commit so
// the field is never blank in the UI.
var Version string

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

// VersionString returns the release tag this binary was built from,
// falling back to a short commit when built outside a release (a dev
// build has no tag). Agents report this so the UI can show what each
// node runs and flag nodes behind the control plane.
func VersionString() string {
	if Version != "" {
		return Version
	}

	commit := Commit()
	if commit == "unknown" {
		return "unknown"
	}

	// Shorten the revision but keep any -dirty marker: "abc1234-dirty".
	rev, dirty := strings.CutSuffix(commit, "-dirty")
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if dirty {
		return rev + "-dirty"
	}

	return rev
}
