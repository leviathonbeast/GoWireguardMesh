package buildinfo

import "testing"

func TestCommitPrefersInjectedRevision(t *testing.T) {
	old := GitCommit
	t.Cleanup(func() { GitCommit = old })

	GitCommit = "0123456789abcdef"
	if got := Commit(); got != GitCommit {
		t.Fatalf("Commit() = %q, want injected %q", got, GitCommit)
	}
}

func TestVersionStringPrefersTag(t *testing.T) {
	defer func(v, c string) { Version, GitCommit = v, c }(Version, GitCommit)

	Version = "v0.9.1"
	GitCommit = "a34d586279d1201d2b003425bcadf712bfd66d7f"
	if got := VersionString(); got != "v0.9.1" {
		t.Fatalf("VersionString() = %q, want the release tag v0.9.1", got)
	}
}

func TestVersionStringFallsBackToShortCommit(t *testing.T) {
	defer func(v, c string) { Version, GitCommit = v, c }(Version, GitCommit)

	Version = ""

	// A dev build has no tag, so the UI should still get something
	// identifying rather than a blank cell.
	GitCommit = "a34d586279d1201d2b003425bcadf712bfd66d7f"
	if got := VersionString(); got != "a34d586" {
		t.Fatalf("VersionString() = %q, want short commit a34d586", got)
	}

	// The -dirty marker matters most on a dev build: it is the signal
	// that the running binary does not match any commit.
	GitCommit = "a34d586279d1201d2b003425bcadf712bfd66d7f-dirty"
	if got := VersionString(); got != "a34d586-dirty" {
		t.Fatalf("VersionString() = %q, want a34d586-dirty", got)
	}
}
