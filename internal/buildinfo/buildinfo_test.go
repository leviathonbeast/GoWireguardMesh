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
