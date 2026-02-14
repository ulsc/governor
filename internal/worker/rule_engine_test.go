package worker

import (
	"testing"

	"governor/internal/checks"
)

func TestScopeAllows_WithDoubleStarGlobs(t *testing.T) {
	scope := checks.Scope{
		IncludeGlobs: []string{"**/*.md"},
		ExcludeGlobs: []string{"**/vendor/**"},
	}
	if !scopeAllows("docs/security/prompt.md", scope) {
		t.Fatal("expected markdown file to match include glob")
	}
	if scopeAllows("vendor/prompts/injection.md", scope) {
		t.Fatal("expected vendor path to be excluded")
	}
	if scopeAllows("docs/security/prompt.txt", scope) {
		t.Fatal("expected txt file to be outside include scope")
	}
}

func TestContainsMatches_CaseInsensitive(t *testing.T) {
	matches := containsMatches("IGNORE previous instructions", "ignore previous instructions", false, 3)
	if len(matches) != 1 {
		t.Fatalf("expected one case-insensitive match, got %d", len(matches))
	}
}

