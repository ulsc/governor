package checks

import (
	"testing"
)

func TestDefaultTestFileExcludeGlobs_ReturnsNonEmpty(t *testing.T) {
	globs := DefaultTestFileExcludeGlobs()
	if len(globs) == 0 {
		t.Fatal("expected non-empty default test file exclude globs")
	}
}

func TestApplyTestFileExclusions_EmptyScope(t *testing.T) {
	scope := ApplyTestFileExclusions(Scope{})
	if len(scope.ExcludeGlobs) != len(DefaultTestFileExcludeGlobs()) {
		t.Fatalf("expected %d exclude globs, got %d", len(DefaultTestFileExcludeGlobs()), len(scope.ExcludeGlobs))
	}
	if scope.IncludeGlobs != nil {
		t.Fatalf("expected nil include globs, got %v", scope.IncludeGlobs)
	}
}

func TestApplyTestFileExclusions_PreservesExisting(t *testing.T) {
	scope := ApplyTestFileExclusions(Scope{
		IncludeGlobs: []string{"**/*.go"},
		ExcludeGlobs: []string{"**/vendor/**"},
	})
	if len(scope.IncludeGlobs) != 1 || scope.IncludeGlobs[0] != "**/*.go" {
		t.Fatalf("expected include globs preserved, got %v", scope.IncludeGlobs)
	}
	if scope.ExcludeGlobs[0] != "**/vendor/**" {
		t.Fatalf("expected first exclude glob to be vendor, got %s", scope.ExcludeGlobs[0])
	}
	if len(scope.ExcludeGlobs) != 1+len(DefaultTestFileExcludeGlobs()) {
		t.Fatalf("expected %d exclude globs, got %d", 1+len(DefaultTestFileExcludeGlobs()), len(scope.ExcludeGlobs))
	}
}

func TestApplyTestFileExclusions_Deduplicates(t *testing.T) {
	scope := ApplyTestFileExclusions(Scope{
		ExcludeGlobs: []string{"**/*_test.go", "**/fixtures/**"},
	})
	// Should not duplicate the two already-present patterns
	expected := len(DefaultTestFileExcludeGlobs())
	if len(scope.ExcludeGlobs) != expected {
		t.Fatalf("expected %d exclude globs (deduped), got %d: %v", expected, len(scope.ExcludeGlobs), scope.ExcludeGlobs)
	}
}
