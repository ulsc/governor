package app

import (
	"testing"

	"governor/internal/model"
)

func TestDedupeFindings_MergesAcrossTracks(t *testing.T) {
	in := []model.Finding{
		{Title: "Hardcoded API key", Category: "secrets", Severity: "high", Evidence: "x", SourceTrack: "secrets_config", Confidence: 0.6, FileRefs: []string{"a.env"}},
		{Title: "Hardcoded API key", Category: "secrets", Severity: "critical", Evidence: "x", SourceTrack: "appsec", Confidence: 0.9, FileRefs: []string{"a.env"}},
	}

	out := dedupeFindings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].Severity != "critical" {
		t.Fatalf("expected critical severity, got %s", out[0].Severity)
	}
	if out[0].Confidence != 0.9 {
		t.Fatalf("expected confidence 0.9, got %f", out[0].Confidence)
	}
	if out[0].SourceTrack != "appsec,secrets_config" {
		t.Fatalf("unexpected source tracks: %s", out[0].SourceTrack)
	}
}

func TestShouldCleanupWorkspace_DefaultAlwaysCleans(t *testing.T) {
	if !shouldCleanupWorkspace(nil, nil, false) {
		t.Fatal("expected cleanup on success by default")
	}
	if !shouldCleanupWorkspace(nil, []string{"warn"}, false) {
		t.Fatal("expected cleanup on warning by default")
	}
	if !shouldCleanupWorkspace(assertErr{}, nil, false) {
		t.Fatal("expected cleanup on failure by default")
	}
}

func TestShouldCleanupWorkspace_KeepOnError(t *testing.T) {
	if !shouldCleanupWorkspace(nil, nil, true) {
		t.Fatal("expected cleanup on success when keep-on-error is enabled")
	}
	if shouldCleanupWorkspace(nil, []string{"warn"}, true) {
		t.Fatal("expected no cleanup on warning when keep-on-error is enabled")
	}
	if shouldCleanupWorkspace(assertErr{}, nil, true) {
		t.Fatal("expected no cleanup on failure when keep-on-error is enabled")
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "err" }
