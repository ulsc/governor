package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildDoctorReport_FindsShadowedAndInvalidChecks(t *testing.T) {
	repoDir := t.TempDir()
	homeDir := t.TempDir()

	if _, err := WriteDefinition(repoDir, Definition{
		APIVersion:   APIVersion,
		ID:           "dup-check",
		Name:         "Repo Check",
		Status:       StatusEnabled,
		Source:       SourceCustom,
		Description:  "repo check",
		Instructions: "This instruction text is intentionally long enough to avoid short-instruction diagnostics.",
		Scope: Scope{
			IncludeGlobs: []string{"**/*"},
		},
	}, false); err != nil {
		t.Fatalf("write repo check: %v", err)
	}
	if _, err := WriteDefinition(homeDir, Definition{
		APIVersion:   APIVersion,
		ID:           "dup-check",
		Name:         "Home Check",
		Status:       StatusDraft,
		Source:       SourceCustom,
		Description:  "home check",
		Instructions: "This instruction text is intentionally long enough to avoid short-instruction diagnostics.",
	}, false); err != nil {
		t.Fatalf("write home check: %v", err)
	}

	invalidPath := filepath.Join(homeDir, "bad.check.yaml")
	if err := os.WriteFile(invalidPath, []byte("api_version: ["), 0o600); err != nil {
		t.Fatalf("write invalid check: %v", err)
	}

	report, err := BuildDoctorReport([]string{repoDir, homeDir})
	if err != nil {
		t.Fatalf("BuildDoctorReport failed: %v", err)
	}
	if len(report.Effective) != 1 {
		t.Fatalf("expected 1 effective check, got %d", len(report.Effective))
	}
	if len(report.Shadowed) != 1 {
		t.Fatalf("expected 1 shadowed check, got %d", len(report.Shadowed))
	}
	if report.Summary.Error == 0 {
		t.Fatalf("expected at least one error diagnostic, got summary %+v", report.Summary)
	}
	if report.Summary.Warning == 0 {
		t.Fatalf("expected at least one warning diagnostic, got summary %+v", report.Summary)
	}
}

func TestExplainCheck_ResolvesRepoFirst(t *testing.T) {
	repoDir := t.TempDir()
	homeDir := t.TempDir()

	repoPath, err := WriteDefinition(repoDir, Definition{
		APIVersion:   APIVersion,
		ID:           "status-check",
		Name:         "Repo Check",
		Status:       StatusEnabled,
		Source:       SourceCustom,
		Description:  "repo check",
		Instructions: "This instruction text is intentionally long enough to avoid short-instruction diagnostics.",
	}, false)
	if err != nil {
		t.Fatalf("write repo check: %v", err)
	}
	if _, err := WriteDefinition(homeDir, Definition{
		APIVersion:   APIVersion,
		ID:           "status-check",
		Name:         "Home Check",
		Status:       StatusEnabled,
		Source:       SourceCustom,
		Description:  "home check",
		Instructions: "This instruction text is intentionally long enough to avoid short-instruction diagnostics.",
	}, false); err != nil {
		t.Fatalf("write home check: %v", err)
	}

	result, err := ExplainCheck([]string{repoDir, homeDir}, "status-check")
	if err != nil {
		t.Fatalf("ExplainCheck failed: %v", err)
	}
	if result.Effective == nil {
		t.Fatal("expected effective check")
	}
	if result.Effective.Path != repoPath {
		t.Fatalf("expected repo check to win, got %s", result.Effective.Path)
	}
	if len(result.Shadowed) != 1 {
		t.Fatalf("expected one shadowed check, got %d", len(result.Shadowed))
	}
}

func TestExplainCheck_InvalidID(t *testing.T) {
	_, err := ExplainCheck([]string{t.TempDir()}, "../bad")
	if err == nil {
		t.Fatal("expected invalid id error")
	}
	if !strings.Contains(err.Error(), "id must match") {
		t.Fatalf("unexpected error: %v", err)
	}
}
