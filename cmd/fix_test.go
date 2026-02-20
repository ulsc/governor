package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"governor/internal/model"
)

func TestRunFix_NoMatchingFindingsWritesArtifacts(t *testing.T) {
	baseDir := t.TempDir()
	inputDir := filepath.Join(baseDir, "input")
	if err := os.MkdirAll(inputDir, 0o700); err != nil {
		t.Fatalf("mkdir input dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatalf("write input file: %v", err)
	}

	auditPath := filepath.Join(baseDir, "audit.json")
	report := model.AuditReport{
		RunMetadata: model.RunMetadata{RunID: "run-1"},
		InputSummary: model.InputSummary{
			InputPath: inputDir,
		},
		Findings: []model.Finding{
			{
				ID:          "f-1",
				Title:       "Low issue",
				Severity:    "low",
				SourceTrack: "appsec",
			},
		},
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	if err := os.WriteFile(auditPath, b, 0o600); err != nil {
		t.Fatalf("write audit: %v", err)
	}

	t.Setenv("GOVERNOR_FIX_TEST_KEY", "test-key")

	outDir := filepath.Join(baseDir, "out")
	err = Execute([]string{
		"fix", auditPath,
		"--out", outDir,
		"--only-severity", "critical",
		"--ai-provider", "openai-compatible",
		"--ai-model", "gpt-4o-mini",
		"--ai-base-url", "https://api.example.com/v1",
		"--ai-auth-mode", "api-key",
		"--ai-api-key-env", "GOVERNOR_FIX_TEST_KEY",
	})
	if err != nil {
		t.Fatalf("run fix failed: %v", err)
	}

	fixJSONPath := filepath.Join(outDir, "fix", "fix-suggestions.json")
	raw, err := os.ReadFile(fixJSONPath)
	if err != nil {
		t.Fatalf("read fix report: %v", err)
	}
	var fixReport model.FixReport
	if err := json.Unmarshal(raw, &fixReport); err != nil {
		t.Fatalf("parse fix report: %v", err)
	}
	if fixReport.Selected != 0 {
		t.Fatalf("expected selected findings = 0, got %d", fixReport.Selected)
	}
	if len(fixReport.Suggestions) != 0 {
		t.Fatalf("expected 0 suggestions, got %d", len(fixReport.Suggestions))
	}
	if len(fixReport.Warnings) == 0 {
		t.Fatal("expected warning when no findings match filters")
	}

	for _, path := range []string{
		filepath.Join(outDir, "fix", "fix-output-schema.json"),
		filepath.Join(outDir, "fix", "fix-suggestions.json"),
		filepath.Join(outDir, "fix", "fix-suggestions.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
}

func TestRunFix_RejectsInvalidMaxSuggestions(t *testing.T) {
	err := runFix([]string{
		"audit.json",
		"--max-suggestions", "0",
	})
	if err == nil {
		t.Fatal("expected max-suggestions validation error")
	}
	if !strings.Contains(err.Error(), "--max-suggestions must be > 0") {
		t.Fatalf("unexpected error: %v", err)
	}
}
