package fix

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"governor/internal/ai"
	"governor/internal/model"
)

func TestRun_GeneratesArtifactsAndSuggestions(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatalf("write repo file: %v", err)
	}

	audit := model.AuditReport{
		RunMetadata: model.RunMetadata{RunID: "run-1"},
		InputSummary: model.InputSummary{
			InputPath: repoDir,
		},
		Findings: []model.Finding{
			{
				ID:             "appsec-1",
				Title:          "Missing authorization check",
				Severity:       "high",
				Category:       "auth",
				SourceTrack:    "appsec",
				Confidence:     0.85,
				Exploitability: "reachable",
				FileRefs:       []string{"main.go"},
				Evidence:       "handler lacks guard",
			},
		},
	}
	auditPath := filepath.Join(t.TempDir(), "audit.json")
	b, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	if err := os.WriteFile(auditPath, b, 0o600); err != nil {
		t.Fatalf("write audit: %v", err)
	}

	called := false
	origExec := executeTrack
	t.Cleanup(func() { executeTrack = origExec })
	executeTrack = func(_ context.Context, _ ai.Runtime, input ai.ExecutionInput) ([]byte, error) {
		called = true
		if !strings.Contains(input.PromptText, "finding_id=appsec-1") {
			t.Fatalf("expected prompt to include finding id, got:\n%s", input.PromptText)
		}
		payload := aiFixOutput{
			Summary: "generated suggestions",
			Suggestions: []aiFixSuggestion{
				{
					FindingID:   "appsec-1",
					Title:       "Missing authorization check",
					SourceTrack: "appsec",
					Priority:    "high",
					Summary:     "Add authorization middleware before handler.",
					Files: []aiFixFileChange{
						{
							Path:         "main.go",
							ChangeType:   "modify",
							Instructions: []string{"Add requireAdmin middleware before route handler execution."},
						},
					},
					ValidationSteps: []string{"Run route auth tests."},
					RiskNotes:       []string{"May reject unauthorized requests now."},
					Confidence:      0.91,
				},
			},
		}
		out, _ := json.MarshalIndent(payload, "", "  ")
		if err := os.WriteFile(input.OutputPath, out, 0o600); err != nil {
			t.Fatalf("write mocked ai output: %v", err)
		}
		return []byte("ok"), nil
	}

	opts := Options{
		AuditPath: auditPath,
		AIRuntime: ai.Runtime{
			Provider: "openai-compatible",
			Model:    "gpt-test",
		},
		Filters: model.FixFilters{
			MaxSuggestions: 10,
		},
	}
	fixReport, paths, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !called {
		t.Fatal("expected ai execution to be called")
	}
	if len(fixReport.Suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(fixReport.Suggestions))
	}
	if fixReport.Suggestions[0].Files[0].Path != "main.go" {
		t.Fatalf("unexpected file path: %+v", fixReport.Suggestions[0].Files)
	}
	for _, path := range []string{paths.JSONPath, paths.MarkdownPath, paths.LogPath, paths.SchemaPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
}

func TestRun_NoMatchingFindingsSkipsAI(t *testing.T) {
	audit := model.AuditReport{
		RunMetadata:  model.RunMetadata{RunID: "run-2"},
		InputSummary: model.InputSummary{InputPath: t.TempDir()},
		Findings: []model.Finding{
			{ID: "f-1", Title: "Issue", Severity: "low", SourceTrack: "appsec"},
		},
	}
	auditPath := filepath.Join(t.TempDir(), "audit.json")
	b, err := json.Marshal(audit)
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	if err := os.WriteFile(auditPath, b, 0o600); err != nil {
		t.Fatalf("write audit: %v", err)
	}

	called := false
	origExec := executeTrack
	t.Cleanup(func() { executeTrack = origExec })
	executeTrack = func(_ context.Context, _ ai.Runtime, _ ai.ExecutionInput) ([]byte, error) {
		called = true
		return nil, nil
	}

	report, _, err := Run(context.Background(), Options{
		AuditPath: auditPath,
		AIRuntime: ai.Runtime{Provider: "openai-compatible", Model: "gpt-test"},
		Filters: model.FixFilters{
			OnlySeverities: []string{"critical"},
		},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if called {
		t.Fatal("did not expect ai execution when no findings are selected")
	}
	if len(report.Suggestions) != 0 {
		t.Fatalf("expected no suggestions, got %d", len(report.Suggestions))
	}
	if len(report.Warnings) == 0 {
		t.Fatal("expected warning when no findings match filters")
	}
}

func TestNormalizeFilters_Defaults(t *testing.T) {
	filters := normalizeFilters(model.FixFilters{
		OnlySeverities: []string{"HIGH", "high"},
		OnlyChecks:     []string{"AppSec", "appsec"},
	})
	if filters.MaxSuggestions != defaultMaxSuggestions {
		t.Fatalf("expected default max suggestions %d, got %d", defaultMaxSuggestions, filters.MaxSuggestions)
	}
	if len(filters.OnlySeverities) != 1 || filters.OnlySeverities[0] != "high" {
		t.Fatalf("unexpected severities: %+v", filters.OnlySeverities)
	}
	if len(filters.OnlyChecks) != 1 || filters.OnlyChecks[0] != "appsec" {
		t.Fatalf("unexpected checks: %+v", filters.OnlyChecks)
	}
}

func TestMapSuggestions_FallsBackToFindingFields(t *testing.T) {
	findings := []model.Finding{
		{
			ID:          "f-1",
			Title:       "Original title",
			SourceTrack: "appsec",
			Severity:    "critical",
			Confidence:  0.7,
		},
	}
	got := mapSuggestions([]aiFixSuggestion{
		{FindingID: "f-1", Summary: "summary"},
	}, findings)
	if len(got) != 1 {
		t.Fatalf("expected one suggestion, got %d", len(got))
	}
	if got[0].Title != "Original title" {
		t.Fatalf("expected title fallback, got %q", got[0].Title)
	}
	if got[0].SourceTrack != "appsec" {
		t.Fatalf("expected source_track fallback, got %q", got[0].SourceTrack)
	}
	if got[0].Priority != "critical" {
		t.Fatalf("expected priority fallback from severity, got %q", got[0].Priority)
	}
	if got[0].Confidence != 0.7 {
		t.Fatalf("expected confidence fallback, got %f", got[0].Confidence)
	}
}

func TestRenderArtifactsTimestampIsUTC(t *testing.T) {
	report := model.FixReport{GeneratedAt: time.Now().UTC(), SourceAudit: "a", OutDir: "b"}
	md := renderMarkdown(report)
	if !strings.Contains(md, "Generated at:") {
		t.Fatalf("expected timestamp line, got: %s", md)
	}
}
