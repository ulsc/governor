package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"governor/internal/model"
)

func TestBuildSARIF_BasicStructure(t *testing.T) {
	report := model.AuditReport{
		RunMetadata: model.RunMetadata{RunID: "test-run", PromptVersion: "1.0"},
		Findings: []model.Finding{
			{
				ID: "f1", Title: "SQL Injection", Severity: "critical", Category: "injection",
				Evidence: "unsanitized input", Impact: "data breach", Remediation: "use parameterized queries",
				FileRefs: []string{"src/db.go", "src/handler.go"}, Confidence: 0.9, SourceTrack: "appsec",
			},
			{
				ID: "f2", Title: "Debug Logging", Severity: "low", Category: "config",
				Evidence: "verbose logs in production", Impact: "info leak", Remediation: "disable debug",
				Confidence: 0.5, SourceTrack: "appsec",
			},
		},
	}

	log := buildSARIF(report)

	if log.Version != "2.1.0" {
		t.Fatalf("expected version 2.1.0, got %s", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "governor" {
		t.Fatalf("expected tool name governor, got %s", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}

	r0 := run.Results[0]
	if r0.RuleID != "f1" {
		t.Fatalf("expected ruleId f1, got %s", r0.RuleID)
	}
	if r0.Level != "error" {
		t.Fatalf("expected level error for critical, got %s", r0.Level)
	}
	if len(r0.Locations) != 2 {
		t.Fatalf("expected 2 locations, got %d", len(r0.Locations))
	}
	if r0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "src/db.go" {
		t.Fatalf("unexpected location URI: %s", r0.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}

	r1 := run.Results[1]
	if r1.Level != "note" {
		t.Fatalf("expected level note for low, got %s", r1.Level)
	}
}

func TestMapSeverityToSARIF(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "note"},
		{"", "note"},
		{"unknown", "note"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := mapSeverityToSARIF(tt.severity)
			if got != tt.want {
				t.Fatalf("mapSeverityToSARIF(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestWriteSARIF_PersistsAndRedacts(t *testing.T) {
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "audit.sarif")

	report := model.AuditReport{
		RunMetadata: model.RunMetadata{RunID: "test-run", PromptVersion: "1.0"},
		Findings: []model.Finding{
			{
				ID: "f1", Title: "Leaked token", Severity: "high", Category: "secrets",
				Evidence: "password=supersecret12", Impact: "credential leak", Remediation: "rotate",
				SourceTrack: "secrets",
			},
		},
	}

	if err := WriteSARIF(outPath, report); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read SARIF: %v", err)
	}

	if strings.Contains(string(content), "supersecret12") {
		t.Fatal("expected secret to be redacted in SARIF output")
	}

	var log sarifLog
	if err := json.Unmarshal(content, &log); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("expected version 2.1.0, got %s", log.Version)
	}
}

func TestBuildSARIF_NoFindings(t *testing.T) {
	report := model.AuditReport{
		RunMetadata: model.RunMetadata{RunID: "empty-run"},
	}
	log := buildSARIF(report)
	if len(log.Runs[0].Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(log.Runs[0].Results))
	}
}

func TestBuildSARIF_DeduplicatesRules(t *testing.T) {
	report := model.AuditReport{
		Findings: []model.Finding{
			{ID: "same-rule", Title: "A", Severity: "high", Evidence: "e1"},
			{ID: "same-rule", Title: "A", Severity: "medium", Evidence: "e2"},
		},
	}
	log := buildSARIF(report)
	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 deduplicated rule, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
	if len(log.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(log.Runs[0].Results))
	}
}
