package scan

import (
	"encoding/json"
	"strings"
	"testing"

	"governor/internal/model"
)

func TestFormatHuman_NoFindings(t *testing.T) {
	out := FormatHuman(nil)
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected 'No findings' in output, got: %s", out)
	}
}

func TestFormatHuman_WithFindings(t *testing.T) {
	findings := []model.Finding{
		{
			Title:       "Hardcoded secret",
			Severity:    "high",
			FileRefs:    []string{"config.go"},
			Evidence:    "password = 'secret123'",
			Remediation: "Use environment variables",
		},
	}
	out := FormatHuman(findings)
	if !strings.Contains(out, "[HIGH") {
		t.Error("expected [HIGH in output")
	}
	if !strings.Contains(out, "Hardcoded secret") {
		t.Error("expected title in output")
	}
	if !strings.Contains(out, "config.go") {
		t.Error("expected file ref in output")
	}
	if !strings.Contains(out, "1 finding(s)") {
		t.Error("expected finding count in output")
	}
}

func TestFormatJSON_WithFindings(t *testing.T) {
	findings := []model.Finding{
		{Title: "Test finding", Severity: "medium"},
	}
	out, err := FormatJSON(findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed []model.Finding
	if unmarshalErr := json.Unmarshal([]byte(out), &parsed); unmarshalErr != nil {
		t.Fatalf("invalid JSON: %v", unmarshalErr)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed))
	}
	if parsed[0].Title != "Test finding" {
		t.Errorf("expected title 'Test finding', got %q", parsed[0].Title)
	}
}

func TestFormatJSON_NilFindings(t *testing.T) {
	out, err := FormatJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out, "[") {
		t.Error("expected JSON array for nil findings")
	}
}

func TestFormatHumanColorized_SortsBySeverity(t *testing.T) {
	findings := []model.Finding{
		{Title: "Low issue", Severity: "low"},
		{Title: "Critical issue", Severity: "critical"},
		{Title: "High issue", Severity: "high"},
	}
	out := FormatHumanColorized(findings, false)
	critIdx := strings.Index(out, "Critical issue")
	highIdx := strings.Index(out, "High issue")
	lowIdx := strings.Index(out, "Low issue")
	if critIdx < 0 || highIdx < 0 || lowIdx < 0 {
		t.Fatalf("expected all findings in output, got:\n%s", out)
	}
	if critIdx > highIdx {
		t.Errorf("critical should appear before high; critical at %d, high at %d", critIdx, highIdx)
	}
	if highIdx > lowIdx {
		t.Errorf("high should appear before low; high at %d, low at %d", highIdx, lowIdx)
	}
}

func TestFormatHumanColorized_SummaryHeader(t *testing.T) {
	findings := []model.Finding{
		{Title: "A", Severity: "critical"},
		{Title: "B", Severity: "high"},
		{Title: "C", Severity: "medium"},
	}
	out := FormatHumanColorized(findings, false)
	if !strings.Contains(out, "3 findings") {
		t.Errorf("expected '3 findings' in summary header, got:\n%s", out)
	}
	if !strings.Contains(out, "1 critical") {
		t.Errorf("expected '1 critical' in summary header, got:\n%s", out)
	}
}

func TestFormatHumanColorized_NoFindings(t *testing.T) {
	out := FormatHumanColorized(nil, false)
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected 'No findings' message, got: %s", out)
	}
}

func TestFormatHumanColorized_VerboseIncludesEvidence(t *testing.T) {
	findings := []model.Finding{
		{
			Title:    "Test finding",
			Severity: "high",
			Evidence: "some evidence text here",
		},
	}

	verbose := FormatHumanColorized(findings, true)
	if !strings.Contains(verbose, "some evidence text here") {
		t.Errorf("verbose mode should include evidence, got:\n%s", verbose)
	}

	concise := FormatHumanColorized(findings, false)
	if strings.Contains(concise, "some evidence text here") {
		t.Errorf("non-verbose mode should not include evidence, got:\n%s", concise)
	}
}
