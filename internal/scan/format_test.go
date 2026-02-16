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
