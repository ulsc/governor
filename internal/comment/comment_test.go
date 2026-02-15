package comment

import (
	"strings"
	"testing"

	"governor/internal/diff"
	"governor/internal/model"
)

func TestGenerate_NoDiff(t *testing.T) {
	report := model.AuditReport{
		Findings: []model.Finding{
			{Title: "SQL injection", Severity: "critical", SourceTrack: "appsec", FileRefs: []string{"src/api.go"}},
			{Title: "Missing rate limit", Severity: "medium", SourceTrack: "appsec"},
		},
	}

	result := Generate(report, nil, Options{})

	if !strings.Contains(result, "## Governor Security Audit") {
		t.Error("expected header")
	}
	if !strings.Contains(result, "**2 finding(s)**") {
		t.Error("expected finding count")
	}
	if !strings.Contains(result, "SQL injection") {
		t.Error("expected finding title")
	}
	if !strings.Contains(result, "| Critical |") {
		t.Error("expected severity in table")
	}
}

func TestGenerate_WithDiff(t *testing.T) {
	report := model.AuditReport{
		SuppressedCount: 2,
	}
	dr := &diff.DiffReport{
		New: []model.Finding{
			{Title: "New finding", Severity: "high", SourceTrack: "appsec", FileRefs: []string{"new.go"}},
		},
		Fixed: []model.Finding{
			{Title: "Fixed finding", Severity: "medium", SourceTrack: "secrets"},
		},
		Unchanged: []model.Finding{
			{Title: "Unchanged", Severity: "low", SourceTrack: "appsec"},
		},
		Summary: diff.DiffSummary{
			NewCount:       1,
			FixedCount:     1,
			UnchangedCount: 1,
		},
	}

	result := Generate(report, dr, Options{})

	if !strings.Contains(result, "**1 new finding(s)**") {
		t.Errorf("expected new findings count, got:\n%s", result)
	}
	if !strings.Contains(result, "1 fixed") {
		t.Error("expected fixed count")
	}
	if !strings.Contains(result, "1 unchanged") {
		t.Error("expected unchanged count")
	}
	if !strings.Contains(result, "2 suppressed") {
		t.Error("expected suppressed count")
	}
	if !strings.Contains(result, "### New Findings") {
		t.Error("expected new findings section")
	}
	if !strings.Contains(result, "### Fixed (since baseline)") {
		t.Error("expected fixed section")
	}
	if !strings.Contains(result, "<details>") {
		t.Error("expected collapsed unchanged section")
	}
}

func TestGenerate_NoFindings(t *testing.T) {
	report := model.AuditReport{}
	result := Generate(report, nil, Options{})

	if !strings.Contains(result, "**0 finding(s)**") {
		t.Errorf("expected 0 findings, got:\n%s", result)
	}
	if !strings.Contains(result, "No security findings detected.") {
		t.Error("expected no findings message")
	}
}

func TestGenerate_ZeroNewWithDiff(t *testing.T) {
	report := model.AuditReport{}
	dr := &diff.DiffReport{
		Unchanged: []model.Finding{
			{Title: "Existing", Severity: "medium", SourceTrack: "appsec"},
		},
		Summary: diff.DiffSummary{
			UnchangedCount: 1,
		},
	}

	result := Generate(report, dr, Options{})

	if !strings.Contains(result, "**0 new findings**") {
		t.Errorf("expected 0 new findings, got:\n%s", result)
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with|pipe", "with\\|pipe"},
		{"with\nnewline", "with newline"},
	}
	for _, tc := range tests {
		got := sanitize(tc.input)
		if got != tc.want {
			t.Errorf("sanitize(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestTitleCase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "Critical"},
		{"HIGH", "High"},
		{"", ""},
		{"medium", "Medium"},
	}
	for _, tc := range tests {
		got := titleCase(tc.input)
		if got != tc.want {
			t.Errorf("titleCase(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
