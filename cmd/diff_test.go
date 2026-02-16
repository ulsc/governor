package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"governor/internal/diff"
	"governor/internal/model"
)

func writeAuditJSON(t *testing.T, dir string, name string, report model.AuditReport) string {
	t.Helper()
	path := filepath.Join(dir, name)
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunDiff_BasicComparison(t *testing.T) {
	dir := t.TempDir()

	oldReport := model.AuditReport{
		Findings: []model.Finding{
			{Title: "Finding A", Severity: "high", Category: "auth", SourceTrack: "appsec"},
			{Title: "Finding B", Severity: "medium", Category: "crypto", SourceTrack: "appsec"},
		},
		CountsBySeverity: map[string]int{"high": 1, "medium": 1},
	}
	newReport := model.AuditReport{
		Findings: []model.Finding{
			{Title: "Finding B", Severity: "medium", Category: "crypto", SourceTrack: "appsec"},
			{Title: "Finding C", Severity: "critical", Category: "injection", SourceTrack: "appsec"},
		},
		CountsBySeverity: map[string]int{"critical": 1, "medium": 1},
	}

	oldPath := writeAuditJSON(t, dir, "old.json", oldReport)
	newPath := writeAuditJSON(t, dir, "new.json", newReport)

	err := Execute([]string{"diff", oldPath, newPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunDiff_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	oldReport := model.AuditReport{
		Findings:         []model.Finding{{Title: "A", Severity: "high", Category: "auth"}},
		CountsBySeverity: map[string]int{"high": 1},
	}
	newReport := model.AuditReport{
		Findings:         []model.Finding{{Title: "B", Severity: "low", Category: "crypto"}},
		CountsBySeverity: map[string]int{"low": 1},
	}

	oldPath := writeAuditJSON(t, dir, "old.json", oldReport)
	newPath := writeAuditJSON(t, dir, "new.json", newReport)

	err := Execute([]string{"diff", "--json", oldPath, newPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunDiff_FailOnNewFindings(t *testing.T) {
	dir := t.TempDir()

	oldReport := model.AuditReport{
		Findings:         []model.Finding{},
		CountsBySeverity: map[string]int{},
	}
	newReport := model.AuditReport{
		Findings:         []model.Finding{{Title: "Critical Bug", Severity: "critical", Category: "auth"}},
		CountsBySeverity: map[string]int{"critical": 1},
	}

	oldPath := writeAuditJSON(t, dir, "old.json", oldReport)
	newPath := writeAuditJSON(t, dir, "new.json", newReport)

	err := Execute([]string{"diff", "--fail-on", "high", oldPath, newPath})
	if err == nil {
		t.Fatal("expected error due to --fail-on threshold exceeded")
	}
}

func TestRunDiff_FailOnNoNewFindings(t *testing.T) {
	dir := t.TempDir()

	report := model.AuditReport{
		Findings:         []model.Finding{{Title: "Same", Severity: "high", Category: "auth"}},
		CountsBySeverity: map[string]int{"high": 1},
	}

	oldPath := writeAuditJSON(t, dir, "old.json", report)
	newPath := writeAuditJSON(t, dir, "new.json", report)

	err := Execute([]string{"diff", "--fail-on", "high", oldPath, newPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunDiff_OutFile(t *testing.T) {
	dir := t.TempDir()

	oldReport := model.AuditReport{
		Findings:         []model.Finding{{Title: "A", Severity: "high", Category: "auth"}},
		CountsBySeverity: map[string]int{"high": 1},
	}
	newReport := model.AuditReport{
		Findings:         []model.Finding{{Title: "B", Severity: "low", Category: "crypto"}},
		CountsBySeverity: map[string]int{"low": 1},
	}

	oldPath := writeAuditJSON(t, dir, "old.json", oldReport)
	newPath := writeAuditJSON(t, dir, "new.json", newReport)
	outPath := filepath.Join(dir, "diff-out.json")

	err := Execute([]string{"diff", "--out", outPath, oldPath, newPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("failed to read output file: %v", readErr)
	}
	var dr diff.DiffReport
	if unmarshalErr := json.Unmarshal(raw, &dr); unmarshalErr != nil {
		t.Fatalf("invalid JSON in output file: %v", unmarshalErr)
	}
	if dr.Summary.NewCount != 1 || dr.Summary.FixedCount != 1 {
		t.Fatalf("unexpected diff summary: new=%d fixed=%d", dr.Summary.NewCount, dr.Summary.FixedCount)
	}
}

func TestRunDiff_MissingArgs(t *testing.T) {
	err := Execute([]string{"diff"})
	if err == nil {
		t.Fatal("expected error for missing args")
	}

	err = Execute([]string{"diff", "only-one.json"})
	if err == nil {
		t.Fatal("expected error for single arg")
	}
}

func TestRunDiff_InvalidJSON(t *testing.T) {
	dir := t.TempDir()

	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	goodReport := model.AuditReport{
		Findings:         []model.Finding{},
		CountsBySeverity: map[string]int{},
	}
	goodPath := writeAuditJSON(t, dir, "good.json", goodReport)

	err := Execute([]string{"diff", badPath, goodPath})
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	err = Execute([]string{"diff", goodPath, badPath})
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
