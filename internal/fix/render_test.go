package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"governor/internal/model"
)

func TestRenderMarkdown_BasicSections(t *testing.T) {
	report := model.FixReport{
		GeneratedAt:   time.Date(2026, time.February, 20, 12, 0, 0, 0, time.UTC),
		SourceAudit:   "/tmp/runs/run/audit.json",
		SourceRunID:   "run-1",
		AIProfile:     "codex",
		AIProvider:    "codex-cli",
		TotalFindings: 3,
		Selected:      1,
		Suggestions: []model.FixSuggestion{
			{
				FindingID:   "appsec-1",
				Title:       "Missing authorization check",
				SourceTrack: "appsec",
				Priority:    "high",
				Summary:     "Add middleware guard before handler.",
				Files: []model.FixFileChange{
					{
						Path:         "api/users.go",
						ChangeType:   "modify",
						Instructions: []string{"Add requireAdmin middleware in route registration."},
					},
				},
				ValidationSteps: []string{"Run auth integration tests."},
				RiskNotes:       []string{"May block unauthorized traffic previously allowed."},
			},
		},
	}

	md := renderMarkdown(report)
	for _, want := range []string{
		"# Governor Fix Suggestions",
		"## Suggestions",
		"Missing authorization check",
		"#### File Changes",
		"api/users.go",
		"#### Validation Steps",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("expected markdown to contain %q, got:\n%s", want, md)
		}
	}
}

func TestWriteFixArtifacts(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "fix.json")
	mdPath := filepath.Join(dir, "fix.md")

	report := model.FixReport{
		GeneratedAt: time.Now().UTC(),
		SourceAudit: "/tmp/run/audit.json",
		Suggestions: []model.FixSuggestion{
			{
				FindingID: "f-1",
				Title:     "Fix title",
				Summary:   "summary",
			},
		},
	}

	if err := writeJSON(jsonPath, report); err != nil {
		t.Fatalf("writeJSON failed: %v", err)
	}
	if err := writeMarkdown(mdPath, report); err != nil {
		t.Fatalf("writeMarkdown failed: %v", err)
	}

	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("expected json artifact: %v", err)
	}
	content, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read markdown artifact: %v", err)
	}
	if !strings.Contains(string(content), "Governor Fix Suggestions") {
		t.Fatalf("unexpected markdown content: %s", string(content))
	}
}
