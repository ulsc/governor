package fix

import (
	"strings"
	"testing"

	"governor/internal/model"
)

func TestBuildPrompt_IncludesSafetyAndFindingContext(t *testing.T) {
	report := model.AuditReport{
		RunMetadata:  model.RunMetadata{RunID: "run-1"},
		InputSummary: model.InputSummary{InputPath: "/tmp/repo"},
	}
	findings := []model.Finding{
		{
			ID:             "appsec-1",
			Title:          "Missing authorization check",
			Severity:       "high",
			Category:       "auth",
			SourceTrack:    "appsec",
			Confidence:     0.82,
			Exploitability: "reachable",
			FileRefs:       []string{"api/users.go"},
			AttackPath:     []string{"request.userId", "service.LoadUser", "db.QueryRow"},
			Evidence:       "handler reads user id directly from request body",
			Remediation:    "add role guard before database access",
		},
	}

	out := buildPrompt(report, findings)
	for _, want := range []string{
		"Do not produce unified diffs",
		"finding_id=appsec-1",
		"title=Missing authorization check",
		"file_refs=api/users.go",
		"attack_path=request.userId -> service.LoadUser -> db.QueryRow",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected prompt to contain %q, got:\n%s", want, out)
		}
	}
}
