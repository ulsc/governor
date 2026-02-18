package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"governor/internal/diff"
	"governor/internal/model"
)

func TestLoadAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := `api_version: governor/policy/v1
defaults:
  fail_on_severity: high
  max_suppression_ratio: 0.4
  require_checks: [appsec]
rules:
  - name: backend-relaxed
    when:
      paths: ["api/**"]
    enforce:
      fail_on_severity: medium
waivers:
  - id: waiver-1
    reason: temp waiver
    expires: "2099-01-01"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if p.APIVersion != APIVersion {
		t.Fatalf("unexpected api version: %s", p.APIVersion)
	}
	if got := p.Defaults.FailOnSeverity; got != "high" {
		t.Fatalf("unexpected severity: %s", got)
	}
}

func TestValidateRejectsInvalidSeverity(t *testing.T) {
	p := Normalize(Policy{APIVersion: APIVersion, Defaults: Gate{FailOnSeverity: "urgent"}})
	err := Validate(p)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "fail_on_severity") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEvaluateGateViolationsAndWaiver(t *testing.T) {
	ratio := 0.3
	maxNew := 0
	p := Normalize(Policy{
		APIVersion: APIVersion,
		Defaults: Gate{
			FailOnSeverity:      "high",
			MaxSuppressionRatio: &ratio,
			MaxNewFindings:      &maxNew,
			RequireChecks:       []string{"appsec"},
			ForbidChecks:        []string{"secrets"},
		},
		Waivers: []Waiver{{
			ID:     "waive-high",
			Reason: "accepted risk",
			Match: MatchSpec{
				Checks: []string{"appsec"},
			},
		}},
	})

	report := model.AuditReport{
		RunMetadata: model.RunMetadata{CheckIDs: []string{"appsec", "secrets"}},
		Findings: []model.Finding{{
			Severity:    "high",
			Category:    "auth",
			SourceTrack: "appsec",
			FileRefs:    []string{"api/auth.go"},
		}},
		SuppressedCount: 4,
	}
	dr := &diff.DiffReport{Summary: diff.DiffSummary{NewCount: 1}}

	decision := Evaluate(".governor/policy.yaml", p, report, dr)
	if decision.Path == "" {
		t.Fatal("expected policy path")
	}
	if decision.Passed {
		t.Fatal("expected policy decision to fail")
	}
	if len(decision.Violations) == 0 {
		t.Fatal("expected violations")
	}
	waivedFound := false
	for _, v := range decision.Violations {
		if v.Code == "fail_on_severity" && v.Waived {
			waivedFound = true
		}
	}
	if !waivedFound {
		t.Fatal("expected severity violation to be waived")
	}
}

func TestRuleMatchOverridesDefaults(t *testing.T) {
	p := Normalize(Policy{
		APIVersion: APIVersion,
		Defaults:   Gate{FailOnSeverity: "high"},
		Rules: []Rule{{
			Name: "api-rule",
			When: MatchSpec{Paths: []string{"api/**"}},
			Enforce: Gate{
				FailOnSeverity: "medium",
			},
		}},
	})
	report := model.AuditReport{Findings: []model.Finding{{FileRefs: []string{"api/server.go"}}}}
	gate := EffectiveGate(p, report)
	if gate.FailOnSeverity != "medium" {
		t.Fatalf("expected rule override severity medium, got %s", gate.FailOnSeverity)
	}
}
