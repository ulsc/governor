package diff

import (
	"testing"

	"governor/internal/model"
)

func TestCompare_AllNew(t *testing.T) {
	baseline := model.AuditReport{}
	current := model.AuditReport{
		Findings: []model.Finding{
			{Title: "A", Severity: "high", Category: "auth", Evidence: "evidence a"},
			{Title: "B", Severity: "low", Category: "config", Evidence: "evidence b"},
		},
	}

	dr := Compare(baseline, current)
	if dr.Summary.NewCount != 2 {
		t.Fatalf("expected 2 new, got %d", dr.Summary.NewCount)
	}
	if dr.Summary.FixedCount != 0 {
		t.Fatalf("expected 0 fixed, got %d", dr.Summary.FixedCount)
	}
	if dr.Summary.UnchangedCount != 0 {
		t.Fatalf("expected 0 unchanged, got %d", dr.Summary.UnchangedCount)
	}
}

func TestCompare_AllFixed(t *testing.T) {
	baseline := model.AuditReport{
		Findings: []model.Finding{
			{Title: "A", Severity: "high", Category: "auth", Evidence: "evidence a"},
		},
	}
	current := model.AuditReport{}

	dr := Compare(baseline, current)
	if dr.Summary.NewCount != 0 {
		t.Fatalf("expected 0 new, got %d", dr.Summary.NewCount)
	}
	if dr.Summary.FixedCount != 1 {
		t.Fatalf("expected 1 fixed, got %d", dr.Summary.FixedCount)
	}
}

func TestCompare_Mixed(t *testing.T) {
	shared := model.Finding{Title: "Shared", Severity: "medium", Category: "auth", Evidence: "shared evidence"}
	baseline := model.AuditReport{
		Findings: []model.Finding{
			shared,
			{Title: "Old", Severity: "low", Category: "config", Evidence: "old evidence"},
		},
	}
	current := model.AuditReport{
		Findings: []model.Finding{
			shared,
			{Title: "New", Severity: "critical", Category: "injection", Evidence: "new evidence"},
		},
	}

	dr := Compare(baseline, current)
	if dr.Summary.NewCount != 1 {
		t.Fatalf("expected 1 new, got %d", dr.Summary.NewCount)
	}
	if dr.Summary.FixedCount != 1 {
		t.Fatalf("expected 1 fixed, got %d", dr.Summary.FixedCount)
	}
	if dr.Summary.UnchangedCount != 1 {
		t.Fatalf("expected 1 unchanged, got %d", dr.Summary.UnchangedCount)
	}
	if dr.New[0].Title != "New" {
		t.Fatalf("expected new finding 'New', got %q", dr.New[0].Title)
	}
	if dr.Fixed[0].Title != "Old" {
		t.Fatalf("expected fixed finding 'Old', got %q", dr.Fixed[0].Title)
	}
}

func TestCompare_BothEmpty(t *testing.T) {
	dr := Compare(model.AuditReport{}, model.AuditReport{})
	if dr.Summary.NewCount != 0 || dr.Summary.FixedCount != 0 || dr.Summary.UnchangedCount != 0 {
		t.Fatalf("expected all zeros for empty reports")
	}
}

func TestCompare_SeverityChangeIsNew(t *testing.T) {
	// Same title but different evidence → different key → shows as new + fixed
	baseline := model.AuditReport{
		Findings: []model.Finding{
			{Title: "Auth bypass", Severity: "medium", Category: "auth", Evidence: "old route"},
		},
	}
	current := model.AuditReport{
		Findings: []model.Finding{
			{Title: "Auth bypass", Severity: "critical", Category: "auth", Evidence: "new route"},
		},
	}

	dr := Compare(baseline, current)
	if dr.Summary.NewCount != 1 {
		t.Fatalf("expected 1 new (different evidence), got %d", dr.Summary.NewCount)
	}
	if dr.Summary.FixedCount != 1 {
		t.Fatalf("expected 1 fixed (old evidence gone), got %d", dr.Summary.FixedCount)
	}
}

func TestCompare_FileRefsAffectKey(t *testing.T) {
	f1 := model.Finding{Title: "XSS", Severity: "high", Category: "web", Evidence: "ev", FileRefs: []string{"a.go"}}
	f2 := model.Finding{Title: "XSS", Severity: "high", Category: "web", Evidence: "ev", FileRefs: []string{"b.go"}}

	baseline := model.AuditReport{Findings: []model.Finding{f1}}
	current := model.AuditReport{Findings: []model.Finding{f2}}

	dr := Compare(baseline, current)
	if dr.Summary.NewCount != 1 || dr.Summary.FixedCount != 1 {
		t.Fatalf("expected different file refs to create new+fixed, got new=%d fixed=%d", dr.Summary.NewCount, dr.Summary.FixedCount)
	}
}
