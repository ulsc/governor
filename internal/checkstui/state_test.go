package checkstui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"governor/internal/checks"
)

func TestLoadSnapshot_IncludesBuiltinAndEffectiveCustomRows(t *testing.T) {
	withRepoAndHomeChecks(t, func(repoChecks string, _ string) {
		if _, err := checks.WriteDefinition(repoChecks, validCustomDefinition("custom-effective", "Custom Effective", checks.StatusEnabled), false); err != nil {
			t.Fatalf("write custom check: %v", err)
		}

		snap, err := loadSnapshot("")
		if err != nil {
			t.Fatalf("load snapshot: %v", err)
		}

		custom, ok := findRow(snap.Rows, "custom-effective", checks.SourceCustom)
		if !ok {
			t.Fatal("expected custom-effective row in snapshot")
		}
		if !custom.Effective || custom.Shadowed || custom.Invalid {
			t.Fatalf("expected effective custom row, got %+v", custom)
		}
		if !custom.Mutable {
			t.Fatal("expected effective custom row to be mutable")
		}
		if !strings.HasSuffix(custom.Path, "custom-effective.check.yaml") {
			t.Fatalf("unexpected custom row path: %q", custom.Path)
		}

		builtin, ok := findRow(snap.Rows, "appsec", checks.SourceBuiltin)
		if !ok {
			t.Fatal("expected appsec builtin row in snapshot")
		}
		if !builtin.Effective || builtin.Shadowed || builtin.Invalid {
			t.Fatalf("expected effective builtin row, got %+v", builtin)
		}
		if builtin.Mutable {
			t.Fatal("expected builtin row to be read-only")
		}
		if builtin.Path != "(builtin)" {
			t.Fatalf("expected builtin path marker, got %q", builtin.Path)
		}
	})
}

func TestLoadSnapshot_MapsInvalidCheckDiagnosticsToInvalidRow(t *testing.T) {
	withRepoAndHomeChecks(t, func(repoChecks string, _ string) {
		if err := os.MkdirAll(repoChecks, 0o700); err != nil {
			t.Fatalf("create checks dir: %v", err)
		}
		invalidPath := filepath.Join(repoChecks, "bad-file.check.yaml")
		if err := os.WriteFile(invalidPath, []byte("api_version: ["), 0o600); err != nil {
			t.Fatalf("write invalid check file: %v", err)
		}

		snap, err := loadSnapshot("")
		if err != nil {
			t.Fatalf("load snapshot: %v", err)
		}

		invalid, ok := findRow(snap.Rows, "bad-file", checks.SourceCustom)
		if !ok {
			t.Fatal("expected invalid row for bad-file.check.yaml")
		}
		if !invalid.Invalid {
			t.Fatalf("expected invalid=true, got %+v", invalid)
		}
		if invalid.Mutable {
			t.Fatal("expected invalid rows to be read-only")
		}
		if invalid.Status != checks.StatusDisabled {
			t.Fatalf("expected disabled status for invalid row, got %q", invalid.Status)
		}
		if invalid.Name != "(invalid check file)" {
			t.Fatalf("unexpected invalid row name %q", invalid.Name)
		}
		if invalid.DiagError == 0 {
			t.Fatalf("expected invalid row to include error diagnostics, got %+v", invalid)
		}
		if !strings.HasSuffix(invalid.Path, "bad-file.check.yaml") {
			t.Fatalf("unexpected invalid row path: %q", invalid.Path)
		}
	})
}

func TestLoadSnapshot_MarksShadowedDuplicateRows(t *testing.T) {
	withRepoAndHomeChecks(t, func(repoChecks string, homeChecks string) {
		if _, err := checks.WriteDefinition(repoChecks, validCustomDefinition("dup-check", "Repo Winner", checks.StatusEnabled), false); err != nil {
			t.Fatalf("write repo check: %v", err)
		}
		if _, err := checks.WriteDefinition(homeChecks, validCustomDefinition("dup-check", "Home Shadowed", checks.StatusEnabled), false); err != nil {
			t.Fatalf("write home check: %v", err)
		}

		snap, err := loadSnapshot("")
		if err != nil {
			t.Fatalf("load snapshot: %v", err)
		}

		var effectiveRow row
		var shadowedRow row
		effectiveCount := 0
		shadowedCount := 0
		for _, candidate := range snap.Rows {
			if candidate.ID != "dup-check" || candidate.Source != checks.SourceCustom {
				continue
			}
			if candidate.Effective && !candidate.Shadowed {
				effectiveCount++
				effectiveRow = candidate
			}
			if candidate.Shadowed {
				shadowedCount++
				shadowedRow = candidate
			}
		}

		if effectiveCount != 1 || shadowedCount != 1 {
			t.Fatalf("expected one effective and one shadowed dup-check row, got effective=%d shadowed=%d", effectiveCount, shadowedCount)
		}
		if !effectiveRow.Mutable {
			t.Fatal("expected effective duplicate winner to remain mutable")
		}
		if shadowedRow.Mutable {
			t.Fatal("expected shadowed duplicate row to be read-only")
		}
		if shadowedRow.DiagWarning == 0 {
			t.Fatalf("expected shadowed row warning diagnostics, got %+v", shadowedRow)
		}
		repoCanonical := mustEvalSymlinks(t, repoChecks)
		homeCanonical := mustEvalSymlinks(t, homeChecks)
		effectiveCanonical := mustEvalSymlinks(t, effectiveRow.Path)
		shadowedCanonical := mustEvalSymlinks(t, shadowedRow.Path)
		if !strings.HasPrefix(effectiveCanonical, repoCanonical) {
			t.Fatalf("expected repo check to win precedence, got %q", effectiveRow.Path)
		}
		if !strings.HasPrefix(shadowedCanonical, homeCanonical) {
			t.Fatalf("expected home check to be shadowed, got %q", shadowedRow.Path)
		}
	})
}

func withRepoAndHomeChecks(t *testing.T, fn func(repoChecks string, homeChecks string)) {
	t.Helper()

	repoRoot := t.TempDir()
	homeRoot := filepath.Join(t.TempDir(), "home")

	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o700); err != nil {
		t.Fatalf("create .git: %v", err)
	}

	t.Setenv("HOME", homeRoot)

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
	}()

	repoChecks := filepath.Join(repoRoot, ".governor", "checks")
	homeChecks := filepath.Join(homeRoot, ".governor", "checks")
	fn(repoChecks, homeChecks)
}

func validCustomDefinition(id string, name string, status checks.Status) checks.Definition {
	return checks.Definition{
		APIVersion:   checks.APIVersion,
		ID:           id,
		Name:         name,
		Status:       status,
		Source:       checks.SourceCustom,
		Description:  "custom test check",
		Instructions: "Analyze authentication and authorization flows, identify insecure access control patterns, and report concrete evidence with remediation guidance.",
		Scope: checks.Scope{
			IncludeGlobs: []string{"**/*.go"},
			ExcludeGlobs: []string{"**/vendor/**"},
		},
	}
}

func findRow(rows []row, id string, source checks.Source) (row, bool) {
	for _, candidate := range rows {
		if candidate.ID == id && candidate.Source == source {
			return candidate, true
		}
	}
	return row{}, false
}

func mustEvalSymlinks(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve path %q: %v", path, err)
	}
	return resolved
}
