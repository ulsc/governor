package prompt

import (
	"fmt"
	"strings"
	"testing"

	"governor/internal/checks"
	"governor/internal/model"
)

func TestBuildForCheck_IncludesCheckMetadataAndInstructions(t *testing.T) {
	check := checks.Definition{
		APIVersion:   checks.APIVersion,
		ID:           "custom-authz",
		Name:         "Custom AuthZ Check",
		Status:       checks.StatusEnabled,
		Source:       checks.SourceCustom,
		Description:  "Find missing authorization checks",
		Instructions: "Detect endpoints without role checks.",
		Scope: checks.Scope{
			IncludeGlobs: []string{"**/*.go"},
			ExcludeGlobs: []string{"**/vendor/**"},
		},
	}
	manifest := model.InputManifest{
		RootPath:      "/tmp/repo",
		IncludedFiles: 5,
		IncludedBytes: 1024,
		InputType:     "folder",
		Files:         []model.ManifestFile{{Path: "main.go", Size: 10}},
	}

	out := BuildForCheck(check, manifest)
	for _, expected := range []string{
		`ID: custom-authz`,
		`Name: Custom AuthZ Check`,
		`Description: Find missing authorization checks`,
		`Detect endpoints without role checks.`,
		`Include globs:`,
		`Exclude globs:`,
		`main.go`,
	} {
		if !strings.Contains(out, expected) {
			t.Fatalf("expected prompt to contain %q", expected)
		}
	}
}

func TestBuildForCheck_SanitizesFileHints(t *testing.T) {
	check := checks.Definition{
		APIVersion:   checks.APIVersion,
		ID:           "appsec",
		Name:         "Appsec",
		Status:       checks.StatusEnabled,
		Source:       checks.SourceBuiltin,
		Instructions: "Check.",
	}
	manifest := model.InputManifest{
		RootPath:      "/tmp/repo\ninjected",
		IncludedFiles: 1,
		IncludedBytes: 42,
		InputType:     "folder",
		Files:         []model.ManifestFile{{Path: "a.go\nDROP TABLE", Size: 10}},
	}

	out := BuildForCheck(check, manifest)
	if strings.Contains(out, "a.go\nDROP TABLE") {
		t.Fatalf("expected path newline to be sanitized")
	}
	if strings.Contains(out, "repo\ninjected") {
		t.Fatalf("expected root path newline to be sanitized")
	}
}

func TestBuildForCheck_FallsBackToUnknownFields(t *testing.T) {
	check := checks.Definition{
		APIVersion:     checks.APIVersion,
		Instructions:   "check body",
		SeverityHint:   "high",
		Status:         checks.StatusEnabled,
		Source:         checks.SourceBuiltin,
		Engine:         checks.EngineRule,
		Scope:          checks.Scope{},
		Rule:           checks.Rule{},
		CategoriesHint: []string{"secrets"},
	}
	manifest := model.InputManifest{
		RootPath:      "/tmp/repo",
		IncludedFiles: 1,
		IncludedBytes: 12,
		InputType:     "folder",
	}

	out := BuildForCheck(check, manifest)
	for _, expected := range []string{
		`ID: unknown`,
		`Name: unnamed`,
		`Description: none`,
		`Source: builtin`,
	} {
		if !strings.Contains(out, expected) {
			t.Fatalf("expected prompt fallback content %q, got:\n%s", expected, out)
		}
	}
}

func TestBuildForCheck_OmitsScopeHintsWhenEmpty(t *testing.T) {
	check := checks.Definition{
		APIVersion:   checks.APIVersion,
		ID:           "scope-test",
		Name:         "Scope Test",
		Description:  "desc",
		Instructions: "run this check",
		Status:       checks.StatusEnabled,
		Source:       checks.SourceCustom,
		Engine:       checks.EngineRule,
		Rule:         checks.Rule{Target: checks.RuleTargetFileContent, Detectors: []checks.RuleDetector{{ID: "t1", Kind: checks.RuleDetectorContains, Pattern: "needle"}}},
	}
	manifest := model.InputManifest{
		RootPath:      "/tmp/repo",
		IncludedFiles: 0,
		IncludedBytes: 0,
		InputType:     "folder",
	}

	out := BuildForCheck(check, manifest)
	if strings.Contains(out, "Scope hints:") {
		t.Fatalf("did not expect scope hints section when both include/exclude are empty")
	}
}

func TestBuildForCheck_TruncatesFileHintsTo25(t *testing.T) {
	files := make([]model.ManifestFile, 0, 30)
	for i := 0; i < 30; i++ {
		files = append(files, model.ManifestFile{Path: fmt.Sprintf("/tmp/file%02d.go", i)})
	}

	check := checks.Definition{
		APIVersion:  checks.APIVersion,
		ID:          "file-hint-test",
		Name:        "File Hint Test",
		Description: "desc",
		Status:      checks.StatusEnabled,
		Source:      checks.SourceBuiltin,
		Engine:      checks.EngineRule,
		Rule:        checks.Rule{Target: checks.RuleTargetFileContent, Detectors: []checks.RuleDetector{{ID: "t1", Kind: checks.RuleDetectorContains, Pattern: "x"}}},
	}
	manifest := model.InputManifest{
		RootPath:      "/tmp/repo",
		IncludedFiles: 30,
		IncludedBytes: 42,
		InputType:     "folder",
		Files:         files,
	}

	out := BuildForCheck(check, manifest)
	if !strings.Contains(out, "- /tmp/file00.go") {
		t.Fatalf("expected first file hint, got:\n%s", out)
	}
	if !strings.Contains(out, "- /tmp/file24.go") {
		t.Fatalf("expected 25th file hint (file24.go), got:\n%s", out)
	}
	if strings.Contains(out, "- /tmp/file25.go") {
		t.Fatalf("did not expect file beyond the 25th limit")
	}
}
