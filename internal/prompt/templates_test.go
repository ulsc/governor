package prompt

import (
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
