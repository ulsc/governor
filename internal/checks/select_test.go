package checks

import (
	"strings"
	"testing"
)

func TestBuildSelection_DefaultIncludesBuiltinsAndEnabledCustom(t *testing.T) {
	custom := []Definition{
		{APIVersion: APIVersion, ID: "custom-enabled", Status: StatusEnabled, Source: SourceCustom, Instructions: "x"},
		{APIVersion: APIVersion, ID: "custom-draft", Status: StatusDraft, Source: SourceCustom, Instructions: "x"},
		{APIVersion: APIVersion, ID: "custom-disabled", Status: StatusDisabled, Source: SourceCustom, Instructions: "x"},
	}

	res, err := BuildSelection(Builtins(), custom, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ids := map[string]struct{}{}
	for _, check := range res.Checks {
		ids[check.ID] = struct{}{}
	}

	if _, ok := ids["appsec"]; !ok {
		t.Fatalf("expected appsec builtin to be selected")
	}
	if _, ok := ids["custom-enabled"]; !ok {
		t.Fatalf("expected custom-enabled to be selected")
	}
	if _, ok := ids["custom-draft"]; ok {
		t.Fatalf("did not expect draft check to be selected")
	}
	if _, ok := ids["custom-disabled"]; ok {
		t.Fatalf("did not expect disabled check to be selected")
	}
}

func TestBuildSelection_OnlyAndSkipApplied(t *testing.T) {
	custom := []Definition{
		{APIVersion: APIVersion, ID: "foo", Status: StatusEnabled, Source: SourceCustom, Instructions: "x"},
		{APIVersion: APIVersion, ID: "bar", Status: StatusEnabled, Source: SourceCustom, Instructions: "x"},
	}

	res, err := BuildSelection(Builtins(), custom, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   true,
		OnlyIDs:         []string{"foo", "appsec"},
		SkipIDs:         []string{"appsec"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Checks) != 1 {
		t.Fatalf("expected 1 selected check, got %d", len(res.Checks))
	}
	if res.Checks[0].ID != "foo" {
		t.Fatalf("expected foo, got %s", res.Checks[0].ID)
	}
}

func TestBuildSelection_DuplicateIDWarnsAndKeepsFirstDefinition(t *testing.T) {
	builtins := []Definition{
		{
			APIVersion:   APIVersion,
			ID:           "dup-check",
			Name:         "Builtin Dup",
			Status:       StatusEnabled,
			Source:       SourceBuiltin,
			Instructions: "builtin instructions",
		},
	}
	custom := []Definition{
		{
			APIVersion:   APIVersion,
			ID:           "dup-check",
			Name:         "Custom Dup",
			Status:       StatusEnabled,
			Source:       SourceCustom,
			Instructions: "custom instructions",
		},
	}

	res, err := BuildSelection(builtins, custom, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Checks) != 1 {
		t.Fatalf("expected one selected check, got %d", len(res.Checks))
	}
	selected := res.Checks[0]
	if selected.ID != "dup-check" {
		t.Fatalf("expected dup-check id, got %q", selected.ID)
	}
	if selected.Source != SourceBuiltin {
		t.Fatalf("expected builtin to win on duplicate id, got source %q", selected.Source)
	}
	if selected.Instructions != "builtin instructions" {
		t.Fatalf("expected builtin definition to be preserved, got %q", selected.Instructions)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("expected duplicate warning")
	}
	if !strings.Contains(res.Warnings[0], `duplicate check id "dup-check"`) {
		t.Fatalf("unexpected warning: %v", res.Warnings)
	}
}

func TestBuildSelection_MissingOnlyIDsWarnsSortedAndErrorsWhenNoneSelected(t *testing.T) {
	custom := []Definition{
		{
			APIVersion:   APIVersion,
			ID:           "skipped-check",
			Status:       StatusEnabled,
			Source:       SourceCustom,
			Instructions: "enabled check",
		},
	}

	res, err := BuildSelection(nil, custom, SelectionOptions{
		IncludeBuiltins: false,
		IncludeCustom:   true,
		OnlyIDs:         []string{"missing-b", "skipped-check", "missing-a"},
		SkipIDs:         []string{"skipped-check"},
	})
	if err == nil {
		t.Fatal("expected no-checks-selected error")
	}
	if !strings.Contains(err.Error(), "no checks selected") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Checks) != 0 {
		t.Fatalf("expected zero selected checks, got %d", len(res.Checks))
	}
	if len(res.Warnings) != 3 {
		t.Fatalf("expected 3 warnings for filtered/missing only-check IDs, got %d: %v", len(res.Warnings), res.Warnings)
	}
	expected := []string{
		`--only-check requested unknown or filtered check "missing-a"`,
		`--only-check requested unknown or filtered check "missing-b"`,
		`--only-check requested unknown or filtered check "skipped-check"`,
	}
	for i, want := range expected {
		if res.Warnings[i] != want {
			t.Fatalf("unexpected warning at index %d: got %q want %q", i, res.Warnings[i], want)
		}
	}
}

func TestBuildSelection_IncludeDraftIncludesDraftChecks(t *testing.T) {
	custom := []Definition{
		{
			APIVersion:   APIVersion,
			ID:           "draft-check",
			Status:       StatusDraft,
			Source:       SourceCustom,
			Instructions: "draft instructions",
		},
		{
			APIVersion:   APIVersion,
			ID:           "enabled-check",
			Status:       StatusEnabled,
			Source:       SourceCustom,
			Instructions: "enabled instructions",
		},
	}

	res, err := BuildSelection(nil, custom, SelectionOptions{
		IncludeCustom: true,
		IncludeDraft:  true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Checks) != 2 {
		t.Fatalf("expected 2 selected checks, got %d", len(res.Checks))
	}

	ids := map[string]struct{}{}
	for _, selected := range res.Checks {
		ids[selected.ID] = struct{}{}
	}
	if _, ok := ids["draft-check"]; !ok {
		t.Fatal("expected draft-check to be selected when include-draft is enabled")
	}
	if _, ok := ids["enabled-check"]; !ok {
		t.Fatal("expected enabled-check to be selected")
	}
}

func TestBuildSelection_ErrorsWhenBuiltinsAndCustomDisabled(t *testing.T) {
	_, err := BuildSelection(nil, nil, SelectionOptions{
		IncludeBuiltins: false,
		IncludeCustom:   false,
	})
	if err == nil {
		t.Fatal("expected selection configuration error when both sources are disabled")
	}
	if !strings.Contains(err.Error(), "selection disabled both built-in and custom checks") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildSelection_NormalizesOnlyAndSkipIDs(t *testing.T) {
	custom := []Definition{
		{
			APIVersion:   APIVersion,
			ID:           "foo",
			Status:       StatusEnabled,
			Source:       SourceCustom,
			Instructions: "foo instructions",
		},
	}

	res, err := BuildSelection(Builtins(), custom, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   true,
		OnlyIDs:         []string{" APPSEC ", " FoO "},
		SkipIDs:         []string{" appsec "},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Checks) != 1 {
		t.Fatalf("expected exactly one selected check, got %d", len(res.Checks))
	}
	if res.Checks[0].ID != "foo" {
		t.Fatalf("expected foo to remain selected, got %q", res.Checks[0].ID)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("expected one warning for filtered appsec only-id, got %d: %v", len(res.Warnings), res.Warnings)
	}
	if got, want := res.Warnings[0], `--only-check requested unknown or filtered check "appsec"`; got != want {
		t.Fatalf("unexpected warning: got %q want %q", got, want)
	}
}

func TestBuildSelection_EngineFilterRuleOnly(t *testing.T) {
	builtins := Builtins()
	res, err := BuildSelection(builtins, nil, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   false,
		EngineFilter:    EngineRule,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, check := range res.Checks {
		if check.Engine != EngineRule {
			t.Errorf("engine filter rule should exclude check %q with engine %q", check.ID, check.Engine)
		}
	}
	if len(res.Checks) == 0 {
		t.Fatal("expected at least one rule check from builtins")
	}
}

func TestBuildSelection_EngineFilterAIOnly(t *testing.T) {
	builtins := Builtins()
	res, err := BuildSelection(builtins, nil, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   false,
		EngineFilter:    EngineAI,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, check := range res.Checks {
		if check.Engine != EngineAI {
			t.Errorf("engine filter ai should exclude check %q with engine %q", check.ID, check.Engine)
		}
	}
}

func TestBuildSelection_EngineFilterEmptyIncludesAll(t *testing.T) {
	builtins := Builtins()
	allRes, err := BuildSelection(builtins, nil, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ruleRes, err := BuildSelection(builtins, nil, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   false,
		EngineFilter:    EngineRule,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	aiRes, err := BuildSelection(builtins, nil, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   false,
		EngineFilter:    EngineAI,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ruleRes.Checks)+len(aiRes.Checks) != len(allRes.Checks) {
		t.Errorf("rule (%d) + ai (%d) != all (%d)", len(ruleRes.Checks), len(aiRes.Checks), len(allRes.Checks))
	}
}
