package checks

import (
	"strings"
	"testing"
)

func TestBuiltins_AllDefinitionsValidateAndHaveUniqueIDs(t *testing.T) {
	defs := Builtins()
	if len(defs) == 0 {
		t.Fatal("expected at least one builtin definition")
	}

	seen := make(map[string]struct{}, len(defs))
	for _, def := range defs {
		if def.Source != SourceBuiltin {
			t.Fatalf("builtin %q has unexpected source %q", def.ID, def.Source)
		}
		if def.Status != StatusEnabled {
			t.Fatalf("builtin %q expected enabled status, got %q", def.ID, def.Status)
		}
		if err := ValidateDefinition(def); err != nil {
			t.Fatalf("builtin %q failed validation: %v", def.ID, err)
		}
		if _, exists := seen[def.ID]; exists {
			t.Fatalf("duplicate builtin id %q", def.ID)
		}
		seen[def.ID] = struct{}{}
	}
}

func TestBuiltins_PromptInjectionRuleProtectsAgainstSelfMatches(t *testing.T) {
	def, ok := builtinByID("prompt_injection")
	if !ok {
		t.Fatal("expected prompt_injection builtin to exist")
	}
	if def.Engine != EngineRule {
		t.Fatalf("expected prompt_injection engine=%q, got %q", EngineRule, def.Engine)
	}

	excludes := make(map[string]struct{}, len(def.Scope.ExcludeGlobs))
	for _, g := range def.Scope.ExcludeGlobs {
		excludes[g] = struct{}{}
	}

	required := []string{
		"**/checks/builtin.go",
		"**/checks/templates.go",
		"**/docs/checks/**",
		"**/README.md",
	}
	for _, glob := range required {
		if _, ok := excludes[glob]; !ok {
			t.Fatalf("prompt_injection scope must exclude %q to avoid self-matches", glob)
		}
	}

	if len(def.Rule.Detectors) < 3 {
		t.Fatalf("expected prompt_injection to have at least 3 detectors, got %d", len(def.Rule.Detectors))
	}
}

func TestBuiltins_RuleDetectorsAreBoundedAndUniquePerCheck(t *testing.T) {
	defs := Builtins()
	for _, def := range defs {
		if def.Engine != EngineRule {
			continue
		}

		if len(def.Scope.IncludeGlobs) == 0 {
			t.Fatalf("rule builtin %q must define include globs", def.ID)
		}
		if len(def.Rule.Detectors) == 0 {
			t.Fatalf("rule builtin %q must define at least one detector", def.ID)
		}

		seenDetectorIDs := make(map[string]struct{}, len(def.Rule.Detectors))
		for _, detector := range def.Rule.Detectors {
			detectorID := strings.TrimSpace(detector.ID)
			if detectorID == "" {
				t.Fatalf("rule builtin %q has detector with empty id", def.ID)
			}
			if _, exists := seenDetectorIDs[detectorID]; exists {
				t.Fatalf("rule builtin %q has duplicate detector id %q", def.ID, detectorID)
			}
			seenDetectorIDs[detectorID] = struct{}{}

			if strings.TrimSpace(detector.Pattern) == "" {
				t.Fatalf("rule builtin %q detector %q has empty pattern", def.ID, detectorID)
			}
			if detector.MaxMatches <= 0 {
				t.Fatalf("rule builtin %q detector %q must cap matches (>0), got %d", def.ID, detectorID, detector.MaxMatches)
			}
		}
	}
}

func builtinByID(id string) (Definition, bool) {
	for _, def := range Builtins() {
		if def.ID == id {
			return def, true
		}
	}
	return Definition{}, false
}
