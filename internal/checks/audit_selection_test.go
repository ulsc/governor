package checks

import (
	"testing"
)

func TestCountChecksByEngine(t *testing.T) {
	ai, rule := CountChecksByEngine([]Definition{
		{
			APIVersion:   APIVersion,
			ID:           "ai-check",
			Status:       StatusEnabled,
			Source:       SourceCustom,
			Instructions: "instruction text",
			Engine:       EngineAI,
		},
		{
			APIVersion: APIVersion,
			ID:         "rule-check",
			Status:     StatusEnabled,
			Source:     SourceCustom,
			Engine:     EngineRule,
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{ID: "d1", Kind: RuleDetectorContains, Pattern: "x"},
				},
			},
		},
	})
	if ai != 1 || rule != 1 {
		t.Fatalf("unexpected engine counts ai=%d rule=%d", ai, rule)
	}
}

func TestSelectionRequiresAI(t *testing.T) {
	if SelectionRequiresAI([]Definition{
		{
			APIVersion: APIVersion,
			ID:         "rule-only",
			Status:     StatusEnabled,
			Source:     SourceCustom,
			Engine:     EngineRule,
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{ID: "d1", Kind: RuleDetectorContains, Pattern: "x"},
				},
			},
		},
	}) {
		t.Fatal("expected rule-only selection to not require codex")
	}

	if !SelectionRequiresAI([]Definition{
		{
			APIVersion:   APIVersion,
			ID:           "ai-check",
			Status:       StatusEnabled,
			Source:       SourceCustom,
			Engine:       EngineAI,
			Instructions: "instruction text",
		},
	}) {
		t.Fatal("expected ai selection to require codex")
	}
}
