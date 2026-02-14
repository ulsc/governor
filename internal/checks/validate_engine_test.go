package checks

import (
	"strings"
	"testing"
)

func TestNormalizeDefinition_DefaultsEngineToAI(t *testing.T) {
	def := NormalizeDefinition(Definition{
		APIVersion:   APIVersion,
		ID:           "default-engine",
		Status:       StatusDraft,
		Source:       SourceCustom,
		Instructions: "instruction text",
	})
	if def.Engine != EngineAI {
		t.Fatalf("expected default engine ai, got %s", def.Engine)
	}
}

func TestValidateDefinition_RuleEngineAllowsEmptyInstructions(t *testing.T) {
	err := ValidateDefinition(Definition{
		APIVersion: APIVersion,
		ID:         "rule-check",
		Status:     StatusEnabled,
		Source:     SourceCustom,
		Engine:     EngineRule,
		Rule: Rule{
			Target: RuleTargetFileContent,
			Detectors: []RuleDetector{
				{
					ID:       "prompt-injection",
					Kind:     RuleDetectorContains,
					Pattern:  "ignore previous instructions",
					Title:    "Prompt injection marker",
					Category: "input_validation",
					Severity: "high",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("expected valid rule definition, got %v", err)
	}
}

func TestValidateDefinition_RuleEngineRejectsInvalidRegex(t *testing.T) {
	err := ValidateDefinition(Definition{
		APIVersion: APIVersion,
		ID:         "rule-check",
		Status:     StatusEnabled,
		Source:     SourceCustom,
		Engine:     EngineRule,
		Rule: Rule{
			Target: RuleTargetFileContent,
			Detectors: []RuleDetector{
				{
					ID:      "bad-regex",
					Kind:    RuleDetectorRegex,
					Pattern: "(",
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected invalid regex error")
	}
	if !strings.Contains(err.Error(), "must compile as regex") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDefinition_AIEngineRequiresInstructions(t *testing.T) {
	err := ValidateDefinition(Definition{
		APIVersion: APIVersion,
		ID:         "ai-check",
		Status:     StatusEnabled,
		Source:     SourceCustom,
		Engine:     EngineAI,
	})
	if err == nil {
		t.Fatal("expected ai instructions validation error")
	}
	if !strings.Contains(err.Error(), "instructions is required for engine=ai") {
		t.Fatalf("unexpected error: %v", err)
	}
}
