package checks

import (
	"strings"
	"testing"
)

// --- Validation Edge Cases ---

func TestValidateDefinition_MaliciousID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"empty", "", true},
		{"spaces", "  ", true},
		{"path traversal", "../etc/passwd", true},
		{"slash", "a/b", true},
		{"backslash", "a\\b", true},
		{"too long", strings.Repeat("a", 65), true},
		{"starts with dash", "-test", true},
		{"starts with underscore", "_test", true},
		{"uppercase", "TEST", true}, // normalized to lowercase first, then validated
		{"valid simple", "test", false},
		{"valid with dash", "my-check", false},
		{"valid with underscore", "my_check", false},
		{"valid with numbers", "check123", false},
		{"min length", "ab", false},
		{"null bytes", "test\x00evil", true},
		{"special chars", "test!@#", true},
		{"unicode", "test\u00e9", true},
		{"dot", "test.check", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def := Definition{
				APIVersion:   APIVersion,
				ID:           tt.id,
				Status:       StatusEnabled,
				Source:       SourceCustom,
				Engine:       EngineAI,
				Instructions: "test instructions for the check",
			}
			err := ValidateDefinition(def)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDefinition with ID=%q: error=%v, wantErr=%v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDefinition_MaliciousInstructions(t *testing.T) {
	// Instructions are passed to AI - verify they're not validated for content
	// (they shouldn't be, but let's document the behavior)
	hugeInstructions := strings.Repeat("A", 100*1024) // 100KB
	def := Definition{
		APIVersion:   APIVersion,
		ID:           "huge-check",
		Status:       StatusEnabled,
		Source:       SourceCustom,
		Engine:       EngineAI,
		Instructions: hugeInstructions,
	}
	err := ValidateDefinition(def)
	if err != nil {
		t.Logf("NOTE: large instructions rejected: %v", err)
	}
	// Document: there's no size limit on instructions. A malicious check
	// could have enormous instructions that consume memory.
}

func TestValidateDefinition_InvalidStatus(t *testing.T) {
	def := Definition{
		APIVersion:   APIVersion,
		ID:           "test-check",
		Status:       "malicious",
		Source:       SourceCustom,
		Engine:       EngineAI,
		Instructions: "instructions",
	}
	if err := ValidateDefinition(def); err == nil {
		t.Error("expected error for invalid status")
	}
}

func TestValidateDefinition_InvalidSource(t *testing.T) {
	def := Definition{
		APIVersion:   APIVersion,
		ID:           "test-check",
		Status:       StatusEnabled,
		Source:       "evil",
		Engine:       EngineAI,
		Instructions: "instructions",
	}
	if err := ValidateDefinition(def); err == nil {
		t.Error("expected error for invalid source")
	}
}

func TestValidateDefinition_InvalidEngine(t *testing.T) {
	def := Definition{
		APIVersion:   APIVersion,
		ID:           "test-check",
		Status:       StatusEnabled,
		Source:       SourceCustom,
		Engine:       "evil-engine",
		Instructions: "instructions",
	}
	if err := ValidateDefinition(def); err == nil {
		t.Error("expected error for invalid engine")
	}
}

func TestValidateDefinition_InvalidSeverityHint(t *testing.T) {
	def := Definition{
		APIVersion:   APIVersion,
		ID:           "test-check",
		Status:       StatusEnabled,
		Source:       SourceCustom,
		Engine:       EngineAI,
		Instructions: "instructions",
		SeverityHint: "extreme",
	}
	if err := ValidateDefinition(def); err == nil {
		t.Error("expected error for invalid severity hint")
	}
}

func TestValidateDefinition_InvalidConfidence(t *testing.T) {
	tests := []struct {
		name       string
		confidence float64
		wantErr    bool
	}{
		{"negative", -0.1, true},
		{"over one", 1.1, true},
		{"zero", 0, false},
		{"one", 1, false},
		{"half", 0.5, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def := Definition{
				APIVersion:     APIVersion,
				ID:             "test-check",
				Status:         StatusEnabled,
				Source:         SourceCustom,
				Engine:         EngineAI,
				Instructions:   "instructions",
				ConfidenceHint: tt.confidence,
			}
			err := ValidateDefinition(def)
			if (err != nil) != tt.wantErr {
				t.Errorf("confidence=%f: error=%v, wantErr=%v", tt.confidence, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDefinition_RuleEngineRequirements(t *testing.T) {
	// Rule engine without target
	def := Definition{
		APIVersion: APIVersion,
		ID:         "rule-check",
		Status:     StatusEnabled,
		Source:     SourceCustom,
		Engine:     EngineRule,
		Rule: Rule{
			Detectors: []RuleDetector{
				{ID: "d1", Kind: RuleDetectorContains, Pattern: "test"},
			},
		},
	}
	if err := ValidateDefinition(def); err == nil {
		t.Error("expected error for rule without target")
	}

	// Rule engine without detectors
	def2 := Definition{
		APIVersion: APIVersion,
		ID:         "rule-check2",
		Status:     StatusEnabled,
		Source:     SourceCustom,
		Engine:     EngineRule,
		Rule: Rule{
			Target: RuleTargetFileContent,
		},
	}
	if err := ValidateDefinition(def2); err == nil {
		t.Error("expected error for rule without detectors")
	}
}

func TestValidateDefinition_RuleDetectorRegexCompile(t *testing.T) {
	def := Definition{
		APIVersion: APIVersion,
		ID:         "regex-check",
		Status:     StatusEnabled,
		Source:     SourceCustom,
		Engine:     EngineRule,
		Rule: Rule{
			Target: RuleTargetFileContent,
			Detectors: []RuleDetector{
				{
					ID:      "bad-regex",
					Kind:    RuleDetectorRegex,
					Pattern: "[invalid-regex",
				},
			},
		},
	}
	if err := ValidateDefinition(def); err == nil {
		t.Error("expected error for invalid regex in detector")
	}
}

func TestValidateDefinition_WrongAPIVersion(t *testing.T) {
	def := Definition{
		APIVersion:   "governor/v99",
		ID:           "test-check",
		Status:       StatusEnabled,
		Source:       SourceCustom,
		Engine:       EngineAI,
		Instructions: "instructions",
	}
	if err := ValidateDefinition(def); err == nil {
		t.Error("expected error for wrong API version")
	}
}

// --- Normalization Tests ---

func TestNormalizeDefinition_Defaults(t *testing.T) {
	def := Definition{
		ID: "TEST-CHECK",
	}
	result := NormalizeDefinition(def)

	if result.ID != "test-check" {
		t.Errorf("expected lowercase ID, got %q", result.ID)
	}
	if result.APIVersion != APIVersion {
		t.Errorf("expected default APIVersion, got %q", result.APIVersion)
	}
	if result.Status != StatusDraft {
		t.Errorf("expected default status=draft, got %q", result.Status)
	}
	if result.Source != SourceCustom {
		t.Errorf("expected default source=custom, got %q", result.Source)
	}
	if result.Engine != EngineAI {
		t.Errorf("expected default engine=ai, got %q", result.Engine)
	}
	if result.Name != "test-check" {
		t.Errorf("expected name=id when empty, got %q", result.Name)
	}
}

func TestNormalizeDefinition_SanitizesGlobs(t *testing.T) {
	def := Definition{
		ID: "test",
		Scope: Scope{
			IncludeGlobs: []string{"  **/*.go  ", "", "  "},
			ExcludeGlobs: []string{"**/vendor/**", "   "},
		},
	}
	result := NormalizeDefinition(def)

	if len(result.Scope.IncludeGlobs) != 1 || result.Scope.IncludeGlobs[0] != "**/*.go" {
		t.Errorf("expected sanitized include globs, got %v", result.Scope.IncludeGlobs)
	}
	if len(result.Scope.ExcludeGlobs) != 1 || result.Scope.ExcludeGlobs[0] != "**/vendor/**" {
		t.Errorf("expected sanitized exclude globs, got %v", result.Scope.ExcludeGlobs)
	}
}

func TestNormalizeDefinition_SortsCategoriesAndDetectors(t *testing.T) {
	def := Definition{
		ID:             "test",
		CategoriesHint: []string{"security", "authentication", "crypto"},
		Engine:         EngineRule,
		Rule: Rule{
			Target: RuleTargetFileContent,
			Detectors: []RuleDetector{
				{ID: "z-detector", Kind: RuleDetectorContains, Pattern: "z"},
				{ID: "a-detector", Kind: RuleDetectorContains, Pattern: "a"},
			},
		},
	}
	result := NormalizeDefinition(def)

	if result.CategoriesHint[0] != "authentication" {
		t.Error("expected categories to be sorted")
	}
	if result.Rule.Detectors[0].ID != "a-detector" {
		t.Error("expected detectors to be sorted by ID")
	}
}

// --- Unique ID Validation ---

func TestValidateUniqueIDs(t *testing.T) {
	defs := []Definition{
		{ID: "check-1"},
		{ID: "check-2"},
		{ID: "check-1"}, // duplicate
	}
	if err := ValidateUniqueIDs(defs); err == nil {
		t.Error("expected error for duplicate IDs")
	}
}

func TestValidateUniqueIDs_NoDuplicates(t *testing.T) {
	defs := []Definition{
		{ID: "check-1"},
		{ID: "check-2"},
		{ID: "check-3"},
	}
	if err := ValidateUniqueIDs(defs); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateUniqueIDs_Empty(t *testing.T) {
	if err := ValidateUniqueIDs(nil); err != nil {
		t.Errorf("unexpected error for nil: %v", err)
	}
}

// --- Parse Status ---

func TestParseStatus_DevilEdgeCases(t *testing.T) {
	tests := []struct {
		input   string
		want    Status
		wantErr bool
	}{
		{"draft", StatusDraft, false},
		{"enabled", StatusEnabled, false},
		{"disabled", StatusDisabled, false},
		{"DRAFT", StatusDraft, false},
		{"  enabled  ", StatusEnabled, false},
		{"invalid", "", true},
		{"", StatusDraft, false}, // empty defaults to draft
		{"Draft", StatusDraft, false},
		{"ENABLED", StatusEnabled, false},
		{"  DISABLED  ", StatusDisabled, false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseStatus(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseStatus(%q) error=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseStatus(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
