package checks

import "time"

const APIVersion = "governor/v1"

type Status string

const (
	StatusDraft    Status = "draft"
	StatusEnabled  Status = "enabled"
	StatusDisabled Status = "disabled"
)

type Source string

const (
	SourceBuiltin Source = "builtin"
	SourceCustom  Source = "custom"
)

type Engine string

const (
	EngineAI   Engine = "ai"
	EngineRule Engine = "rule"
)

type RuleTarget string

const (
	RuleTargetFileContent RuleTarget = "file_content"
)

type RuleDetectorKind string

const (
	RuleDetectorContains RuleDetectorKind = "contains"
	RuleDetectorRegex    RuleDetectorKind = "regex"
)

type RuleDetector struct {
	ID            string           `yaml:"id" json:"id"`
	Kind          RuleDetectorKind `yaml:"kind" json:"kind"`
	Pattern       string           `yaml:"pattern" json:"pattern"`
	CaseSensitive bool             `yaml:"case_sensitive,omitempty" json:"case_sensitive,omitempty"`

	Title       string  `yaml:"title,omitempty" json:"title,omitempty"`
	Category    string  `yaml:"category,omitempty" json:"category,omitempty"`
	Severity    string  `yaml:"severity,omitempty" json:"severity,omitempty"`
	Confidence  float64 `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	Remediation string  `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	MaxMatches  int     `yaml:"max_matches,omitempty" json:"max_matches,omitempty"`
}

type Rule struct {
	Target    RuleTarget     `yaml:"target" json:"target"`
	Detectors []RuleDetector `yaml:"detectors" json:"detectors"`
	Notes     []string       `yaml:"notes,omitempty" json:"notes,omitempty"`
}

type Scope struct {
	IncludeGlobs []string `yaml:"include_globs,omitempty" json:"include_globs,omitempty"`
	ExcludeGlobs []string `yaml:"exclude_globs,omitempty" json:"exclude_globs,omitempty"`
}

type Origin struct {
	Method string   `yaml:"method,omitempty" json:"method,omitempty"`
	Inputs []string `yaml:"inputs,omitempty" json:"inputs,omitempty"`
}

// DefaultTestFileExcludeGlobs returns the canonical set of glob patterns used
// to exclude test files and fixtures from security scanning.
func DefaultTestFileExcludeGlobs() []string {
	return []string{
		"**/*_test.go",
		"**/test/**",
		"**/*.test.*",
		"**/fixtures/**",
		"**/__tests__/**",
		"**/*.spec.*",
		"**/testdata/**",
	}
}

// ApplyTestFileExclusions returns a copy of scope with the default test file
// exclusion globs appended, deduplicating any that already exist.
func ApplyTestFileExclusions(scope Scope) Scope {
	existing := make(map[string]struct{}, len(scope.ExcludeGlobs))
	for _, g := range scope.ExcludeGlobs {
		existing[g] = struct{}{}
	}
	out := make([]string, len(scope.ExcludeGlobs))
	copy(out, scope.ExcludeGlobs)
	for _, g := range DefaultTestFileExcludeGlobs() {
		if _, ok := existing[g]; !ok {
			out = append(out, g)
		}
	}
	return Scope{
		IncludeGlobs: scope.IncludeGlobs,
		ExcludeGlobs: out,
	}
}

type Definition struct {
	APIVersion     string    `yaml:"api_version" json:"api_version"`
	ID             string    `yaml:"id" json:"id"`
	Name           string    `yaml:"name,omitempty" json:"name,omitempty"`
	Status         Status    `yaml:"status" json:"status"`
	Source         Source    `yaml:"source" json:"source"`
	Engine         Engine    `yaml:"engine,omitempty" json:"engine,omitempty"`
	Description    string    `yaml:"description,omitempty" json:"description,omitempty"`
	Instructions   string    `yaml:"instructions" json:"instructions"`
	Rule           Rule      `yaml:"rule,omitempty" json:"rule,omitempty"`
	Scope          Scope     `yaml:"scope,omitempty" json:"scope,omitempty"`
	CategoriesHint []string  `yaml:"categories_hint,omitempty" json:"categories_hint,omitempty"`
	SeverityHint   string    `yaml:"severity_hint,omitempty" json:"severity_hint,omitempty"`
	ConfidenceHint float64   `yaml:"confidence_hint,omitempty" json:"confidence_hint,omitempty"`
	CWE            string    `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	OWASP          string    `yaml:"owasp,omitempty" json:"owasp,omitempty"`
	CreatedAt      time.Time `yaml:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt      time.Time `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
	Origin         Origin    `yaml:"origin,omitempty" json:"origin,omitempty"`
}
