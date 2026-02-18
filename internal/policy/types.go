package policy

import "time"

const APIVersion = "governor/policy/v1"

type Policy struct {
	APIVersion string   `yaml:"api_version" json:"api_version"`
	Defaults   Gate     `yaml:"defaults" json:"defaults"`
	Rules      []Rule   `yaml:"rules,omitempty" json:"rules,omitempty"`
	Waivers    []Waiver `yaml:"waivers,omitempty" json:"waivers,omitempty"`
}

type Gate struct {
	FailOnSeverity      string   `yaml:"fail_on_severity,omitempty" json:"fail_on_severity,omitempty"`
	MaxSuppressionRatio *float64 `yaml:"max_suppression_ratio,omitempty" json:"max_suppression_ratio,omitempty"`
	RequireChecks       []string `yaml:"require_checks,omitempty" json:"require_checks,omitempty"`
	ForbidChecks        []string `yaml:"forbid_checks,omitempty" json:"forbid_checks,omitempty"`
	MaxNewFindings      *int     `yaml:"max_new_findings,omitempty" json:"max_new_findings,omitempty"`
}

type Rule struct {
	Name    string    `yaml:"name,omitempty" json:"name,omitempty"`
	When    MatchSpec `yaml:"when,omitempty" json:"when,omitempty"`
	Enforce Gate      `yaml:"enforce" json:"enforce"`
}

type MatchSpec struct {
	Paths      []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Categories []string `yaml:"categories,omitempty" json:"categories,omitempty"`
	Checks     []string `yaml:"checks,omitempty" json:"checks,omitempty"`
}

type Waiver struct {
	ID       string    `yaml:"id" json:"id"`
	Reason   string    `yaml:"reason" json:"reason"`
	Expires  string    `yaml:"expires,omitempty" json:"expires,omitempty"`
	Approver string    `yaml:"approver,omitempty" json:"approver,omitempty"`
	Match    MatchSpec `yaml:"match,omitempty" json:"match,omitempty"`
}

func (w Waiver) IsExpired(now time.Time) bool {
	if w.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", w.Expires)
	if err != nil {
		return false
	}
	return now.After(t)
}
