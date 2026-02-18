package suppress

import "time"

// Rule represents a centralized suppression rule from .governor/suppressions.yaml.
type Rule struct {
	ID       string `yaml:"id,omitempty" json:"id,omitempty"`
	Check    string `yaml:"check,omitempty"`
	Title    string `yaml:"title,omitempty"`
	Category string `yaml:"category,omitempty"`
	Files    string `yaml:"files,omitempty"`
	Severity string `yaml:"severity,omitempty"`

	Reason  string `yaml:"reason"`
	Author  string `yaml:"author,omitempty"`
	Expires string `yaml:"expires,omitempty"`
}

// IsExpired returns true if the rule has an expiration date that has passed.
func (r Rule) IsExpired(now time.Time) bool {
	if r.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", r.Expires)
	if err != nil {
		return false
	}
	return now.After(t)
}

// HasInvalidExpiry returns true when the expires field is set but not parseable.
func (r Rule) HasInvalidExpiry() bool {
	if r.Expires == "" {
		return false
	}
	_, err := time.Parse("2006-01-02", r.Expires)
	return err != nil
}

// InlineSuppression represents a governor:suppress annotation found in source.
type InlineSuppression struct {
	CheckID string
	Reason  string
	File    string
	Line    int
}

// suppressionsFile is the top-level YAML structure for .governor/suppressions.yaml.
type suppressionsFile struct {
	Suppressions []Rule `yaml:"suppressions"`
}
