package suppress

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"governor/internal/model"

	"gopkg.in/yaml.v3"
)

// DefaultPath returns the conventional path for the suppressions file.
func DefaultPath(root string) string {
	return filepath.Join(root, ".governor", "suppressions.yaml")
}

// Load reads and parses suppression rules from a YAML file.
// Returns nil rules and nil error if the file does not exist.
func Load(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, nil
	}
	var sf suppressionsFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, err
	}
	for i, rule := range sf.Suppressions {
		if strings.TrimSpace(rule.Reason) == "" {
			return nil, fmt.Errorf("suppression rule %d: reason is required", i+1)
		}
	}
	return sf.Suppressions, nil
}

// Apply partitions findings into active and suppressed based on rules and inline annotations.
// Expired rules are ignored (finding remains active).
func Apply(findings []model.Finding, rules []Rule, inline map[string][]InlineSuppression) (active, suppressed []model.Finding) {
	now := time.Now().UTC()
	active = make([]model.Finding, 0, len(findings))
	suppressed = make([]model.Finding, 0)

	for _, f := range findings {
		if reason, source := matchRules(f, rules, now); reason != "" {
			f.Suppressed = true
			f.SuppressionReason = reason
			f.SuppressionSource = source
			suppressed = append(suppressed, f)
			continue
		}
		if reason := matchInline(f, inline); reason != "" {
			f.Suppressed = true
			f.SuppressionReason = reason
			f.SuppressionSource = "inline"
			suppressed = append(suppressed, f)
			continue
		}
		active = append(active, f)
	}
	return
}

// matchRules checks if any non-expired rule matches the finding.
func matchRules(f model.Finding, rules []Rule, now time.Time) (reason, source string) {
	for _, r := range rules {
		if r.IsExpired(now) {
			continue
		}
		if !ruleMatches(f, r) {
			continue
		}
		return r.Reason, "file"
	}
	return "", ""
}

// ruleMatches returns true if ALL specified fields in the rule match the finding.
func ruleMatches(f model.Finding, r Rule) bool {
	// Reject standalone wildcard check or title — too broad.
	if r.Check == "*" || r.Title == "*" {
		return false
	}
	if r.Check != "" && !matchGlob(r.Check, f.SourceTrack) {
		return false
	}
	if r.Title != "" && !matchGlob(r.Title, f.Title) {
		return false
	}
	if r.Category != "" && !strings.EqualFold(r.Category, f.Category) {
		return false
	}
	if r.Severity != "" && !strings.EqualFold(r.Severity, f.Severity) {
		return false
	}
	if r.Files != "" {
		if !matchAnyFileRef(r.Files, f.FileRefs) {
			return false
		}
	}
	// A rule with no matching fields (all empty) should not match anything.
	if r.Check == "" && r.Title == "" && r.Category == "" && r.Severity == "" && r.Files == "" {
		return false
	}
	return true
}

// matchInline checks if any inline suppression applies to the finding's files.
func matchInline(f model.Finding, inline map[string][]InlineSuppression) string {
	if len(inline) == 0 {
		return ""
	}
	for _, ref := range f.FileRefs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		suppressions, ok := inline[ref]
		if !ok {
			continue
		}
		for _, s := range suppressions {
			if s.CheckID == "*" {
				continue // wildcard rejected
			}
			if matchGlob(s.CheckID, f.SourceTrack) {
				reason := "inline suppression"
				if s.Reason != "" {
					reason = s.Reason
				}
				return reason
			}
		}
	}
	return ""
}

// matchAnyFileRef returns true if the glob pattern matches any of the file refs.
func matchAnyFileRef(pattern string, refs []string) bool {
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if matchGlob(pattern, ref) {
			return true
		}
	}
	return false
}

// matchGlob performs case-insensitive glob matching using filepath.Match semantics,
// with an extension: ** matches any path segment.
func matchGlob(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))

	// Handle ** by trying all possible subpath matches.
	if strings.Contains(pattern, "**") {
		return matchDoublestar(pattern, value)
	}

	matched, _ := filepath.Match(pattern, value)
	return matched
}

// matchDoublestar handles ** glob patterns.
func matchDoublestar(pattern, value string) bool {
	// Split pattern on **
	parts := strings.SplitN(pattern, "**", 2)
	if len(parts) != 2 {
		matched, _ := filepath.Match(pattern, value)
		return matched
	}
	prefix := parts[0]
	suffix := strings.TrimPrefix(parts[1], "/")
	suffix = strings.TrimPrefix(suffix, string(filepath.Separator))

	// prefix must match the start of value
	if prefix != "" {
		if !strings.HasPrefix(value, prefix) {
			return false
		}
		value = value[len(prefix):]
	}

	// If no suffix, match everything after prefix
	if suffix == "" {
		return true
	}

	// Try matching suffix against every possible tail of value
	for i := 0; i <= len(value); i++ {
		tail := value[i:]
		if matched, _ := filepath.Match(suffix, tail); matched {
			return true
		}
		// Also try matching with path components
		if i < len(value) && (value[i] == '/' || value[i] == filepath.Separator) {
			if matched, _ := filepath.Match(suffix, value[i+1:]); matched {
				return true
			}
		}
	}
	return false
}
