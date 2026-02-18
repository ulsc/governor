package suppress

import (
	"crypto/sha256"
	"encoding/hex"
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
	return EnsureRuleIDs(sf.Suppressions), nil
}

// Save writes suppression rules to disk using the canonical YAML structure.
func Save(path string, rules []Rule) error {
	rules = EnsureRuleIDs(rules)
	sf := suppressionsFile{Suppressions: rules}
	data, err := yaml.Marshal(sf)
	if err != nil {
		return fmt.Errorf("marshal suppressions: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create suppressions dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write suppressions: %w", err)
	}
	return nil
}

// EnsureRuleIDs fills missing rule IDs and guarantees uniqueness.
func EnsureRuleIDs(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)

	used := make(map[string]struct{}, len(out))
	for i := range out {
		out[i].ID = normalizeRuleID(out[i].ID)
		if out[i].ID == "" {
			out[i].ID = generateRuleID(out[i])
		}
		base := out[i].ID
		for n := 2; ; n++ {
			if _, exists := used[out[i].ID]; !exists {
				used[out[i].ID] = struct{}{}
				break
			}
			out[i].ID = fmt.Sprintf("%s-%d", base, n)
		}
	}
	return out
}

type MatchOptions struct {
	IDPattern string
	Check     string
	Title     string
	Category  string
	Files     string
	Severity  string
}

// RemoveMatching partitions rules into kept and removed groups.
func RemoveMatching(rules []Rule, opts MatchOptions) (kept []Rule, removed []Rule) {
	rules = EnsureRuleIDs(rules)
	kept = make([]Rule, 0, len(rules))
	removed = make([]Rule, 0)
	for _, rule := range rules {
		if RuleMatches(rule, opts) {
			removed = append(removed, rule)
			continue
		}
		kept = append(kept, rule)
	}
	return kept, removed
}

// RuleMatches returns true if a rule matches all specified options.
func RuleMatches(rule Rule, opts MatchOptions) bool {
	if strings.TrimSpace(opts.IDPattern) != "" && !matchGlob(opts.IDPattern, rule.ID) {
		return false
	}
	if strings.TrimSpace(opts.Check) != "" && !matchGlob(opts.Check, rule.Check) {
		return false
	}
	if strings.TrimSpace(opts.Title) != "" && !matchGlob(opts.Title, rule.Title) {
		return false
	}
	if strings.TrimSpace(opts.Category) != "" && !strings.EqualFold(strings.TrimSpace(opts.Category), strings.TrimSpace(rule.Category)) {
		return false
	}
	if strings.TrimSpace(opts.Files) != "" && !matchGlob(opts.Files, rule.Files) {
		return false
	}
	if strings.TrimSpace(opts.Severity) != "" && !strings.EqualFold(strings.TrimSpace(opts.Severity), strings.TrimSpace(rule.Severity)) {
		return false
	}
	if strings.TrimSpace(opts.IDPattern) == "" &&
		strings.TrimSpace(opts.Check) == "" &&
		strings.TrimSpace(opts.Title) == "" &&
		strings.TrimSpace(opts.Category) == "" &&
		strings.TrimSpace(opts.Files) == "" &&
		strings.TrimSpace(opts.Severity) == "" {
		return false
	}
	return true
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

func normalizeRuleID(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	for _, ch := range raw {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '-' || ch == '_':
			b.WriteRune(ch)
		case ch == ' ':
			b.WriteRune('-')
		}
	}
	id := strings.Trim(b.String(), "-_")
	return id
}

func generateRuleID(rule Rule) string {
	parts := []string{
		strings.TrimSpace(rule.Check),
		strings.TrimSpace(rule.Title),
		strings.TrimSpace(rule.Category),
		strings.TrimSpace(rule.Files),
		strings.TrimSpace(rule.Severity),
		strings.TrimSpace(rule.Reason),
		strings.TrimSpace(rule.Author),
		strings.TrimSpace(rule.Expires),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "sup-" + hex.EncodeToString(sum[:6])
}
