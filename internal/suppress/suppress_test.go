package suppress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"governor/internal/model"
)

func TestLoad_Missing(t *testing.T) {
	rules, err := Load("/nonexistent/path/suppressions.yaml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected empty rules, got %d", len(rules))
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")
	content := `suppressions:
  - check: hardcoded_credentials
    files: "tests/**"
    reason: "Test fixtures"
    author: "jane@example.com"
    expires: "2099-01-01"
  - title: "Hardcoded API key*"
    reason: "Placeholder values"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Check != "hardcoded_credentials" {
		t.Errorf("expected check=hardcoded_credentials, got %q", rules[0].Check)
	}
	if rules[1].Title != "Hardcoded API key*" {
		t.Errorf("expected title glob, got %q", rules[1].Title)
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rules))
	}
}

func TestRule_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		expires string
		now     time.Time
		want    bool
	}{
		{"no expiry", "", time.Now(), false},
		{"future", "2099-01-01", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"past", "2020-01-01", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"invalid format", "not-a-date", time.Now(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Rule{Expires: tc.expires}
			got := r.IsExpired(tc.now)
			if got != tc.want {
				t.Errorf("IsExpired(%q, %v) = %v, want %v", tc.expires, tc.now, got, tc.want)
			}
		})
	}
}

func TestApply_FileRules(t *testing.T) {
	findings := []model.Finding{
		{Title: "SQL injection", Severity: "high", Category: "appsec", SourceTrack: "appsec", FileRefs: []string{"src/api.go"}},
		{Title: "Hardcoded API key in test", Severity: "medium", Category: "secrets", SourceTrack: "hardcoded_credentials", FileRefs: []string{"tests/fixtures/keys.go"}},
		{Title: "Missing rate limit", Severity: "low", Category: "appsec", SourceTrack: "appsec"},
	}

	rules := []Rule{
		{Check: "hardcoded_credentials", Files: "tests/**", Reason: "test fixtures"},
	}

	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 2 {
		t.Fatalf("expected 2 active findings, got %d", len(active))
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", len(suppressed))
	}
	if suppressed[0].Title != "Hardcoded API key in test" {
		t.Errorf("wrong finding suppressed: %q", suppressed[0].Title)
	}
	if !suppressed[0].Suppressed {
		t.Error("expected Suppressed=true")
	}
	if suppressed[0].SuppressionReason != "test fixtures" {
		t.Errorf("expected reason 'test fixtures', got %q", suppressed[0].SuppressionReason)
	}
	if suppressed[0].SuppressionSource != "file" {
		t.Errorf("expected source 'file', got %q", suppressed[0].SuppressionSource)
	}
}

func TestApply_TitleGlob(t *testing.T) {
	findings := []model.Finding{
		{Title: "Hardcoded API key found", Category: "secrets", SourceTrack: "secrets"},
		{Title: "SQL injection", Category: "appsec", SourceTrack: "appsec"},
	}

	rules := []Rule{
		{Title: "Hardcoded API key*", Reason: "false positive"},
	}

	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed, got %d", len(suppressed))
	}
}

func TestApply_CategoryMatch(t *testing.T) {
	findings := []model.Finding{
		{Title: "Key in config", Category: "secrets", SourceTrack: "secrets", FileRefs: []string{"docs/examples/config.yaml"}},
		{Title: "SQL injection", Category: "appsec", SourceTrack: "appsec"},
	}

	rules := []Rule{
		{Category: "secrets", Files: "docs/examples/**", Reason: "doc examples"},
	}

	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed, got %d", len(suppressed))
	}
}

func TestApply_ExpiredRuleIgnored(t *testing.T) {
	findings := []model.Finding{
		{Title: "Test key", Category: "secrets", SourceTrack: "hardcoded_credentials", FileRefs: []string{"test.go"}},
	}

	rules := []Rule{
		{Check: "hardcoded_credentials", Reason: "expired", Expires: "2020-01-01"},
	}

	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 1 {
		t.Fatalf("expected 1 active (expired rule ignored), got %d", len(active))
	}
	if len(suppressed) != 0 {
		t.Fatalf("expected 0 suppressed, got %d", len(suppressed))
	}
}

func TestApply_InlineSuppression(t *testing.T) {
	findings := []model.Finding{
		{Title: "Hardcoded key", SourceTrack: "hardcoded_credentials", FileRefs: []string{"config.go"}},
		{Title: "SQL injection", SourceTrack: "appsec", FileRefs: []string{"api.go"}},
	}

	inline := map[string][]InlineSuppression{
		"config.go": {
			{CheckID: "hardcoded_credentials", Reason: "test fixture", File: "config.go", Line: 10},
		},
	}

	active, suppressed := Apply(findings, nil, inline)
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed, got %d", len(suppressed))
	}
	if suppressed[0].SuppressionSource != "inline" {
		t.Errorf("expected source 'inline', got %q", suppressed[0].SuppressionSource)
	}
}

func TestApply_EmptyRuleNoMatch(t *testing.T) {
	findings := []model.Finding{
		{Title: "Test", SourceTrack: "check1"},
	}

	rules := []Rule{
		{Reason: "empty rule should not match"},
	}

	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 1 {
		t.Fatalf("expected 1 active (empty rule no match), got %d", len(active))
	}
	if len(suppressed) != 0 {
		t.Fatalf("expected 0 suppressed, got %d", len(suppressed))
	}
}

func TestApply_SeverityMatch(t *testing.T) {
	findings := []model.Finding{
		{Title: "Low issue", Severity: "low", SourceTrack: "check1"},
		{Title: "High issue", Severity: "high", SourceTrack: "check1"},
	}

	rules := []Rule{
		{Severity: "low", Reason: "suppress low findings"},
	}

	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed, got %d", len(suppressed))
	}
	if suppressed[0].Title != "Low issue" {
		t.Errorf("wrong finding suppressed: %q", suppressed[0].Title)
	}
}

func TestApply_WildcardCheckRejected(t *testing.T) {
	findings := []model.Finding{
		{Title: "SQL injection", SourceTrack: "appsec"},
		{Title: "Hardcoded key", SourceTrack: "hardcoded_credentials"},
	}

	rules := []Rule{
		{Check: "*", Reason: "blanket suppress"},
	}
	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 2 {
		t.Fatalf("expected 2 active (wildcard rejected), got %d", len(active))
	}
	if len(suppressed) != 0 {
		t.Fatalf("expected 0 suppressed, got %d", len(suppressed))
	}
}

func TestApply_WildcardTitleRejected(t *testing.T) {
	findings := []model.Finding{
		{Title: "SQL injection", SourceTrack: "appsec"},
	}

	rules := []Rule{
		{Title: "*", Reason: "blanket suppress"},
	}
	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 1 {
		t.Fatalf("expected 1 active (wildcard title rejected), got %d", len(active))
	}
	if len(suppressed) != 0 {
		t.Fatalf("expected 0 suppressed, got %d", len(suppressed))
	}
}

func TestApply_InlineWildcardRejected(t *testing.T) {
	findings := []model.Finding{
		{Title: "Key found", SourceTrack: "hardcoded_credentials", FileRefs: []string{"config.go"}},
	}

	inline := map[string][]InlineSuppression{
		"config.go": {
			{CheckID: "*", Reason: "suppress all", File: "config.go", Line: 5},
		},
	}

	active, suppressed := Apply(findings, nil, inline)
	if len(active) != 1 {
		t.Fatalf("expected 1 active (inline wildcard rejected), got %d", len(active))
	}
	if len(suppressed) != 0 {
		t.Fatalf("expected 0 suppressed, got %d", len(suppressed))
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"tests/**", "tests/fixtures/keys.go", true},
		{"tests/**", "src/main.go", false},
		{"*.go", "main.go", true},
		{"*.go", "main.py", false},
		{"Hardcoded API key*", "Hardcoded API key found", true},
		{"Hardcoded API key*", "SQL injection", false},
		{"docs/examples/**", "docs/examples/config.yaml", true},
		{"src/**/*.go", "src/api/users.go", true},
	}
	for _, tc := range tests {
		t.Run(tc.pattern+"_"+tc.value, func(t *testing.T) {
			got := matchGlob(tc.pattern, tc.value)
			if got != tc.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
			}
		})
	}
}

func TestLoad_MissingReasonReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")
	content := `suppressions:
  - check: hardcoded_credentials
    files: "tests/**"
    reason: "Test fixtures"
  - title: "Hardcoded API key*"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for rule without reason")
	}
	if !strings.Contains(err.Error(), "reason is required") {
		t.Fatalf("expected 'reason is required' error, got: %v", err)
	}
}

func TestEnsureRuleIDs_FillsAndUniquifies(t *testing.T) {
	rules := []Rule{
		{Check: "check-a", Reason: "one"},
		{Check: "check-a", Reason: "one"},
		{ID: "custom id", Check: "check-b", Reason: "two"},
	}
	withIDs := EnsureRuleIDs(rules)
	if withIDs[0].ID == "" || withIDs[1].ID == "" || withIDs[2].ID == "" {
		t.Fatal("expected all rules to have IDs")
	}
	if withIDs[0].ID == withIDs[1].ID {
		t.Fatal("expected duplicate rule IDs to be disambiguated")
	}
	if withIDs[2].ID != "custom-id" {
		t.Fatalf("expected normalized custom id, got %q", withIDs[2].ID)
	}
}

func TestRemoveMatching_ByIDPattern(t *testing.T) {
	rules := EnsureRuleIDs([]Rule{
		{ID: "sup-auth", Check: "auth", Reason: "one"},
		{ID: "sup-secrets", Check: "secrets", Reason: "two"},
	})
	kept, removed := RemoveMatching(rules, MatchOptions{IDPattern: "sup-auth"})
	if len(removed) != 1 || removed[0].ID != "sup-auth" {
		t.Fatalf("unexpected removed rules: %+v", removed)
	}
	if len(kept) != 1 || kept[0].ID != "sup-secrets" {
		t.Fatalf("unexpected kept rules: %+v", kept)
	}
}

func TestRuleHasInvalidExpiry(t *testing.T) {
	if !(Rule{Expires: "invalid-date"}).HasInvalidExpiry() {
		t.Fatal("expected invalid expiry to be detected")
	}
	if (Rule{Expires: "2099-01-01"}).HasInvalidExpiry() {
		t.Fatal("did not expect valid date to be marked invalid")
	}
}

func TestLoad_AllReasonsPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")
	content := `suppressions:
  - check: hardcoded_credentials
    files: "tests/**"
    reason: "Test fixtures"
  - title: "Hardcoded API key*"
    reason: "False positive"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}
