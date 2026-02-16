package intake

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseIgnorePatterns_CommentsAndBlanks(t *testing.T) {
	lines := []string{
		"# this is a comment",
		"",
		"  # indented comment",
		"  ",
		"*.log",
	}
	rules := ParseIgnorePatterns(lines)
	if len(rules.patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(rules.patterns))
	}
	if !rules.ShouldIgnore("app.log", false) {
		t.Error("expected *.log to match app.log")
	}
}

func TestParseIgnorePatterns_GlobPattern(t *testing.T) {
	rules := ParseIgnorePatterns([]string{"*.generated.go"})
	tests := []struct {
		path   string
		expect bool
	}{
		{"model.generated.go", true},
		{"pkg/model.generated.go", true},
		{"model.go", false},
		{"generated.go.bak", false},
	}
	for _, tt := range tests {
		got := rules.ShouldIgnore(tt.path, false)
		if got != tt.expect {
			t.Errorf("ShouldIgnore(%q) = %v, want %v", tt.path, got, tt.expect)
		}
	}
}

func TestParseIgnorePatterns_DirectoryOnly(t *testing.T) {
	rules := ParseIgnorePatterns([]string{"fixtures/"})

	if !rules.ShouldIgnore("fixtures", true) {
		t.Error("expected fixtures/ to match dir 'fixtures'")
	}
	if rules.ShouldIgnore("fixtures", false) {
		t.Error("expected fixtures/ to NOT match file 'fixtures'")
	}
	if !rules.ShouldIgnore("pkg/fixtures", true) {
		t.Error("expected fixtures/ to match nested dir 'pkg/fixtures'")
	}
}

func TestParseIgnorePatterns_DoubleStarGlob(t *testing.T) {
	rules := ParseIgnorePatterns([]string{"**/test_data/**"})
	tests := []struct {
		path   string
		expect bool
	}{
		{"test_data/file.txt", true},
		{"pkg/test_data/nested/file.go", true},
		{"src/test_data/data.json", true},
		{"src/other/file.go", false},
	}
	for _, tt := range tests {
		got := rules.ShouldIgnore(tt.path, false)
		if got != tt.expect {
			t.Errorf("ShouldIgnore(%q) = %v, want %v", tt.path, got, tt.expect)
		}
	}
}

func TestParseIgnorePatterns_Negation(t *testing.T) {
	rules := ParseIgnorePatterns([]string{
		"*.go",
		"!keep.go",
	})
	if !rules.ShouldIgnore("main.go", false) {
		t.Error("expected *.go to match main.go")
	}
	if rules.ShouldIgnore("keep.go", false) {
		t.Error("expected !keep.go to re-include keep.go")
	}
}

func TestShouldIgnore_NilRules(t *testing.T) {
	var rules *IgnoreRules
	if rules.ShouldIgnore("anything.go", false) {
		t.Error("nil rules should return false")
	}
}

func TestLoadIgnoreFile_MissingFile(t *testing.T) {
	rules, err := LoadIgnoreFile(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules != nil {
		t.Error("expected nil rules for missing file")
	}
}

func TestLoadIgnoreFile_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".governorignore")
	content := "# comment\n*.log\nfixtures/\n!important.log\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules == nil {
		t.Fatal("expected non-nil rules")
	}
	if len(rules.patterns) != 3 {
		t.Fatalf("expected 3 patterns, got %d", len(rules.patterns))
	}

	if !rules.ShouldIgnore("debug.log", false) {
		t.Error("expected *.log to match debug.log")
	}
	if rules.ShouldIgnore("important.log", false) {
		t.Error("expected !important.log to re-include")
	}
	if !rules.ShouldIgnore("fixtures", true) {
		t.Error("expected fixtures/ to match dir")
	}
}

func TestParseIgnorePatterns_PathWithSlash(t *testing.T) {
	rules := ParseIgnorePatterns([]string{"generated/output"})

	if !rules.ShouldIgnore("generated/output", false) {
		t.Error("expected exact path match")
	}
	if rules.ShouldIgnore("other/output", false) {
		t.Error("should not match different prefix")
	}
}
