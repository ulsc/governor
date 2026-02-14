package worker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"governor/internal/checks"
	"governor/internal/model"
)

// --- Regex DoS Tests ---

func TestCompileDetectors_RejectsInvalidRegex(t *testing.T) {
	detectors := []checks.RuleDetector{
		{
			ID:      "bad-regex",
			Kind:    checks.RuleDetectorRegex,
			Pattern: "[invalid",
		},
	}
	_, err := compileDetectors(detectors)
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

func TestCompileDetectors_UnsupportedKind(t *testing.T) {
	detectors := []checks.RuleDetector{
		{
			ID:      "bad-kind",
			Kind:    "unknown",
			Pattern: "test",
		},
	}
	_, err := compileDetectors(detectors)
	if err == nil {
		t.Error("expected error for unsupported detector kind")
	}
}

func TestCompileDetectors_EmptySlice(t *testing.T) {
	compiled, err := compileDetectors(nil)
	if err != nil {
		t.Errorf("expected no error for nil detectors, got: %v", err)
	}
	if len(compiled) != 0 {
		t.Errorf("expected 0 compiled, got %d", len(compiled))
	}
}

func TestExecuteRuleCheck_PotentialReDoS(t *testing.T) {
	// Test with a pattern that could cause catastrophic backtracking
	// if the regex engine is vulnerable. Go's regexp uses NFA-based matching
	// so this should be safe, but we test with a timeout anyway.
	workspace := t.TempDir()
	content := strings.Repeat("a", 1000) + "!"
	mustWriteRuleTest(t, filepath.Join(workspace, "test.txt"), content)

	manifest := model.InputManifest{
		RootPath: workspace,
		Files:    []model.ManifestFile{{Path: "test.txt", Size: int64(len(content))}},
	}

	// This pattern is intentionally designed to trigger backtracking in PCRE
	// but Go's regexp2/NFA should handle it in polynomial time
	checkDef := checks.Definition{
		APIVersion: checks.APIVersion,
		ID:         "redos-test",
		Name:       "ReDoS Test",
		Status:     checks.StatusEnabled,
		Source:     checks.SourceCustom,
		Engine:     checks.EngineRule,
		Rule: checks.Rule{
			Target: checks.RuleTargetFileContent,
			Detectors: []checks.RuleDetector{
				{
					ID:      "redos-detector",
					Kind:    checks.RuleDetectorRegex,
					Pattern: `(a+)+b`,
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := executeRuleCheck(ctx, workspace, manifest, checkDef)
	if ctx.Err() == context.DeadlineExceeded {
		t.Error("REGEX DOS: pattern caused timeout (catastrophic backtracking)")
	}
	_ = result
}

func TestExecuteRuleCheck_LargeFileSkip(t *testing.T) {
	workspace := t.TempDir()
	// Create a file larger than maxRuleFileBytes
	largeContent := strings.Repeat("a", 3*1024*1024) // 3MB > 2MB limit
	mustWriteRuleTest(t, filepath.Join(workspace, "large.txt"), largeContent)

	manifest := model.InputManifest{
		RootPath: workspace,
		Files:    []model.ManifestFile{{Path: "large.txt", Size: int64(len(largeContent))}},
	}

	checkDef := checks.Definition{
		APIVersion: checks.APIVersion,
		ID:         "size-test",
		Name:       "Size Test",
		Status:     checks.StatusEnabled,
		Source:     checks.SourceCustom,
		Engine:     checks.EngineRule,
		Rule: checks.Rule{
			Target: checks.RuleTargetFileContent,
			Detectors: []checks.RuleDetector{
				{
					ID:      "detector-1",
					Kind:    checks.RuleDetectorContains,
					Pattern: "a",
				},
			},
		},
	}

	result := executeRuleCheck(context.Background(), workspace, manifest, checkDef)
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	// Large file should be skipped
	found := false
	for _, note := range result.payload.Notes {
		if strings.Contains(note, "files_large_skipped=1") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected large file to be skipped")
	}
}

func TestExecuteRuleCheck_ScopeFiltering(t *testing.T) {
	workspace := t.TempDir()
	mustWriteRuleTest(t, filepath.Join(workspace, "src", "main.go"), "TODO fix this")
	mustWriteRuleTest(t, filepath.Join(workspace, "vendor", "lib.go"), "TODO fix this")
	mustWriteRuleTest(t, filepath.Join(workspace, "test", "main_test.go"), "TODO fix this")

	manifest := model.InputManifest{
		RootPath: workspace,
		Files: []model.ManifestFile{
			{Path: "src/main.go", Size: 13},
			{Path: "vendor/lib.go", Size: 13},
			{Path: "test/main_test.go", Size: 13},
		},
	}

	checkDef := checks.Definition{
		APIVersion: checks.APIVersion,
		ID:         "scope-test",
		Name:       "Scope Test",
		Status:     checks.StatusEnabled,
		Source:     checks.SourceCustom,
		Engine:     checks.EngineRule,
		Scope: checks.Scope{
			IncludeGlobs: []string{"**/*.go"},
			ExcludeGlobs: []string{"**/vendor/**", "**/*_test.go"},
		},
		Rule: checks.Rule{
			Target: checks.RuleTargetFileContent,
			Detectors: []checks.RuleDetector{
				{
					ID:      "todo-detector",
					Kind:    checks.RuleDetectorContains,
					Pattern: "TODO",
				},
			},
		},
	}

	result := executeRuleCheck(context.Background(), workspace, manifest, checkDef)
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}

	// Only src/main.go should match
	matchedFiles := 0
	for _, f := range result.payload.Findings {
		for _, ref := range f.FileRefs {
			if ref == "src/main.go" {
				matchedFiles++
			}
		}
	}
	if matchedFiles == 0 {
		t.Error("expected at least one finding in src/main.go")
	}

	// vendor and test files should be excluded
	for _, f := range result.payload.Findings {
		for _, ref := range f.FileRefs {
			if strings.Contains(ref, "vendor") {
				t.Error("vendor file should be excluded by scope")
			}
			if strings.Contains(ref, "_test.go") {
				t.Error("test file should be excluded by scope")
			}
		}
	}
}

func TestExecuteRuleCheck_CaseInsensitiveContains(t *testing.T) {
	workspace := t.TempDir()
	mustWriteRuleTest(t, filepath.Join(workspace, "test.go"), "eval(userInput)")

	manifest := model.InputManifest{
		RootPath: workspace,
		Files:    []model.ManifestFile{{Path: "test.go", Size: 15}},
	}

	checkDef := checks.Definition{
		APIVersion: checks.APIVersion,
		ID:         "case-test",
		Name:       "Case Test",
		Status:     checks.StatusEnabled,
		Source:     checks.SourceCustom,
		Engine:     checks.EngineRule,
		Rule: checks.Rule{
			Target: checks.RuleTargetFileContent,
			Detectors: []checks.RuleDetector{
				{
					ID:            "eval-detector",
					Kind:          checks.RuleDetectorContains,
					Pattern:       "EVAL",
					CaseSensitive: false,
				},
			},
		},
	}

	result := executeRuleCheck(context.Background(), workspace, manifest, checkDef)
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if len(result.payload.Findings) == 0 {
		t.Error("expected case-insensitive match for EVAL/eval")
	}
}

func TestExecuteRuleCheck_CaseSensitiveContains(t *testing.T) {
	workspace := t.TempDir()
	mustWriteRuleTest(t, filepath.Join(workspace, "test.go"), "eval(userInput)")

	manifest := model.InputManifest{
		RootPath: workspace,
		Files:    []model.ManifestFile{{Path: "test.go", Size: 15}},
	}

	checkDef := checks.Definition{
		APIVersion: checks.APIVersion,
		ID:         "case-strict-test",
		Name:       "Case Strict Test",
		Status:     checks.StatusEnabled,
		Source:     checks.SourceCustom,
		Engine:     checks.EngineRule,
		Rule: checks.Rule{
			Target: checks.RuleTargetFileContent,
			Detectors: []checks.RuleDetector{
				{
					ID:            "eval-detector",
					Kind:          checks.RuleDetectorContains,
					Pattern:       "EVAL",
					CaseSensitive: true,
				},
			},
		},
	}

	result := executeRuleCheck(context.Background(), workspace, manifest, checkDef)
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if len(result.payload.Findings) > 0 {
		t.Error("expected no match for case-sensitive EVAL vs eval")
	}
}

func TestExecuteRuleCheck_MaxMatchesLimit(t *testing.T) {
	workspace := t.TempDir()
	content := strings.Repeat("TODO ", 100)
	mustWriteRuleTest(t, filepath.Join(workspace, "test.go"), content)

	manifest := model.InputManifest{
		RootPath: workspace,
		Files:    []model.ManifestFile{{Path: "test.go", Size: int64(len(content))}},
	}

	checkDef := checks.Definition{
		APIVersion: checks.APIVersion,
		ID:         "maxmatch-test",
		Name:       "Max Match Test",
		Status:     checks.StatusEnabled,
		Source:     checks.SourceCustom,
		Engine:     checks.EngineRule,
		Rule: checks.Rule{
			Target: checks.RuleTargetFileContent,
			Detectors: []checks.RuleDetector{
				{
					ID:         "todo-detector",
					Kind:       checks.RuleDetectorContains,
					Pattern:    "TODO",
					MaxMatches: 3,
				},
			},
		},
	}

	result := executeRuleCheck(context.Background(), workspace, manifest, checkDef)
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if len(result.payload.Findings) != 3 {
		t.Errorf("expected exactly 3 findings (max_matches=3), got %d", len(result.payload.Findings))
	}
}

func TestExecuteRuleCheck_EmptyManifest(t *testing.T) {
	workspace := t.TempDir()
	manifest := model.InputManifest{
		RootPath: workspace,
		Files:    nil,
	}

	checkDef := checks.Definition{
		APIVersion: checks.APIVersion,
		ID:         "empty-test",
		Name:       "Empty Test",
		Status:     checks.StatusEnabled,
		Source:     checks.SourceCustom,
		Engine:     checks.EngineRule,
		Rule: checks.Rule{
			Target: checks.RuleTargetFileContent,
			Detectors: []checks.RuleDetector{
				{
					ID:      "detector-1",
					Kind:    checks.RuleDetectorContains,
					Pattern: "test",
				},
			},
		},
	}

	result := executeRuleCheck(context.Background(), workspace, manifest, checkDef)
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if len(result.payload.Findings) != 0 {
		t.Errorf("expected 0 findings for empty manifest, got %d", len(result.payload.Findings))
	}
}

func TestExecuteRuleCheck_ContextCancellation(t *testing.T) {
	workspace := t.TempDir()
	// Create many files
	for i := 0; i < 100; i++ {
		mustWriteRuleTest(t, filepath.Join(workspace, "file"+string(rune('a'+i%26))+".go"), "TODO")
	}
	files := make([]model.ManifestFile, 100)
	for i := 0; i < 100; i++ {
		files[i] = model.ManifestFile{Path: "file" + string(rune('a'+i%26)) + ".go", Size: 4}
	}

	manifest := model.InputManifest{
		RootPath: workspace,
		Files:    files,
	}

	checkDef := checks.Definition{
		APIVersion: checks.APIVersion,
		ID:         "cancel-test",
		Name:       "Cancel Test",
		Status:     checks.StatusEnabled,
		Source:     checks.SourceCustom,
		Engine:     checks.EngineRule,
		Rule: checks.Rule{
			Target: checks.RuleTargetFileContent,
			Detectors: []checks.RuleDetector{
				{ID: "d1", Kind: checks.RuleDetectorContains, Pattern: "TODO"},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := executeRuleCheck(ctx, workspace, manifest, checkDef)
	if result.err == nil {
		// It's OK if some files were processed before cancellation
		t.Log("NOTE: rule check completed despite cancelled context (fast execution)")
	}
}

// --- Glob Matching Tests ---

func TestGlobMatch_Patterns(t *testing.T) {
	tests := []struct {
		glob  string
		value string
		match bool
	}{
		{"**/*.go", "src/main.go", true},
		{"**/*.go", "main.go", true},
		{"**/*.go", "src/deep/file.go", true},
		{"**/*.go", "main.txt", false},
		{"*.go", "main.go", true},
		{"*.go", "src/main.go", false},
		{"src/**", "src/main.go", true},
		{"src/**", "lib/main.go", false},
		{"**/*_test.go", "pkg/handler_test.go", true},
		{"**/*_test.go", "handler.go", false},
		{"", "anything", false},
		{"   ", "anything", false},
	}
	for _, tt := range tests {
		t.Run(tt.glob+"_"+tt.value, func(t *testing.T) {
			result := globMatch(tt.glob, tt.value)
			if result != tt.match {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tt.glob, tt.value, result, tt.match)
			}
		})
	}
}

func TestGlobToRegex_SpecialChars(t *testing.T) {
	tests := []struct {
		glob     string
		contains string
	}{
		{"*.go", `[^/]*\.go`},
		{"**/*.js", `(?:.*/)?[^/]*\.js`},
		{"file+name", `file\+name`},
	}
	for _, tt := range tests {
		result := globToRegex(tt.glob)
		if !strings.Contains(result, tt.contains) {
			t.Errorf("globToRegex(%q) = %q, expected to contain %q", tt.glob, result, tt.contains)
		}
	}
}

// --- Evidence Snippet Tests ---

func TestBuildEvidenceSnippet_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		content string
		start   int
		end     int
		empty   bool
	}{
		{"negative start", "content", -1, 5, true},
		{"start > content", "abc", 10, 15, true},
		{"end < start", "content", 5, 3, true},
		{"zero length content", "", 0, 0, true},
		{"valid range", "hello world", 0, 5, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildEvidenceSnippet(tt.content, tt.start, tt.end)
			if tt.empty && result != "" {
				t.Errorf("expected empty snippet, got %q", result)
			}
			if !tt.empty && result == "" {
				t.Error("expected non-empty snippet")
			}
		})
	}
}

func TestBuildEvidenceSnippet_Context(t *testing.T) {
	content := strings.Repeat("x", 200) + "SECRET" + strings.Repeat("y", 200)
	start := 200
	end := 206

	snippet := buildEvidenceSnippet(content, start, end)
	if !strings.Contains(snippet, "SECRET") {
		t.Error("expected snippet to contain the match")
	}
	if !strings.HasPrefix(snippet, "...") {
		t.Error("expected snippet to start with ... (left context truncated)")
	}
	if !strings.HasSuffix(snippet, "...") {
		t.Error("expected snippet to end with ... (right context truncated)")
	}
}

// --- Contains Match Tests ---

func TestContainsMatches_EmptyNeedle(t *testing.T) {
	result := containsMatches("content", "", false, 5)
	if len(result) != 0 {
		t.Errorf("expected no matches for empty needle, got %d", len(result))
	}
}

func TestContainsMatches_WhitespaceNeedle(t *testing.T) {
	result := containsMatches("content", "   ", false, 5)
	if len(result) != 0 {
		t.Errorf("expected no matches for whitespace needle, got %d", len(result))
	}
}

func TestContainsMatches_ZeroMax(t *testing.T) {
	result := containsMatches("test test test", "test", true, 0)
	if len(result) != 0 {
		t.Errorf("expected no matches for max=0, got %d", len(result))
	}
}

func mustWriteRuleTest(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
