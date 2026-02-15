package extractor

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadInputs_SkipsSymlinkEntriesInDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on windows test environments")
	}

	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "policy.md"), []byte("allowed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "leak.txt")); err != nil {
		t.Fatal(err)
	}

	docs, warnings, err := loadInputsWithLimit([]string{root}, 1024, false)
	if err != nil {
		t.Fatalf("loadInputsWithLimit failed: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 doc, got %d", len(docs))
	}
	if !strings.HasSuffix(docs[0].path, "policy.md") {
		t.Fatalf("expected policy.md, got %s", docs[0].path)
	}
	if len(warnings) == 0 {
		t.Fatal("expected symlink warning")
	}
}

func TestLoadInputs_RejectsTopLevelSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on windows test environments")
	}

	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(target, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "input-link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadInputsWithLimit([]string{link}, 1024, false)
	if err == nil {
		t.Fatal("expected symlink rejection")
	}
	if !strings.Contains(err.Error(), "symlink inputs are not allowed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadInputs_EnforcesLimitWithoutReadingAllData(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "big.txt")
	if err := os.WriteFile(p, []byte(strings.Repeat("a", 256)), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadInputsWithLimit([]string{p}, 64, false)
	if err == nil {
		t.Fatal("expected byte-limit error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadInputs_DeduplicatesAndSortsInputs(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.txt")
	b := filepath.Join(root, "b.txt")
	if err := os.WriteFile(a, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}

	absA, err := filepath.Abs(a)
	if err != nil {
		t.Fatalf("abs a: %v", err)
	}
	absB, err := filepath.Abs(b)
	if err != nil {
		t.Fatalf("abs b: %v", err)
	}

	docs, warnings, err := loadInputsWithLimit([]string{b, a, a}, 1024, false)
	if err != nil {
		t.Fatalf("loadInputsWithLimit failed: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %q", warnings)
	}
	if len(docs) != 2 {
		t.Fatalf("expected 2 docs, got %d", len(docs))
	}
	if docs[0].path != absA || docs[1].path != absB {
		t.Fatalf("expected docs sorted by absolute path, got %q and %q", docs[0].path, docs[1].path)
	}
}

func TestLoadInputs_WarnsOnUnsupportedFilesInDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "readme.md"), []byte("policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "skip.bin"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}

	docs, warnings, err := loadInputsWithLimit([]string{root}, 1024, false)
	if err != nil {
		t.Fatalf("loadInputsWithLimit failed: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected one supported doc, got %d", len(docs))
	}
	if !strings.Contains(docs[0].path, "readme.md") {
		t.Fatalf("expected readme.md to be selected, got %q", docs[0].path)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %d", len(warnings))
	}
	if !strings.Contains(warnings[0], "unsupported extension \".bin\"") {
		t.Fatalf("expected unsupported extension warning, got %q", warnings)
	}
}

func TestBuildPrompt_TrimsSnippetAndLimitsChecks(t *testing.T) {
	docs := docSet{
		{
			path:    "policy/one.md",
			content: strings.Repeat("x", maxSnippetChars+500),
		},
		{
			path:    "policy/two.md",
			content: "brief policy text",
		},
	}

	prompt := buildPrompt(docs, 5)
	if len(prompt) > maxPromptChars {
		t.Fatalf("expected prompt length <= %d, got %d", maxPromptChars, len(prompt))
	}
	if !strings.Contains(prompt, "Generate at most 5 checks.") {
		t.Fatalf("expected max checks in prompt, got:\n%s", prompt)
	}

	lines := strings.Split(prompt, "\n")
	for i, line := range lines {
		if strings.TrimPrefix(line, "Document: ") != "policy/one.md" {
			continue
		}
		if i+1 >= len(lines) {
			t.Fatal("document content line missing")
		}
		if len(lines[i+1]) != maxSnippetChars {
			t.Fatalf("expected first doc to be truncated to %d chars, got %d", maxSnippetChars, len(lines[i+1]))
		}
		return
	}
	t.Fatal("expected policy/one.md section in prompt")
}
