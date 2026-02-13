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
