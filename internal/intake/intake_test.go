package intake

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageFolder_BuildManifestAndSkip(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")
	mustWrite(t, filepath.Join(root, "config.yaml"), "x: 1")
	mustWrite(t, filepath.Join(root, "image.png"), "not-source")
	mustWrite(t, filepath.Join(root, "node_modules", "lib.js"), "skip")
	mustWrite(t, filepath.Join(root, ".governor", "runs", "old", "audit.json"), "{}")
	mustWrite(t, filepath.Join(root, "bin", "governor"), "binary")
	mustWrite(t, filepath.Join(root, ".DS_Store"), "junk")
	mustWrite(t, filepath.Join(root, ".env"), "OPENAI_API_KEY=test")

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  10,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}

	if res.Manifest.IncludedFiles != 2 {
		t.Fatalf("expected 2 included files, got %d", res.Manifest.IncludedFiles)
	}
	if res.WorkspacePath == root {
		t.Fatalf("expected staged workspace separate from source root")
	}
	if res.Manifest.SkippedFiles == 0 {
		t.Fatalf("expected skipped files > 0")
	}
	if got := res.Manifest.SkippedByReason["skip_dir"]; got < 2 {
		t.Fatalf("expected skip_dir >= 2, got %d", got)
	}
	if got := res.Manifest.SkippedByReason["skip_name"]; got < 1 {
		t.Fatalf("expected skip_name >= 1, got %d", got)
	}
	if got := res.Manifest.SkippedByReason["skip_secret"]; got < 1 {
		t.Fatalf("expected skip_secret >= 1, got %d", got)
	}
	if _, err := os.Stat(filepath.Join(res.WorkspacePath, "main.go")); err != nil {
		t.Fatalf("expected copied file in workspace: %v", err)
	}
	if _, err := os.Stat(filepath.Join(res.WorkspacePath, "image.png")); !os.IsNotExist(err) {
		t.Fatalf("expected skipped file to be absent from workspace")
	}
	if _, err := os.Stat(filepath.Join(res.WorkspacePath, "node_modules", "lib.js")); !os.IsNotExist(err) {
		t.Fatalf("expected skipped directory to be absent from workspace")
	}
	if _, err := os.Stat(filepath.Join(res.WorkspacePath, ".env")); !os.IsNotExist(err) {
		t.Fatalf("expected secret file to be absent from workspace")
	}
	if err := res.Cleanup(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if _, err := os.Stat(res.WorkspacePath); !os.IsNotExist(err) {
		t.Fatalf("expected workspace to be removed after cleanup")
	}
}

func TestStageFolder_ExceedsFileLimit(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.go"), "a")
	mustWrite(t, filepath.Join(root, "b.go"), "b")

	_, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    t.TempDir(),
		MaxFiles:  1,
		MaxBytes:  1024,
	})
	if err == nil {
		t.Fatal("expected file limit error")
	}
}

func TestStageFolder_ExceedsByteLimit(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), strings.Repeat("a", 32))

	_, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    t.TempDir(),
		MaxFiles:  10,
		MaxBytes:  8,
	})
	if err == nil {
		t.Fatal("expected byte limit error")
	}
}

func TestValidateCleanupWorkspace_RejectsUnsafePath(t *testing.T) {
	out := t.TempDir()
	unsafe := filepath.Join(out, "not-workspace")
	if err := validateCleanupWorkspace(unsafe, out); err == nil {
		t.Fatal("expected unsafe cleanup path to be rejected")
	}
}

func TestStageFolder_SkipsHardLinkedFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	mustWrite(t, outside, "outside")

	linked := filepath.Join(root, "linked.txt")
	if err := os.Link(outside, linked); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}

	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    t.TempDir(),
		MaxFiles:  10,
		MaxBytes:  1024,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}
	if res.Manifest.IncludedFiles != 0 {
		t.Fatalf("expected no included files, got %d", res.Manifest.IncludedFiles)
	}
	if got := res.Manifest.SkippedByReason["hardlink"]; got < 1 {
		t.Fatalf("expected hardlink skip count >= 1, got %d", got)
	}
}

func TestCopyFileWithLimit_DetectsSourceReplacement(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.txt")
	b := filepath.Join(root, "b.txt")
	dst := filepath.Join(t.TempDir(), "dst.txt")
	mustWrite(t, a, "a")
	mustWrite(t, b, "b")

	infoA, err := os.Lstat(a)
	if err != nil {
		t.Fatalf("stat a: %v", err)
	}

	_, err = copyFileWithLimit(b, dst, 64, infoA, root)
	if err == nil {
		t.Fatal("expected source replacement detection error")
	}
	if !strings.Contains(err.Error(), "changed during copy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSkipFile_OversizedFile(t *testing.T) {
	reason, skip := skipFile("big.go", "big.go", maxFileBytes+1, 0)
	if !skip {
		t.Fatal("expected oversized file to be skipped")
	}
	if reason != "file_too_large" {
		t.Fatalf("expected reason file_too_large, got %q", reason)
	}
}

func TestSkipFile_SmallFileIncluded(t *testing.T) {
	reason, skip := skipFile("main.go", "main.go", 1024, 0)
	if skip {
		t.Fatalf("expected small file to be included, got reason=%q", reason)
	}
}

func TestSkipFile_ExactlyAtLimit(t *testing.T) {
	reason, skip := skipFile("exact.go", "exact.go", maxFileBytes, 0)
	if skip {
		t.Fatalf("expected file at exact limit to be included, got reason=%q", reason)
	}
}

func TestStageFolder_SkipsOversizedFile(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "small.go"), "package main")

	// Create an oversized file by writing just above the limit
	bigPath := filepath.Join(root, "big.go")
	f, err := os.Create(bigPath)
	if err != nil {
		t.Fatal(err)
	}
	// Write maxFileBytes+1 bytes
	buf := make([]byte, maxFileBytes+1)
	for i := range buf {
		buf[i] = 'x'
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  int64(maxFileBytes * 3),
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}
	if res.Manifest.IncludedFiles != 1 {
		t.Fatalf("expected 1 included file (small.go), got %d", res.Manifest.IncludedFiles)
	}
	if got := res.Manifest.SkippedByReason["file_too_large"]; got != 1 {
		t.Fatalf("expected 1 file_too_large skip, got %d", got)
	}
}

func mustWrite(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
