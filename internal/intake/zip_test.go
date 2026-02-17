package intake

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageZip_UnsafePath(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "unsafe.zip")
	createZip(t, zipPath, map[string]string{
		"../evil.txt": "pwn",
	})

	_, err := Stage(StageOptions{
		InputPath: zipPath,
		OutDir:    t.TempDir(),
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err == nil {
		t.Fatal("expected unsafe path error")
	}
}

func TestStageZip_SafeAndFiltered(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "safe.zip")
	createZip(t, zipPath, map[string]string{
		"src/main.go": "package main",
		"README.md":   "ok",
		".git/config": "skip",
		"image.png":   "skip",
		".env":        "OPENAI_API_KEY=test",
	})

	res, err := Stage(StageOptions{
		InputPath: zipPath,
		OutDir:    t.TempDir(),
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage zip failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(res.WorkspacePath, "src", "main.go")); err != nil {
		t.Fatalf("expected extracted file in workspace: %v", err)
	}
	if _, err := os.Stat(filepath.Join(res.WorkspacePath, ".git", "config")); !os.IsNotExist(err) {
		t.Fatalf("expected .git files to be excluded from workspace")
	}
	if res.Manifest.IncludedFiles != 2 {
		t.Fatalf("expected 2 included files, got %d", res.Manifest.IncludedFiles)
	}
	if got := res.Manifest.SkippedByReason["skip_dir"]; got == 0 {
		t.Fatalf("expected skip_dir > 0, got %d", got)
	}
	if got := res.Manifest.SkippedByReason["security_relevant_excluded"]; got == 0 {
		t.Fatalf("expected security_relevant_excluded > 0, got %d", got)
	}
	if _, err := os.Stat(filepath.Join(res.WorkspacePath, ".env")); !os.IsNotExist(err) {
		t.Fatalf("expected secret file to be excluded from workspace")
	}
}

func TestStageZip_ExceedsByteLimit(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "big.zip")
	createZip(t, zipPath, map[string]string{
		"src/main.go": strings.Repeat("a", 128),
	})

	_, err := Stage(StageOptions{
		InputPath: zipPath,
		OutDir:    t.TempDir(),
		MaxFiles:  10,
		MaxBytes:  8,
	})
	if err == nil {
		t.Fatal("expected byte limit error")
	}
}

func createZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	w := zip.NewWriter(f)
	for name, content := range files {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
