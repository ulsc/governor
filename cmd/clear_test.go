package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClearRuns_EmptyDir(t *testing.T) {
	runsDir := filepath.Join(t.TempDir(), "runs")
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	removed, err := clearRuns(runsDir, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("expected nothing removed, got %v", removed)
	}
}

func TestClearRuns_DirNotExist(t *testing.T) {
	runsDir := filepath.Join(t.TempDir(), "nonexistent")
	removed, err := clearRuns(runsDir, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("expected nothing removed, got %v", removed)
	}
}

func TestClearRuns_RemovesAll(t *testing.T) {
	runsDir := filepath.Join(t.TempDir(), "runs")
	dirs := []string{"20260101-000000", "20260102-000000", "20260103-000000"}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(runsDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	removed, err := clearRuns(runsDir, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(removed) != 3 {
		t.Fatalf("expected 3 removed, got %d: %v", len(removed), removed)
	}
	entries, _ := os.ReadDir(runsDir)
	if len(entries) != 0 {
		t.Fatalf("expected empty runs dir, got %d entries", len(entries))
	}
}

func TestClearRuns_KeepOne(t *testing.T) {
	runsDir := filepath.Join(t.TempDir(), "runs")
	dirs := []string{"20260101-000000", "20260102-000000", "20260103-000000"}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(runsDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	removed, err := clearRuns(runsDir, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(removed) != 2 {
		t.Fatalf("expected 2 removed, got %d: %v", len(removed), removed)
	}

	entries, _ := os.ReadDir(runsDir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 remaining, got %d", len(entries))
	}
	if entries[0].Name() != "20260103-000000" {
		t.Fatalf("expected newest kept, got %s", entries[0].Name())
	}
}

func TestClearRuns_KeepTwo(t *testing.T) {
	runsDir := filepath.Join(t.TempDir(), "runs")
	dirs := []string{"20260101-000000", "20260102-000000", "20260103-000000"}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(runsDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	removed, err := clearRuns(runsDir, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed, got %d: %v", len(removed), removed)
	}
	if removed[0] != "20260101-000000" {
		t.Fatalf("expected oldest removed, got %s", removed[0])
	}

	entries, _ := os.ReadDir(runsDir)
	if len(entries) != 2 {
		t.Fatalf("expected 2 remaining, got %d", len(entries))
	}
}

func TestClearRuns_KeepExceedsTotal(t *testing.T) {
	runsDir := filepath.Join(t.TempDir(), "runs")
	dirs := []string{"20260101-000000", "20260102-000000"}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(runsDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	removed, err := clearRuns(runsDir, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("expected nothing removed, got %v", removed)
	}
}

func TestClearRuns_SkipsFiles(t *testing.T) {
	runsDir := filepath.Join(t.TempDir(), "runs")
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Create a file (not a directory)
	if err := os.WriteFile(filepath.Join(runsDir, "stray-file.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	// Create one real run directory
	if err := os.MkdirAll(filepath.Join(runsDir, "20260101-000000"), 0o755); err != nil {
		t.Fatalf("mkdir run: %v", err)
	}

	removed, err := clearRuns(runsDir, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed, got %d: %v", len(removed), removed)
	}
	if removed[0] != "20260101-000000" {
		t.Fatalf("expected directory removed, got %s", removed[0])
	}
	// File should still exist
	if _, err := os.Stat(filepath.Join(runsDir, "stray-file.txt")); err != nil {
		t.Fatalf("expected stray file to remain: %v", err)
	}
}

func TestRunClear_Integration(t *testing.T) {
	tmp := t.TempDir()
	restoreWD := setWorkingDir(t, tmp)
	defer restoreWD()

	runsDir := filepath.Join(tmp, ".governor", "runs")
	dirs := []string{"20260101-000000", "20260102-000000", "20260103-000000"}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(runsDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	out := captureStdout(t, func() {
		if err := runClear([]string{"--without-last", "2"}); err != nil {
			t.Fatalf("runClear failed: %v", err)
		}
	})

	if !strings.Contains(out, "Removed 1 run(s).") {
		t.Fatalf("expected removal message, got:\n%s", out)
	}
	if !strings.Contains(out, "20260101-000000") {
		t.Fatalf("expected removed dir name in output, got:\n%s", out)
	}

	entries, _ := os.ReadDir(runsDir)
	if len(entries) != 2 {
		t.Fatalf("expected 2 remaining, got %d", len(entries))
	}
}

func TestRunClear_NoRuns(t *testing.T) {
	tmp := t.TempDir()
	restoreWD := setWorkingDir(t, tmp)
	defer restoreWD()

	out := captureStdout(t, func() {
		if err := runClear(nil); err != nil {
			t.Fatalf("runClear failed: %v", err)
		}
	})

	if !strings.Contains(out, "No runs to clear.") {
		t.Fatalf("expected no-runs message, got:\n%s", out)
	}
}

func TestRunClear_WithoutLastDefaultsToOne(t *testing.T) {
	tmp := t.TempDir()
	restoreWD := setWorkingDir(t, tmp)
	defer restoreWD()

	runsDir := filepath.Join(tmp, ".governor", "runs")
	dirs := []string{"20260101-000000", "20260102-000000"}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(runsDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	out := captureStdout(t, func() {
		if err := runClear([]string{"--without-last"}); err != nil {
			t.Fatalf("runClear failed: %v", err)
		}
	})

	if !strings.Contains(out, "Removed 1 run(s).") {
		t.Fatalf("expected 1 removed, got:\n%s", out)
	}

	entries, _ := os.ReadDir(runsDir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 remaining, got %d", len(entries))
	}
	if entries[0].Name() != "20260102-000000" {
		t.Fatalf("expected newest kept, got %s", entries[0].Name())
	}
}

func TestRunClear_UnknownFlag(t *testing.T) {
	err := runClear([]string{"--bogus"})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrintUsage_IncludesClearCommand(t *testing.T) {
	out := captureStdout(t, func() {
		printUsage()
	})

	if !strings.Contains(out, "governor clear") {
		t.Fatalf("expected usage to include clear command, got:\n%s", out)
	}
	if !strings.Contains(out, "--without-last") {
		t.Fatalf("expected usage to include --without-last flag, got:\n%s", out)
	}
}
