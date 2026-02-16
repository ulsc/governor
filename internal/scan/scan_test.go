package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func mustWriteFile(t *testing.T, dir string, name string, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScan_NoFindings(t *testing.T) {
	dir := t.TempDir()
	f := mustWriteFile(t, dir, "clean.go", `package main

func main() {
	println("hello")
}
`)
	result, err := Run(context.Background(), Options{
		Files:          []string{f},
		NoCustomChecks: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestScan_DetectsHardcodedSecret(t *testing.T) {
	dir := t.TempDir()
	f := mustWriteFile(t, dir, "config.go", `package main

var password = "secret123"
var apiKey = "AKIA1234567890ABCDEF"
`)
	result, err := Run(context.Background(), Options{
		Files:          []string{f},
		NoCustomChecks: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings for hardcoded secrets")
	}
}

func TestScan_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := mustWriteFile(t, dir, "a.go", `var password = "secret123"`)
	f2 := mustWriteFile(t, dir, "b.go", `var key = "AKIA1234567890ABCDEF"`)

	result, err := Run(context.Background(), Options{
		Files:          []string{f1, f2},
		NoCustomChecks: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify findings reference correct files.
	seenFiles := map[string]bool{}
	for _, f := range result.Findings {
		for _, ref := range f.FileRefs {
			seenFiles[ref] = true
		}
	}
	if !seenFiles[f1] && !seenFiles[f2] {
		t.Error("expected findings to reference at least one of the input files")
	}
}

func TestScan_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := Run(context.Background(), Options{
		Files:          []string{dir},
		NoCustomChecks: true,
	})
	if err == nil {
		t.Fatal("expected error for directory input")
	}
}

func TestScan_OnlyCheck(t *testing.T) {
	dir := t.TempDir()
	f := mustWriteFile(t, dir, "config.go", `var password = "secret123"`)

	result, err := Run(context.Background(), Options{
		Files:          []string{f},
		NoCustomChecks: true,
		OnlyIDs:        []string{"hardcoded_credentials"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Checks != 1 {
		t.Fatalf("expected 1 check, got %d", result.Checks)
	}
}

func TestScan_SkipCheck(t *testing.T) {
	dir := t.TempDir()
	f := mustWriteFile(t, dir, "config.go", `var password = "secret123"`)

	result, err := Run(context.Background(), Options{
		Files:          []string{f},
		NoCustomChecks: true,
		SkipIDs:        []string{"hardcoded_credentials"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, finding := range result.Findings {
		if finding.SourceTrack == "hardcoded_credentials" {
			t.Error("expected hardcoded_credentials findings to be skipped")
		}
	}
}
