package taps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCloneTap_InvalidURL(t *testing.T) {
	dir := t.TempDir()
	err := CloneTap("https://invalid.example.com/no/repo.git", dir)
	if err == nil {
		t.Fatal("expected error cloning invalid URL")
	}
}

func TestListPacks_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	packsDir := filepath.Join(dir, "packs")
	if err := os.MkdirAll(packsDir, 0755); err != nil {
		t.Fatal(err)
	}
	packs, err := ListPacks(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(packs) != 0 {
		t.Fatalf("expected 0 packs, got %d", len(packs))
	}
}

func TestListPacks_NoPacksDirReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	packs, err := ListPacks(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(packs) != 0 {
		t.Fatalf("expected 0 packs, got %d", len(packs))
	}
}

func TestListPacks_WithPacks(t *testing.T) {
	dir := t.TempDir()
	packsDir := filepath.Join(dir, "packs", "nextjs")
	if err := os.MkdirAll(packsDir, 0755); err != nil {
		t.Fatal(err)
	}
	packYAML := "name: nextjs\ndescription: Next.js checks\nversion: 1.0.0\nauthor: test\n"
	if err := os.WriteFile(filepath.Join(packsDir, "pack.yaml"), []byte(packYAML), 0644); err != nil {
		t.Fatal(err)
	}
	checkYAML := "api_version: governor/v1\nid: test-check\nstatus: enabled\n"
	if err := os.WriteFile(filepath.Join(packsDir, "test-check.check.yaml"), []byte(checkYAML), 0644); err != nil {
		t.Fatal(err)
	}

	packs, err := ListPacks(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("expected 1 pack, got %d", len(packs))
	}
	if packs[0].Name != "nextjs" {
		t.Errorf("expected pack name nextjs, got %q", packs[0].Name)
	}
	if packs[0].Description != "Next.js checks" {
		t.Errorf("expected description 'Next.js checks', got %q", packs[0].Description)
	}
}

func TestFindPack(t *testing.T) {
	dir := t.TempDir()
	packDir := filepath.Join(dir, "packs", "mypack")
	if err := os.MkdirAll(packDir, 0755); err != nil {
		t.Fatal(err)
	}

	found, ok := FindPack(dir, "mypack")
	if !ok {
		t.Fatal("expected to find pack")
	}
	if found != packDir {
		t.Errorf("expected %q, got %q", packDir, found)
	}

	_, ok = FindPack(dir, "nonexistent")
	if ok {
		t.Fatal("expected not to find nonexistent pack")
	}
}

func TestCopyPackChecks(t *testing.T) {
	srcDir := t.TempDir()
	packDir := filepath.Join(srcDir, "packs", "mypack")
	if err := os.MkdirAll(packDir, 0755); err != nil {
		t.Fatal(err)
	}
	checkContent := "api_version: governor/v1\nid: my-check\nstatus: enabled\nsource: custom\nengine: rule\n"
	if err := os.WriteFile(filepath.Join(packDir, "my-check.check.yaml"), []byte(checkContent), 0644); err != nil {
		t.Fatal(err)
	}
	// Also write a non-check file that should NOT be copied.
	if err := os.WriteFile(filepath.Join(packDir, "pack.yaml"), []byte("name: mypack\n"), 0644); err != nil {
		t.Fatal(err)
	}

	dstDir := t.TempDir()
	n, err := CopyPackChecks(packDir, dstDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 check copied, got %d", n)
	}

	// Verify check file exists in destination.
	if _, err := os.Stat(filepath.Join(dstDir, "my-check.check.yaml")); err != nil {
		t.Fatalf("expected copied check file to exist: %v", err)
	}
	// Verify non-check file was NOT copied.
	if _, err := os.Stat(filepath.Join(dstDir, "pack.yaml")); !os.IsNotExist(err) {
		t.Fatal("pack.yaml should not be copied")
	}
}
