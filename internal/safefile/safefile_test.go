package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureFreshDir_CreatesAndRejectsExisting(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "runs", "20260213-230000")

	created, err := EnsureFreshDir(target, 0o700)
	if err != nil {
		t.Fatalf("EnsureFreshDir failed: %v", err)
	}
	if created != target {
		t.Fatalf("unexpected created path: got %s want %s", created, target)
	}

	if _, err := EnsureFreshDir(target, 0o700); err == nil {
		t.Fatal("expected existing directory to fail")
	}
}

func TestWriteFileAtomic_RejectsSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	err := WriteFileAtomic(link, []byte("new"), 0o600)
	if err == nil {
		t.Fatal("expected symlink target to be rejected")
	}
	if !strings.Contains(err.Error(), "symlinked file target") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWriteFileAtomic_OverwritesRegularFile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "audit.json")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(target, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("unexpected content: %s", string(got))
	}
}

func TestEnsureDir_RequireEmpty(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "out")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := EnsureDir(target, 0o700, true); err != nil {
		t.Fatalf("expected empty dir to pass: %v", err)
	}

	if err := os.WriteFile(filepath.Join(target, "audit.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureDir(target, 0o700, true); err == nil {
		t.Fatal("expected non-empty dir to fail")
	}
}
