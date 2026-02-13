package trust

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveCodexBinary_DefaultNameOnPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "codex")
	writeExecutable(t, bin, "#!/bin/sh\necho 'codex 1.2.3'\n")
	t.Setenv("PATH", dir)

	out, err := ResolveCodexBinary(context.Background(), "codex", false)
	if err != nil {
		t.Fatalf("ResolveCodexBinary failed: %v", err)
	}
	want, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatalf("EvalSymlinks failed: %v", err)
	}
	if out.ResolvedPath != want {
		t.Fatalf("expected resolved path %s, got %s", bin, out.ResolvedPath)
	}
	if out.Version != "codex 1.2.3" {
		t.Fatalf("unexpected version: %q", out.Version)
	}
	if out.SHA256 == "" {
		t.Fatal("expected SHA256 to be set")
	}
}

func TestResolveCodexBinary_CaseVariantRequiresOptIn(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "CoDeX")
	writeExecutable(t, bin, "#!/bin/sh\necho 'codex 1.2.3'\n")
	t.Setenv("PATH", dir)

	_, err := ResolveCodexBinary(context.Background(), "CoDeX", false)
	if err == nil {
		t.Fatal("expected error for custom binary without opt-in")
	}
	if !strings.Contains(err.Error(), "custom codex binary is disabled") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveCodexBinary_RejectsGroupWritableBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "codex")
	writeExecutable(t, bin, "#!/bin/sh\necho 'codex 1.2.3'\n")
	if err := os.Chmod(bin, 0o775); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	t.Setenv("PATH", dir)

	_, err := ResolveCodexBinary(context.Background(), "codex", false)
	if err == nil {
		t.Fatal("expected group/world writable rejection")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeExecutable(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}
