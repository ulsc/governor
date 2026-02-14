package intake

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Path Traversal Tests ---

func TestWorkspaceTargetPath_RejectsDotDotVariants(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name string
		rel  string
	}{
		{"simple dotdot", "../etc/passwd"},
		{"dotdot with slash", "foo/../../etc/passwd"},
		{"triple dotdot", "a/b/../../../etc/passwd"},
		{"just dotdot", ".."},
		{"dotdot slash", "../"},
		{"dotdot at end", "foo/.."},
		// Note: URL-encoded paths are not decoded by filepath.Clean, so %2f stays literal
		// This is safe because the % chars are literal in the filesystem
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := workspaceTargetPath(root, tt.rel)
			if err == nil {
				t.Errorf("expected error for path traversal attempt %q, got nil", tt.rel)
			}
		})
	}
}

func TestWorkspaceTargetPath_AcceptsValidPaths(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name string
		rel  string
	}{
		{"simple file", "main.go"},
		{"nested file", "src/main.go"},
		{"deep nesting", "a/b/c/d/e/f.go"},
		{"dotfile", ".gitignore"},
		{"file with dots", "my.config.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := workspaceTargetPath(root, tt.rel)
			if err != nil {
				t.Errorf("expected valid path for %q, got error: %v", tt.rel, err)
			}
			if !strings.HasPrefix(path, root) {
				t.Errorf("result path %q does not start with root %q", path, root)
			}
		})
	}
}

func TestWorkspaceTargetPath_EmptyAndDot(t *testing.T) {
	root := t.TempDir()
	_, err := workspaceTargetPath(root, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
	_, err = workspaceTargetPath(root, ".")
	if err == nil {
		t.Error("expected error for dot path")
	}
}

// --- Symlink Attack Tests ---

func TestStageFolder_SkipsSymlinkedFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	mustWriteDevil(t, outside, "TOP SECRET DATA")

	// Create a regular file and a symlink pointing outside
	mustWriteDevil(t, filepath.Join(root, "legit.go"), "package main")
	if err := os.Symlink(outside, filepath.Join(root, "sneaky.txt")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}

	// Symlinked file should not appear in workspace
	if _, err := os.Stat(filepath.Join(res.WorkspacePath, "sneaky.txt")); !os.IsNotExist(err) {
		t.Error("symlinked file should not be copied to workspace")
	}
	// But the regular file should be there
	if _, err := os.Stat(filepath.Join(res.WorkspacePath, "legit.go")); err != nil {
		t.Error("regular file should be in workspace")
	}
	// Check skip count
	if res.Manifest.SkippedByReason["symlink"] < 1 {
		t.Error("expected symlink skip count >= 1")
	}
}

func TestStageFolder_SkipsSymlinkedDirectories(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	mustWriteDevil(t, filepath.Join(outsideDir, "secret.go"), "package secret")

	if err := os.Symlink(outsideDir, filepath.Join(root, "linked-dir")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	mustWriteDevil(t, filepath.Join(root, "legit.go"), "package main")

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(res.WorkspacePath, "linked-dir", "secret.go")); !os.IsNotExist(err) {
		t.Error("symlinked directory contents should not be in workspace")
	}
}

// --- Sensitive File Detection Tests ---

func TestIsSensitiveFileName_Comprehensive(t *testing.T) {
	sensitive := []string{
		".env", ".env.local", ".env.production", ".env.staging",
		".npmrc", ".netrc", ".pypirc",
		"id_rsa", "id_ed25519",
		"secrets.yaml", "secrets.json", "secrets.env",
	}
	for _, name := range sensitive {
		if !isSensitiveFileName(name) {
			t.Errorf("expected %q to be detected as sensitive", name)
		}
	}
}

func TestIsSensitiveFileName_NotSensitive(t *testing.T) {
	safe := []string{
		"main.go", "config.yaml", "README.md",
		"Dockerfile", "Makefile",
		".gitignore", ".editorconfig",
		"env.go",         // not .env
		"secrets_test.go", // not secrets.*
	}
	for _, name := range safe {
		if isSensitiveFileName(name) {
			t.Errorf("expected %q to NOT be detected as sensitive", name)
		}
	}
}

func TestIsSensitiveFileName_CaseInsensitive(t *testing.T) {
	// The function lowercases input, so these should also be caught
	if !isSensitiveFileName(".ENV") {
		t.Error("expected .ENV to be sensitive (case-insensitive)")
	}
	if !isSensitiveFileName(".Env.Local") {
		t.Error("expected .Env.Local to be sensitive (case-insensitive)")
	}
}

func TestIsSensitiveFileName_MissingPatterns(t *testing.T) {
	// Files that SHOULD be sensitive but might not be caught
	possiblyMissing := []struct {
		name     string
		expected bool
	}{
		{".env.backup", true},       // .env.* pattern should catch
		{"credentials.json", false}, // Not in the sensitive list currently
		{".htpasswd", false},        // Not in the sensitive list
		{"authorized_keys", false},  // Not in the sensitive list
		{".pgpass", false},          // Not in the sensitive list
	}
	for _, tt := range possiblyMissing {
		result := isSensitiveFileName(tt.name)
		if result != tt.expected {
			t.Logf("NOTE: %q sensitivity=%v (expected %v) - potential gap", tt.name, result, tt.expected)
		}
	}
}

// --- Boundary Condition Tests ---

func TestStageFolder_EmptyDirectory(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage of empty dir should succeed, got: %v", err)
	}
	if res.Manifest.IncludedFiles != 0 {
		t.Errorf("expected 0 included files from empty dir, got %d", res.Manifest.IncludedFiles)
	}
}

func TestStageFolder_SingleByteFile(t *testing.T) {
	root := t.TempDir()
	mustWriteDevil(t, filepath.Join(root, "a.txt"), "a")
	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}
	if res.Manifest.IncludedFiles != 1 {
		t.Errorf("expected 1 included file, got %d", res.Manifest.IncludedFiles)
	}
}

func TestStageFolder_ZeroByteBudget(t *testing.T) {
	root := t.TempDir()
	mustWriteDevil(t, filepath.Join(root, "a.txt"), "a")
	_, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    t.TempDir(),
		MaxFiles:  100,
		MaxBytes:  0,
	})
	if err == nil {
		t.Error("expected error for zero byte budget")
	}
}

func TestStageFolder_ZeroFileLimit(t *testing.T) {
	root := t.TempDir()
	mustWriteDevil(t, filepath.Join(root, "a.txt"), "a")
	_, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    t.TempDir(),
		MaxFiles:  0,
		MaxBytes:  1024,
	})
	if err == nil {
		t.Error("expected error for zero file limit")
	}
}

func TestStageFolder_EmptyInputPath(t *testing.T) {
	_, err := Stage(StageOptions{
		InputPath: "",
		OutDir:    t.TempDir(),
		MaxFiles:  100,
		MaxBytes:  1024,
	})
	if err == nil {
		t.Error("expected error for empty input path")
	}
}

func TestStageFolder_WhitespaceInputPath(t *testing.T) {
	_, err := Stage(StageOptions{
		InputPath: "   ",
		OutDir:    t.TempDir(),
		MaxFiles:  100,
		MaxBytes:  1024,
	})
	if err == nil {
		t.Error("expected error for whitespace input path")
	}
}

func TestStageFolder_NonExistentInput(t *testing.T) {
	_, err := Stage(StageOptions{
		InputPath: "/nonexistent/path/that/does/not/exist",
		OutDir:    t.TempDir(),
		MaxFiles:  100,
		MaxBytes:  1024,
	})
	if err == nil {
		t.Error("expected error for non-existent input")
	}
}

// --- Cleanup Safety Tests ---

func TestValidateCleanupWorkspace_Comprehensive(t *testing.T) {
	out := t.TempDir()
	tests := []struct {
		name    string
		ws      string
		outDir  string
		wantErr bool
	}{
		{
			name:    "valid workspace",
			ws:      filepath.Join(out, "workspace"),
			outDir:  out,
			wantErr: false,
		},
		{
			name:    "workspace at root",
			ws:      "/workspace",
			outDir:  "/",
			wantErr: true, // /workspace does not have prefix / + separator
		},
		{
			name:    "empty workspace",
			ws:      "",
			outDir:  out,
			wantErr: true,
		},
		{
			name:    "empty output",
			ws:      filepath.Join(out, "workspace"),
			outDir:  "",
			wantErr: true,
		},
		{
			name:    "dot workspace",
			ws:      ".",
			outDir:  out,
			wantErr: true,
		},
		{
			name:    "non-workspace basename",
			ws:      filepath.Join(out, "notworkspace"),
			outDir:  out,
			wantErr: true,
		},
		{
			name:    "workspace outside output",
			ws:      "/tmp/random/workspace",
			outDir:  out,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCleanupWorkspace(tt.ws, tt.outDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCleanupWorkspace(%q, %q) error = %v, wantErr %v", tt.ws, tt.outDir, err, tt.wantErr)
			}
		})
	}
}

// --- Skip Directory Tests ---

func TestHasSkippedDirComponent_Comprehensive(t *testing.T) {
	tests := []struct {
		rel    string
		expect bool
	}{
		{"src/main.go", false},
		{"node_modules/express/index.js", true},
		{".git/config", true},
		{"vendor/github.com/pkg.go", true},
		{"dist/bundle.js", true},
		{"build/output.js", true},
		{".next/cache/file.js", true},
		{"target/classes/Main.class", true},
		{"coverage/lcov.info", true},
		{".aws/credentials", true},
		{".ssh/id_rsa", true},
		{".gnupg/trustdb.gpg", true},
		{".governor/config.yaml", true},
		// Edge cases
		{"", false},
		{"   ", false},
		{"normal/path/file.go", false},
	}
	for _, tt := range tests {
		t.Run(tt.rel, func(t *testing.T) {
			result := hasSkippedDirComponent(tt.rel)
			if result != tt.expect {
				t.Errorf("hasSkippedDirComponent(%q) = %v, want %v", tt.rel, result, tt.expect)
			}
		})
	}
}

// --- Path Safety Tests ---

func TestPathWithinRoot(t *testing.T) {
	tests := []struct {
		path   string
		root   string
		expect bool
	}{
		{"/a/b/c", "/a/b", true},
		{"/a/b", "/a/b", true},
		{"/a/bc", "/a/b", false}, // tricky: /a/bc is NOT within /a/b
		{"/a", "/a/b", false},
		{"/", "/", true},
		{"/a/b/../c", "/a", true}, // Clean resolves to /a/c
	}
	for _, tt := range tests {
		t.Run(tt.path+"_in_"+tt.root, func(t *testing.T) {
			result := pathWithinRoot(tt.path, tt.root)
			if result != tt.expect {
				t.Errorf("pathWithinRoot(%q, %q) = %v, want %v", tt.path, tt.root, result, tt.expect)
			}
		})
	}
}

func mustWriteDevil(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
