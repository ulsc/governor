package intake

import (
	"io"
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
	if got := res.Manifest.SkippedByReason["security_relevant_excluded"]; got < 1 {
		t.Fatalf("expected security_relevant_excluded >= 1, got %d", got)
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

func TestIsSensitiveFileName_CloudCredentials(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"credentials", true},
		{"credentials.json", true},
		{"application_default_credentials.json", true},
		{"kubeconfig", true},
		{".env", true},
		{"main.go", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitiveFileName(tt.name)
			if got != tt.want {
				t.Errorf("isSensitiveFileName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsSensitiveFilePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{".aws/credentials", true},
		{".aws/config", true},
		{".kube/config", true},
		{".docker/config.json", true},
		{"home/user/.aws/credentials", true},
		{"main.go", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isSensitiveFilePath(tt.path)
			if got != tt.want {
				t.Errorf("isSensitiveFilePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestSkipDirNames_IncludesIDEAndBuildDirs(t *testing.T) {
	for _, dir := range []string{"__pycache__", ".terraform", ".idea", ".vscode"} {
		if _, ok := skipDirNames[dir]; !ok {
			t.Errorf("expected %q in skipDirNames", dir)
		}
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
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()

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

func TestStageFolder_OnlyFilesFilter(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")
	mustWrite(t, filepath.Join(root, "config.yaml"), "x: 1")
	mustWrite(t, filepath.Join(root, "util.go"), "package util")

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
		OnlyFiles: []string{"main.go"},
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}

	if res.Manifest.IncludedFiles != 1 {
		t.Fatalf("expected 1 included file with OnlyFiles, got %d", res.Manifest.IncludedFiles)
	}
	found := false
	for _, f := range res.Manifest.Files {
		if f.Path == "main.go" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected main.go in manifest")
	}
}

func TestStageFolder_OnlyFilesEmpty(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")
	mustWrite(t, filepath.Join(root, "util.go"), "package util")

	out := t.TempDir()
	// nil OnlyFiles should include all files (normal behavior).
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}
	if res.Manifest.IncludedFiles != 2 {
		t.Fatalf("expected 2 included files without OnlyFiles, got %d", res.Manifest.IncludedFiles)
	}
}

func TestStageFolder_OnlyFilesSubdir(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")
	mustWrite(t, filepath.Join(root, "pkg", "util.go"), "package pkg")
	mustWrite(t, filepath.Join(root, "pkg", "other.go"), "package pkg")

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
		OnlyFiles: []string{"pkg/util.go"},
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}
	if res.Manifest.IncludedFiles != 1 {
		t.Fatalf("expected 1 included file, got %d", res.Manifest.IncludedFiles)
	}
	if res.Manifest.Files[0].Path != "pkg/util.go" {
		t.Fatalf("expected pkg/util.go, got %s", res.Manifest.Files[0].Path)
	}
}

func TestStageFolder_GovernorIgnore(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")
	mustWrite(t, filepath.Join(root, "util.go"), "package main")
	mustWrite(t, filepath.Join(root, "generated", "model.go"), "package gen")
	mustWrite(t, filepath.Join(root, "debug.log"), "log data")

	ignorePath := filepath.Join(root, ".governorignore")
	mustWrite(t, ignorePath, "generated/\n*.log\n")

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath:  root,
		OutDir:     out,
		MaxFiles:   100,
		MaxBytes:   10 * 1024 * 1024,
		IgnoreFile: ignorePath,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}

	// main.go, util.go, and .governorignore itself should be included.
	if res.Manifest.IncludedFiles != 3 {
		t.Fatalf("expected 3 included files, got %d", res.Manifest.IncludedFiles)
	}

	for _, f := range res.Manifest.Files {
		if strings.Contains(f.Path, "generated") || strings.Contains(f.Path, ".log") {
			t.Errorf("ignored file %s should not be in manifest", f.Path)
		}
	}

	if got := res.Manifest.SkippedByReason["governorignore"]; got < 2 {
		t.Fatalf("expected governorignore >= 2, got %d", got)
	}
}

func TestStageFolder_GovernorIgnoreMissing(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath:  root,
		OutDir:     out,
		MaxFiles:   100,
		MaxBytes:   10 * 1024 * 1024,
		IgnoreFile: filepath.Join(root, ".governorignore"),
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}

	if res.Manifest.IncludedFiles != 1 {
		t.Fatalf("expected 1 included file, got %d", res.Manifest.IncludedFiles)
	}
}

func TestStageFolder_SecurityRelevantFilesCounted(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")
	mustWrite(t, filepath.Join(root, "server.pem"), "-----BEGIN CERTIFICATE-----")
	mustWrite(t, filepath.Join(root, "private.key"), "-----BEGIN PRIVATE KEY-----")
	mustWrite(t, filepath.Join(root, ".env"), "SECRET=abc")

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

	if res.Manifest.SecurityRelevantSkipped != 3 {
		t.Fatalf("expected 3 security-relevant skipped, got %d", res.Manifest.SecurityRelevantSkipped)
	}
	if got := res.Manifest.SkippedByReason["security_relevant_excluded"]; got != 3 {
		t.Fatalf("expected security_relevant_excluded == 3, got %d", got)
	}
}

func TestSkipFile_SecurityRelevantReason(t *testing.T) {
	tests := []struct {
		name       string
		filename   string
		wantReason string
		wantSkip   bool
	}{
		{"pem file", "server.pem", "security_relevant_excluded", true},
		{"key file", "private.key", "security_relevant_excluded", true},
		{"p12 file", "cert.p12", "security_relevant_excluded", true},
		{"pfx file", "cert.pfx", "security_relevant_excluded", true},
		{"crt file", "ca.crt", "security_relevant_excluded", true},
		{"env file", ".env", "security_relevant_excluded", true},
		{"env variant", ".env.production", "security_relevant_excluded", true},
		{"secrets yaml", "secrets.yaml", "security_relevant_excluded", true},
		{"credentials json", "credentials.json", "security_relevant_excluded", true},
		{"png still skipped", "image.png", "skip_ext", true},
		{"exe still skipped", "app.exe", "skip_ext", true},
		{"go not skipped", "main.go", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, skip := skipFile(tc.filename, tc.filename, 100, 0o644)
			if skip != tc.wantSkip {
				t.Errorf("skipFile(%q) skip=%v, want %v", tc.filename, skip, tc.wantSkip)
			}
			if reason != tc.wantReason {
				t.Errorf("skipFile(%q) reason=%q, want %q", tc.filename, reason, tc.wantReason)
			}
		})
	}
}

func TestStageFolder_SecurityRelevantWarning(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")
	mustWrite(t, filepath.Join(root, "server.pem"), "cert")
	mustWrite(t, filepath.Join(root, ".env"), "SECRET=x")

	// Capture stderr
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	out := t.TempDir()
	_, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  10,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		_ = w.Close()
		os.Stderr = old
		t.Fatalf("stage failed: %v", err)
	}

	_ = w.Close()
	var buf strings.Builder
	_, _ = io.Copy(&buf, r)
	os.Stderr = old

	stderr := buf.String()
	if !strings.Contains(stderr, "security-relevant files skipped") {
		t.Fatalf("expected security-relevant warning on stderr, got: %q", stderr)
	}
	if !strings.Contains(stderr, "secrets scanner") {
		t.Fatalf("expected secrets scanner suggestion in warning, got: %q", stderr)
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
