package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}
	run("init")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "test")
	// Create initial commit so HEAD exists.
	if err := os.WriteFile(filepath.Join(dir, "initial.txt"), []byte("init"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "initial.txt")
	run("commit", "-m", "initial")
	return dir
}

func TestRepoRoot(t *testing.T) {
	dir := initTestRepo(t)
	root, err := RepoRoot(dir)
	if err != nil {
		t.Fatalf("RepoRoot: %v", err)
	}
	// Resolve symlinks for macOS /private/var/folders comparison.
	wantAbs, _ := filepath.EvalSymlinks(dir)
	gotAbs, _ := filepath.EvalSymlinks(root)
	if gotAbs != wantAbs {
		t.Errorf("RepoRoot = %q, want %q", gotAbs, wantAbs)
	}
}

func TestRepoRootNotARepo(t *testing.T) {
	dir := t.TempDir()
	_, err := RepoRoot(dir)
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
}

func TestChangedFilesVsHEAD(t *testing.T) {
	dir := initTestRepo(t)

	// Create a new file (unstaged change).
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	files, err := ChangedFiles(dir, "")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	// new.txt is untracked, not changed vs HEAD in git diff.
	// Modify an existing tracked file instead.
	if err := os.WriteFile(filepath.Join(dir, "initial.txt"), []byte("modified"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err = ChangedFiles(dir, "")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	if len(files) != 1 || files[0] != "initial.txt" {
		t.Errorf("ChangedFiles = %v, want [initial.txt]", files)
	}
}

func TestChangedFilesSinceRef(t *testing.T) {
	dir := initTestRepo(t)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	// Tag the current commit (lightweight tag).
	run("tag", "-a", "v1", "-m", "v1")

	// Create and commit a new file.
	if err := os.WriteFile(filepath.Join(dir, "feature.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "feature.go")
	run("commit", "-m", "add feature")

	files, err := ChangedFiles(dir, "v1")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	if len(files) != 1 || files[0] != "feature.go" {
		t.Errorf("ChangedFiles(v1) = %v, want [feature.go]", files)
	}
}

func TestStagedFiles(t *testing.T) {
	dir := initTestRepo(t)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	// No staged changes initially.
	files, err := StagedFiles(dir)
	if err != nil {
		t.Fatalf("StagedFiles: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("StagedFiles = %v, want empty", files)
	}

	// Stage a new file.
	if err := os.WriteFile(filepath.Join(dir, "staged.txt"), []byte("staged content"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "staged.txt")

	files, err = StagedFiles(dir)
	if err != nil {
		t.Fatalf("StagedFiles: %v", err)
	}
	if len(files) != 1 || files[0] != "staged.txt" {
		t.Errorf("StagedFiles = %v, want [staged.txt]", files)
	}
}

func TestChangedFilesDeletedExcluded(t *testing.T) {
	dir := initTestRepo(t)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	// Delete the tracked file.
	run("rm", "initial.txt")

	files, err := ChangedFiles(dir, "")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	// Deleted files should be excluded by --diff-filter=d.
	for _, f := range files {
		if f == "initial.txt" {
			t.Error("deleted file initial.txt should not appear in ChangedFiles")
		}
	}
}

func TestParseLines(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty", "", 0},
		{"whitespace only", "  \n  \n  ", 0},
		{"single file", "foo.go\n", 1},
		{"multiple files", "a.go\nb.go\nc.go\n", 3},
		{"trailing newlines", "a.go\n\n\n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLines(tt.input)
			if len(got) != tt.want {
				t.Errorf("parseLines(%q) = %d items, want %d", tt.input, len(got), tt.want)
			}
		})
	}
}
