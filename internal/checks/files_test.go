package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateStatus_RejectsInvalidID(t *testing.T) {
	_, err := UpdateStatus(t.TempDir(), "../escape", StatusEnabled)
	if err == nil {
		t.Fatal("expected invalid id error")
	}
	if !strings.Contains(err.Error(), "id must match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateStatus_RejectsSymlinkedCheckFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(target, []byte("api_version: governor/v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := CheckFilePath(dir, "safe-id")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, err := UpdateStatus(dir, "safe-id", StatusEnabled)
	if err == nil {
		t.Fatal("expected symlink rejection")
	}
	if !strings.Contains(err.Error(), "symlinked check file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveReadDirs_DefaultRepoThenHome(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}

	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)

	restoreWD := setWorkingDir(t, repoRoot)
	defer restoreWD()

	dirs, err := ResolveReadDirs("")
	if err != nil {
		t.Fatalf("ResolveReadDirs failed: %v", err)
	}
	if len(dirs) != 2 {
		t.Fatalf("expected 2 dirs, got %d (%v)", len(dirs), dirs)
	}

	resolvedRepoRoot, err := FindRepoRootFromCWD()
	if err != nil {
		t.Fatalf("FindRepoRootFromCWD failed: %v", err)
	}
	if dirs[0] != filepath.Join(resolvedRepoRoot, ".governor", "checks") {
		t.Fatalf("unexpected first dir: %s", dirs[0])
	}

	resolvedHomePath, err := resolvePath("~/.governor/checks")
	if err != nil {
		t.Fatalf("resolve home path failed: %v", err)
	}
	if dirs[1] != resolvedHomePath {
		t.Fatalf("unexpected second dir: %s", dirs[1])
	}
}

func TestResolveWriteDir_DefaultRepoWhenInGitRepo(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))

	restoreWD := setWorkingDir(t, repoRoot)
	defer restoreWD()

	dir, err := ResolveWriteDir("")
	if err != nil {
		t.Fatalf("ResolveWriteDir failed: %v", err)
	}
	resolvedRepoRoot, err := FindRepoRootFromCWD()
	if err != nil {
		t.Fatalf("FindRepoRootFromCWD failed: %v", err)
	}
	want := filepath.Join(resolvedRepoRoot, ".governor", "checks")
	if dir != want {
		t.Fatalf("unexpected write dir: got %q want %q", dir, want)
	}
}

func TestResolveWriteDir_DefaultHomeWhenNotInGitRepo(t *testing.T) {
	workDir := t.TempDir()
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)

	restoreWD := setWorkingDir(t, workDir)
	defer restoreWD()

	dir, err := ResolveWriteDir("")
	if err != nil {
		t.Fatalf("ResolveWriteDir failed: %v", err)
	}
	want, err := resolvePath("~/.governor/checks")
	if err != nil {
		t.Fatalf("resolve home path failed: %v", err)
	}
	if dir != want {
		t.Fatalf("unexpected write dir: got %q want %q", dir, want)
	}
}

func TestLoadCustomDirs_RepoShadowsHomeOnDuplicateID(t *testing.T) {
	repoDir := t.TempDir()
	homeDir := t.TempDir()

	if _, err := WriteDefinition(repoDir, Definition{
		APIVersion:   APIVersion,
		ID:           "dup-check",
		Name:         "Repo Check",
		Status:       StatusEnabled,
		Source:       SourceCustom,
		Instructions: "repo instructions",
	}, false); err != nil {
		t.Fatalf("write repo check: %v", err)
	}
	if _, err := WriteDefinition(homeDir, Definition{
		APIVersion:   APIVersion,
		ID:           "dup-check",
		Name:         "Home Check",
		Status:       StatusEnabled,
		Source:       SourceCustom,
		Instructions: "home instructions",
	}, false); err != nil {
		t.Fatalf("write home check: %v", err)
	}

	defs, warnings, err := LoadCustomDirs([]string{repoDir, homeDir})
	if err != nil {
		t.Fatalf("LoadCustomDirs failed: %v", err)
	}
	if len(defs) != 1 {
		t.Fatalf("expected 1 merged check, got %d", len(defs))
	}
	if defs[0].Name != "Repo Check" {
		t.Fatalf("expected repo check to win, got %q", defs[0].Name)
	}

	foundDuplicateWarning := false
	for _, w := range warnings {
		if strings.Contains(w, "duplicate custom check id") && strings.Contains(w, "dup-check") {
			foundDuplicateWarning = true
			break
		}
	}
	if !foundDuplicateWarning {
		t.Fatalf("expected duplicate-id warning, got %v", warnings)
	}
}

func TestUpdateStatusInDirs_UsesRepoPrecedence(t *testing.T) {
	repoDir := t.TempDir()
	homeDir := t.TempDir()

	repoPath, err := WriteDefinition(repoDir, Definition{
		APIVersion:   APIVersion,
		ID:           "status-check",
		Name:         "Repo Check",
		Status:       StatusDraft,
		Source:       SourceCustom,
		Instructions: "repo instructions",
		CreatedAt:    time.Now().UTC().Add(-time.Hour),
	}, false)
	if err != nil {
		t.Fatalf("write repo check: %v", err)
	}
	homePath, err := WriteDefinition(homeDir, Definition{
		APIVersion:   APIVersion,
		ID:           "status-check",
		Name:         "Home Check",
		Status:       StatusDisabled,
		Source:       SourceCustom,
		Instructions: "home instructions",
		CreatedAt:    time.Now().UTC().Add(-time.Hour),
	}, false)
	if err != nil {
		t.Fatalf("write home check: %v", err)
	}

	updatedPath, err := UpdateStatusInDirs([]string{repoDir, homeDir}, "status-check", StatusEnabled)
	if err != nil {
		t.Fatalf("UpdateStatusInDirs failed: %v", err)
	}
	if updatedPath != repoPath {
		t.Fatalf("expected repo path update, got %q want %q", updatedPath, repoPath)
	}

	repoDef, err := ReadDefinition(repoPath)
	if err != nil {
		t.Fatalf("read repo check: %v", err)
	}
	if repoDef.Status != StatusEnabled {
		t.Fatalf("expected repo status enabled, got %s", repoDef.Status)
	}

	homeDef, err := ReadDefinition(homePath)
	if err != nil {
		t.Fatalf("read home check: %v", err)
	}
	if homeDef.Status != StatusDisabled {
		t.Fatalf("expected home status unchanged, got %s", homeDef.Status)
	}
}

func setWorkingDir(t *testing.T, path string) func() {
	t.Helper()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(path); err != nil {
		t.Fatalf("chdir %s: %v", path, err)
	}
	return func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}
}
