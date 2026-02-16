package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func initHooksTestRepo(t *testing.T) string {
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
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "f.txt")
	run("commit", "-m", "init")
	return dir
}

func TestHooksInstallAndRemove(t *testing.T) {
	dir := initHooksTestRepo(t)
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// Install.
	if err := runHooks([]string{"install"}); err != nil {
		t.Fatalf("hooks install: %v", err)
	}

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}
	if !strings.Contains(string(content), hookMarkerStart) {
		t.Fatal("hook should contain governor marker")
	}
	if !strings.Contains(string(content), "governor audit --staged --quick --fail-on high") {
		t.Fatal("hook should contain governor audit command")
	}

	// Install again (should be idempotent).
	if err := runHooks([]string{"install"}); err != nil {
		t.Fatalf("hooks install (idempotent): %v", err)
	}

	// Remove.
	if err := runHooks([]string{"remove"}); err != nil {
		t.Fatalf("hooks remove: %v", err)
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatal("hook file should be removed")
	}
}

func TestHooksInstallRefusesExisting(t *testing.T) {
	dir := initHooksTestRepo(t)
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// Create a non-governor hook.
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho custom"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := runHooks([]string{"install"})
	if err == nil {
		t.Fatal("expected error when hook exists without --force")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected 'already exists' error, got: %v", err)
	}
}

func TestHooksInstallForce(t *testing.T) {
	dir := initHooksTestRepo(t)
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// Create a non-governor hook.
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho custom"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Install with --force.
	if err := runHooks([]string{"install", "--force"}); err != nil {
		t.Fatalf("hooks install --force: %v", err)
	}
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), hookMarkerStart) {
		t.Fatal("hook should contain governor marker after --force")
	}
}

func TestHooksRemoveNonGovernorHook(t *testing.T) {
	dir := initHooksTestRepo(t)
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// Create a non-governor hook.
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho custom"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := runHooks([]string{"remove"})
	if err == nil {
		t.Fatal("expected error when removing non-governor hook")
	}
	if !strings.Contains(err.Error(), "not installed by governor") {
		t.Fatalf("expected 'not installed by governor' error, got: %v", err)
	}
}

func TestHooksStatusNotInstalled(t *testing.T) {
	dir := initHooksTestRepo(t)
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if err := runHooks([]string{"status"}); err != nil {
		t.Fatalf("hooks status: %v", err)
	}
}

func TestHooksStatusInstalled(t *testing.T) {
	dir := initHooksTestRepo(t)
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if err := runHooks([]string{"install"}); err != nil {
		t.Fatalf("hooks install: %v", err)
	}
	if err := runHooks([]string{"status"}); err != nil {
		t.Fatalf("hooks status: %v", err)
	}
}

func TestHooksUnknownSubcommand(t *testing.T) {
	err := runHooks([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error for unknown hooks subcommand")
	}
}

func TestHooksNoSubcommand(t *testing.T) {
	err := runHooks(nil)
	if err == nil {
		t.Fatal("expected error for no hooks subcommand")
	}
}
