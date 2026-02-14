package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFiles(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with no files: %v", err)
	}
	if cfg.AIProfile != "" {
		t.Fatalf("expected empty AIProfile, got %q", cfg.AIProfile)
	}
}

func TestLoad_GlobalOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	dir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("ai_profile: openai\nworkers: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AIProfile != "openai" {
		t.Fatalf("expected AIProfile openai, got %q", cfg.AIProfile)
	}
	if cfg.Workers == nil || *cfg.Workers != 2 {
		t.Fatalf("expected Workers 2, got %v", cfg.Workers)
	}
}

func TestLoad_LocalOverridesGlobal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	repoRoot := t.TempDir()
	restoreWD := setWorkingDir(t, repoRoot)
	defer restoreWD()

	globalDir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(globalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(globalDir, "config.yaml"), []byte("ai_profile: openai\nworkers: 2\nfail_on: medium\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	localDir := filepath.Join(repoRoot, ".governor")
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "config.yaml"), []byte("ai_profile: claude\nworkers: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AIProfile != "claude" {
		t.Fatalf("expected local AIProfile claude, got %q", cfg.AIProfile)
	}
	if cfg.Workers == nil || *cfg.Workers != 1 {
		t.Fatalf("expected local Workers 1, got %v", cfg.Workers)
	}
	if cfg.FailOn != "medium" {
		t.Fatalf("expected global FailOn medium (not overridden), got %q", cfg.FailOn)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	dir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("{{invalid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	dir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with empty file: %v", err)
	}
	if cfg.AIProfile != "" {
		t.Fatalf("expected empty config from empty file, got AIProfile=%q", cfg.AIProfile)
	}
}

func TestMerge_NilPointersSafe(t *testing.T) {
	a := Config{AIProfile: "base"}
	b := Config{}
	result := merge(a, b)
	if result.AIProfile != "base" {
		t.Fatalf("merge should not override with zero value, got %q", result.AIProfile)
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
