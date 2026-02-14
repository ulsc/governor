package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Malicious Config File Tests ---

func TestLoad_YAMLBomb(t *testing.T) {
	// YAML "billion laughs" style expansion attack
	// Go's yaml.v3 library should handle this safely
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	dir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Anchors and aliases that could expand exponentially
	yamlBomb := `
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yamlBomb), 0o600); err != nil {
		t.Fatal(err)
	}

	// This should not panic or consume excessive memory
	// yaml.v3 handles anchors safely by default
	_, err := Load()
	if err != nil {
		t.Logf("YAML bomb handled safely with error: %v", err)
	}
	// No panic = success
}

func TestLoad_OversizedConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	dir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 10MB config file with valid YAML
	bigValue := strings.Repeat("a", 10*1024*1024)
	content := "ai_profile: " + bigValue + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Logf("Oversized config handled with error: %v", err)
		return
	}
	// If it loaded, it should have the value
	if cfg.AIProfile == "" {
		t.Error("expected non-empty AIProfile from oversized config")
	}
}

func TestLoad_MaliciousFieldValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	dir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "command injection in ai_bin",
			content: "ai_bin: \"; rm -rf / #\"\n",
		},
		{
			name:    "path traversal in checks_dir",
			content: "checks_dir: \"../../../etc\"\n",
		},
		{
			name:    "negative workers",
			content: "workers: -1\n",
		},
		{
			name:    "zero workers",
			content: "workers: 0\n",
		},
		{
			name:    "huge workers",
			content: "workers: 999999\n",
		},
		{
			name:    "null bytes in string",
			content: "ai_profile: \"test\\x00evil\"\n",
		},
		{
			name:    "newlines in profile name",
			content: "ai_profile: \"test\\nevil\"\n",
		},
		{
			name:    "negative max_bytes",
			content: "max_bytes: -1\n",
		},
		{
			name:    "overflow max_files",
			content: "max_files: 2147483648\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}

			cfg, err := Load()
			if err != nil {
				t.Logf("Malicious config handled with error: %v", err)
				return
			}
			// Config loaded - the malicious values are stored but should be
			// validated downstream by the CLI before use
			_ = cfg
		})
	}
}

func TestLoad_SymlinkedConfigFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	dir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Create a file somewhere else
	evilConfig := filepath.Join(t.TempDir(), "evil-config.yaml")
	if err := os.WriteFile(evilConfig, []byte("ai_bin: /evil/binary\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Symlink the config
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(evilConfig, configPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	// Config currently does NOT check for symlinks - this is a potential concern
	cfg, err := Load()
	if err != nil {
		t.Logf("Symlinked config handled with error: %v", err)
		return
	}
	// Document this gap: config.Load() follows symlinks without protection
	if cfg.AIBin == "/evil/binary" {
		t.Log("SECURITY NOTE: config.Load() follows symlinks. A malicious symlink at " +
			"~/.governor/config.yaml could point to an attacker-controlled file.")
	}
}

func TestMerge_AllFields(t *testing.T) {
	workers1 := 1
	workers2 := 2
	maxFiles1 := 100
	maxBytes1 := int64(1024)
	verbose := true
	noCustom := true

	a := Config{
		Workers:       &workers1,
		AIProfile:     "profile1",
		AIProvider:    "provider1",
		AIModel:       "model1",
		AIAuthMode:    "auto",
		AIBin:         "bin1",
		AIBaseURL:     "url1",
		AIAPIKeyEnv:   "env1",
		ExecutionMode: "sandboxed",
		AISandbox:     "read-only",
		MaxFiles:      &maxFiles1,
		MaxBytes:      &maxBytes1,
		Timeout:       "1m",
		Verbose:       &verbose,
		ChecksDir:     "dir1",
		NoCustom:      &noCustom,
		FailOn:        "high",
		Baseline:      "path1",
	}

	b := Config{
		Workers:   &workers2,
		AIProfile: "profile2",
	}

	result := merge(a, b)
	if result.Workers == nil || *result.Workers != 2 {
		t.Error("expected workers=2 from override")
	}
	if result.AIProfile != "profile2" {
		t.Error("expected AIProfile from override")
	}
	// Fields not overridden should remain from a
	if result.AIProvider != "provider1" {
		t.Error("expected AIProvider preserved from base")
	}
	if result.FailOn != "high" {
		t.Error("expected FailOn preserved from base")
	}
}

func TestLoad_UnknownFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	dir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	content := `
ai_profile: codex
unknown_field: "this should be silently ignored"
another_unknown:
  nested: true
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with unknown fields: %v", err)
	}
	if cfg.AIProfile != "codex" {
		t.Errorf("expected AIProfile=codex, got %q", cfg.AIProfile)
	}
}

func TestLoad_WhitespaceOnlyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, t.TempDir())
	defer restoreWD()

	dir := filepath.Join(home, ".governor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("   \n  \n  "), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with whitespace file: %v", err)
	}
	if cfg.AIProfile != "" {
		t.Errorf("expected empty config from whitespace file, got AIProfile=%q", cfg.AIProfile)
	}
}
