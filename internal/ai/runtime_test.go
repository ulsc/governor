package ai

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRuntime_DefaultCodexProfile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cwd := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()

	rt, err := ResolveRuntime(ResolveOptions{})
	if err != nil {
		t.Fatalf("ResolveRuntime failed: %v", err)
	}
	if rt.Provider != ProviderCodexCLI {
		t.Fatalf("expected codex provider, got %s", rt.Provider)
	}
	if rt.Bin != "codex" {
		t.Fatalf("expected default codex bin, got %s", rt.Bin)
	}
}

func TestResolveRuntime_ProfileFromRepoOverridesBuiltins(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	repo := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()

	profilePath := filepath.Join(repo, ".governor", "ai")
	if err := os.MkdirAll(profilePath, 0o700); err != nil {
		t.Fatalf("mkdir profile path: %v", err)
	}
	content := []byte(`api_version: governor/ai/v1
profiles:
  - name: codex
    provider: codex-cli
    bin: /tmp/custom-codex
`)
	if err := os.WriteFile(filepath.Join(profilePath, "profiles.yaml"), content, 0o600); err != nil {
		t.Fatalf("write profiles.yaml: %v", err)
	}

	rt, err := ResolveRuntime(ResolveOptions{Profile: "codex"})
	if err != nil {
		t.Fatalf("ResolveRuntime failed: %v", err)
	}
	if rt.Bin != "/tmp/custom-codex" {
		t.Fatalf("expected overridden bin, got %s", rt.Bin)
	}
}

func TestResolveRuntime_RejectsUnknownProvider(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cwd := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()

	_, err = ResolveRuntime(ResolveOptions{Provider: "unknown-provider"})
	if err == nil {
		t.Fatal("expected unknown provider error")
	}
}

func TestExtractJSONObject_StripsCodeFence(t *testing.T) {
	payload, err := extractJSONObject("```json\n{\"ok\":true}\n```")
	if err != nil {
		t.Fatalf("extractJSONObject failed: %v", err)
	}
	if payload != "{\"ok\":true}" {
		t.Fatalf("unexpected payload: %s", payload)
	}
}
