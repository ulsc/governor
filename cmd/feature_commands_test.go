package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"governor/internal/checks"
	"governor/internal/suppress"
	"governor/internal/taps"
)

func TestRunDoctor_StrictMode(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o700); err != nil {
		t.Fatalf("create .git dir: %v", err)
	}
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)
	t.Setenv("OPENAI_API_KEY", "test-key")

	govDir := filepath.Join(repoRoot, ".governor")
	if err := os.MkdirAll(govDir, 0o700); err != nil {
		t.Fatalf("mkdir .governor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(govDir, "config.yaml"), []byte("ai_profile: openai\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := checks.WriteDefinition(filepath.Join(govDir, "checks"), checks.Definition{
		APIVersion:   checks.APIVersion,
		ID:           "doctor-warning",
		Name:         "Doctor Warning",
		Status:       checks.StatusEnabled,
		Source:       checks.SourceCustom,
		Instructions: "short",
	}, false); err != nil {
		t.Fatalf("write check: %v", err)
	}

	restoreWD := setWorkingDir(t, repoRoot)
	defer restoreWD()

	if err := runDoctor(nil); err != nil {
		t.Fatalf("expected doctor to pass in non-strict mode: %v", err)
	}

	err := runDoctor([]string{"--strict"})
	if err == nil {
		t.Fatal("expected strict mode to fail")
	}
	if !strings.Contains(err.Error(), "strict mode failed") {
		t.Fatalf("unexpected strict error: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runDoctor([]string{"--json"}); err != nil {
			t.Fatalf("doctor json failed: %v", err)
		}
	})
	if !strings.Contains(out, "\"checks\"") {
		t.Fatalf("expected json output, got:\n%s", out)
	}
}

func TestRunChecksLockAndInstallPack(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o700); err != nil {
		t.Fatalf("create .git dir: %v", err)
	}
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, repoRoot)
	defer restoreWD()

	tapRoot := filepath.Join(home, "tap-src")
	packDir := filepath.Join(tapRoot, "packs", "web")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		t.Fatalf("mkdir pack dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "pack.yaml"), []byte("name: web\nversion: 1.0.0\ndescription: web checks\n"), 0o644); err != nil {
		t.Fatalf("write pack meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "web.check.yaml"), []byte("id: web-check\n"), 0o644); err != nil {
		t.Fatalf("write check: %v", err)
	}

	cfg := &taps.Config{Taps: []taps.Tap{{
		Name: "acme/checks",
		URL:  "https://example.com/acme/checks.git",
		Path: tapRoot,
	}}}
	if err := taps.SaveConfig(taps.DefaultConfigPath(), cfg); err != nil {
		t.Fatalf("save taps config: %v", err)
	}

	if err := runChecksLock(nil); err != nil {
		t.Fatalf("runChecksLock failed: %v", err)
	}
	lock, err := taps.LoadLock(taps.DefaultLockPath())
	if err != nil {
		t.Fatalf("load lock: %v", err)
	}
	if len(lock.Packs) != 1 || lock.Packs[0].Name != "web" {
		t.Fatalf("unexpected lock packs: %+v", lock.Packs)
	}

	if err := runChecksInstallPack([]string{"web"}); err != nil {
		t.Fatalf("runChecksInstallPack failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoRoot, ".governor", "checks", "web.check.yaml")); err != nil {
		t.Fatalf("expected installed check file: %v", err)
	}
}

func TestRunChecksUpdatePacksMajorGate(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o700); err != nil {
		t.Fatalf("create .git dir: %v", err)
	}
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)
	restoreWD := setWorkingDir(t, repoRoot)
	defer restoreWD()

	tapRoot := filepath.Join(home, "tap-src")
	packDir := filepath.Join(tapRoot, "packs", "api")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		t.Fatalf("mkdir pack dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "pack.yaml"), []byte("name: api\nversion: 1.0.0\n"), 0o644); err != nil {
		t.Fatalf("write pack meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "api.check.yaml"), []byte("id: api-check\n"), 0o644); err != nil {
		t.Fatalf("write check: %v", err)
	}

	cfg := &taps.Config{Taps: []taps.Tap{{Name: "acme/checks", URL: "https://example.com/acme/checks.git", Path: tapRoot}}}
	if err := taps.SaveConfig(taps.DefaultConfigPath(), cfg); err != nil {
		t.Fatalf("save taps config: %v", err)
	}
	if err := runChecksLock(nil); err != nil {
		t.Fatalf("runChecksLock failed: %v", err)
	}

	if err := os.WriteFile(filepath.Join(packDir, "pack.yaml"), []byte("name: api\nversion: 2.0.0\n"), 0o644); err != nil {
		t.Fatalf("update pack meta: %v", err)
	}

	if err := runChecksUpdatePacks(nil); err != nil {
		t.Fatalf("runChecksUpdatePacks without --major failed: %v", err)
	}
	lock, err := taps.LoadLock(taps.DefaultLockPath())
	if err != nil {
		t.Fatalf("load lock: %v", err)
	}
	if got := lock.Packs[0].Version; got != "1.0.0" {
		t.Fatalf("expected version to remain 1.0.0, got %s", got)
	}

	if err := runChecksUpdatePacks([]string{"--major"}); err != nil {
		t.Fatalf("runChecksUpdatePacks --major failed: %v", err)
	}
	lock, err = taps.LoadLock(taps.DefaultLockPath())
	if err != nil {
		t.Fatalf("reload lock: %v", err)
	}
	if got := lock.Packs[0].Version; got != "2.0.0" {
		t.Fatalf("expected version 2.0.0, got %s", got)
	}
}

func TestRunFindingsUnsuppressAndPrune(t *testing.T) {
	repoRoot := t.TempDir()
	restoreWD := setWorkingDir(t, repoRoot)
	defer restoreWD()

	path := filepath.Join(repoRoot, ".governor", "suppressions.yaml")
	rules := []suppress.Rule{
		{Check: "auth", Reason: "temporary", Expires: "2020-01-01"},
		{Check: "secrets", Reason: "fixture", Expires: "not-a-date"},
		{Check: "appsec", Reason: "validated"},
	}
	if err := suppress.Save(path, rules); err != nil {
		t.Fatalf("save suppressions: %v", err)
	}

	if err := runFindingsUnsuppress([]string{"--check", "appsec", "--suppressions", path}); err != nil {
		t.Fatalf("runFindingsUnsuppress failed: %v", err)
	}
	loaded, err := suppress.Load(path)
	if err != nil {
		t.Fatalf("load suppressions: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 suppressions after unsuppress, got %d", len(loaded))
	}

	err = runFindingsPrune([]string{"--suppressions", path})
	if err == nil {
		t.Fatal("expected prune preview to return error")
	}
	if !strings.Contains(err.Error(), "preview") {
		t.Fatalf("unexpected prune preview error: %v", err)
	}

	if err := runFindingsPrune([]string{"--yes", "--suppressions", path}); err != nil {
		t.Fatalf("runFindingsPrune --yes failed: %v", err)
	}
	loaded, err = suppress.Load(path)
	if err != nil {
		t.Fatalf("reload suppressions: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("expected all remaining suppressions pruned, got %d", len(loaded))
	}
}
