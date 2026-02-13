package isolation

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveRuntimeWithLookPath_AutoPrefersDocker(t *testing.T) {
	look := func(bin string) (string, error) {
		if bin == "docker" {
			return "/usr/bin/docker", nil
		}
		return "", errors.New("not found")
	}
	got, err := resolveRuntimeWithLookPath(RuntimeAuto, look)
	if err != nil {
		t.Fatalf("resolve runtime failed: %v", err)
	}
	if got != "docker" {
		t.Fatalf("expected docker, got %s", got)
	}
}

func TestResolveRuntimeWithLookPath_AutoFallsBackPodman(t *testing.T) {
	look := func(bin string) (string, error) {
		if bin == "podman" {
			return "/usr/bin/podman", nil
		}
		return "", errors.New("not found")
	}
	got, err := resolveRuntimeWithLookPath(RuntimeAuto, look)
	if err != nil {
		t.Fatalf("resolve runtime failed: %v", err)
	}
	if got != "podman" {
		t.Fatalf("expected podman, got %s", got)
	}
}

func TestResolveAuthMode_AutoSubscription(t *testing.T) {
	codexHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(codexHome, "auth.json"), []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mode, err := resolveAuthMode(AuthAuto, codexHome, map[string]string{})
	if err != nil {
		t.Fatalf("resolve auth mode failed: %v", err)
	}
	if mode != AuthSubscription {
		t.Fatalf("expected subscription, got %s", mode)
	}
}

func TestResolveAuthMode_AutoAPIKey(t *testing.T) {
	mode, err := resolveAuthMode(AuthAuto, t.TempDir(), map[string]string{"OPENAI_API_KEY": "x"})
	if err != nil {
		t.Fatalf("resolve auth mode failed: %v", err)
	}
	if mode != AuthAPIKey {
		t.Fatalf("expected api-key, got %s", mode)
	}
}

func TestStageSubscriptionBundle_CopiesMinimalFiles(t *testing.T) {
	codexHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(codexHome, "auth.json"), []byte("auth"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte("cfg"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexHome, "history.jsonl"), []byte("history"), 0o600); err != nil {
		t.Fatal(err)
	}

	seed := filepath.Join(t.TempDir(), "seed")
	out, err := stageSubscriptionBundle(codexHome, seed)
	if err != nil {
		t.Fatalf("stage bundle failed: %v", err)
	}
	if out != seed {
		t.Fatalf("unexpected seed path: %s", out)
	}

	if _, err := os.Stat(filepath.Join(seed, "auth.json")); err != nil {
		t.Fatalf("expected staged file auth.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(seed, "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("config.toml should not be staged by default")
	}
	if _, err := os.Stat(filepath.Join(seed, "history.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("history.jsonl should not be staged")
	}
}

func TestBuildContainerEnv_SubscriptionDoesNotForwardAPIKeys(t *testing.T) {
	env := buildContainerEnv(map[string]string{
		"OPENAI_API_KEY": "secret",
		"HTTPS_PROXY":    "http://proxy.local:8080",
	}, AuthSubscription)
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "OPENAI_API_KEY") {
		t.Fatalf("expected OPENAI_API_KEY to be excluded for subscription mode")
	}
	if !strings.Contains(joined, "HTTPS_PROXY=http://proxy.local:8080") {
		t.Fatalf("expected HTTPS_PROXY to be forwarded")
	}
	if !strings.Contains(joined, "PATH="+defaultPathInImage) {
		t.Fatalf("expected fixed PATH in environment")
	}
}

func TestEnvNames_StripsValues(t *testing.T) {
	in := []string{
		"OPENAI_API_KEY=secret-value",
		"HTTPS_PROXY=http://proxy.local:8080",
		"PATH=/usr/bin",
	}
	names := envNames(in)
	joined := strings.Join(names, "\n")
	if strings.Contains(joined, "=") {
		t.Fatalf("expected env names without values, got %q", joined)
	}
	for _, key := range []string{"OPENAI_API_KEY", "HTTPS_PROXY", "PATH"} {
		if !strings.Contains(joined, key) {
			t.Fatalf("expected env key %s in names", key)
		}
	}
}

func TestMergeEnv_OverridesValues(t *testing.T) {
	base := []string{"PATH=/bin", "HOME=/tmp/home"}
	overrides := []string{"PATH=/usr/bin:/bin", "CODEX_HOME=/codex-home"}
	merged := mergeEnv(base, overrides)
	joined := strings.Join(merged, "\n")
	if !strings.Contains(joined, "PATH=/usr/bin:/bin") {
		t.Fatalf("expected overridden PATH in merged env")
	}
	if !strings.Contains(joined, "CODEX_HOME=/codex-home") {
		t.Fatalf("expected CODEX_HOME in merged env")
	}
}

func TestBuildEntrypointScript_ContainsSeedCopy(t *testing.T) {
	script := buildEntrypointScript([]string{"audit", "/input"}, true)
	if !strings.Contains(script, "/codex-seed") {
		t.Fatalf("expected seed copy logic in script")
	}
	if !strings.Contains(script, "exec 'governor' 'audit' '/input'") {
		t.Fatalf("unexpected exec command: %s", script)
	}
}

func TestBuildInnerGovernorArgs_UsesSandboxedExecutionByDefault(t *testing.T) {
	args := buildInnerGovernorArgs(AuditOptions{
		Workers:  3,
		MaxFiles: 10,
		MaxBytes: 1000,
		Timeout:  30 * time.Second,
	}, false)

	got := strings.Join(args, " ")
	if !strings.Contains(got, "--execution-mode sandboxed") {
		t.Fatalf("expected sandboxed execution mode, got: %s", got)
	}
	if !strings.Contains(got, "--codex-sandbox read-only") {
		t.Fatalf("expected read-only sandbox in isolated mode, got: %s", got)
	}
	if !strings.Contains(got, "--allow-existing-out-dir") {
		t.Fatalf("expected allow-existing-out-dir flag in isolated mode, got: %s", got)
	}
	if strings.Contains(got, "--keep-workspace-error") {
		t.Fatalf("did not expect keep-workspace-error by default, got: %s", got)
	}
}

func TestBuildInnerGovernorArgs_ForwardsKeepWorkspaceError(t *testing.T) {
	args := buildInnerGovernorArgs(AuditOptions{
		Workers:              3,
		MaxFiles:             10,
		MaxBytes:             1000,
		Timeout:              30 * time.Second,
		KeepWorkspaceOnError: true,
	}, false)

	got := strings.Join(args, " ")
	if !strings.Contains(got, "--keep-workspace-error") {
		t.Fatalf("expected keep-workspace-error flag, got: %s", got)
	}
}

func TestValidateOptions_AllowsEmptyOutDir(t *testing.T) {
	opts := normalizeOptions(AuditOptions{
		InputPath: "/tmp/input",
		Workers:   1,
		MaxFiles:  1,
		MaxBytes:  1,
		Timeout:   time.Second,
	})
	if err := validateOptions(opts); err != nil {
		t.Fatalf("validate options failed: %v", err)
	}
}

func TestNormalizeOptions_HardenedDefaults(t *testing.T) {
	opts := normalizeOptions(AuditOptions{
		InputPath: "/tmp/input",
	})
	if opts.NetworkPolicy != NetworkNone {
		t.Fatalf("expected default network none, got %s", opts.NetworkPolicy)
	}
	if opts.PullPolicy != PullNever {
		t.Fatalf("expected default pull never, got %s", opts.PullPolicy)
	}
	if opts.AuthMode != AuthSubscription {
		t.Fatalf("expected default auth subscription, got %s", opts.AuthMode)
	}
	if opts.ExecutionMode != "sandboxed" {
		t.Fatalf("expected default execution mode sandboxed, got %s", opts.ExecutionMode)
	}
	if opts.SandboxMode != "read-only" {
		t.Fatalf("expected default sandbox mode read-only, got %s", opts.SandboxMode)
	}
}

func TestValidateImagePolicy_RequiresDigestWhenPulling(t *testing.T) {
	err := validateImagePolicy("ghcr.io/example/governor-runner:latest", PullAlways)
	if err == nil {
		t.Fatal("expected digest-pinning error for pull always")
	}
	if !strings.Contains(err.Error(), "digest pinned") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateImagePolicy_AllowsDigestWhenPulling(t *testing.T) {
	err := validateImagePolicy("ghcr.io/example/governor-runner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PullIfMissing)
	if err != nil {
		t.Fatalf("expected digest image to pass: %v", err)
	}
}

func TestResolveOutDir_Default(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()

	now := time.Date(2026, 2, 13, 20, 48, 18, 0, time.UTC)
	got, err := resolveOutDir("", now)
	if err != nil {
		t.Fatalf("resolve out dir: %v", err)
	}
	base := tmp
	if resolved, err := filepath.EvalSymlinks(tmp); err == nil {
		base = resolved
	}
	want := filepath.Join(base, ".governor", "runs", "20260213-204818")
	if got != want {
		t.Fatalf("unexpected out dir: got %q want %q", got, want)
	}
}

func TestResolveOutDir_ExplicitPath(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()

	got, err := resolveOutDir("my-output", time.Now().UTC())
	if err != nil {
		t.Fatalf("resolve out dir: %v", err)
	}
	base := tmp
	if resolved, err := filepath.EvalSymlinks(tmp); err == nil {
		base = resolved
	}
	want := filepath.Join(base, "my-output")
	if got != want {
		t.Fatalf("unexpected out dir: got %q want %q", got, want)
	}
}
