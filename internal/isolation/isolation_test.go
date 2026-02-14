package isolation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"governor/internal/ai"
	"governor/internal/model"
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

func TestResolveAuthMode_AutoAccount(t *testing.T) {
	codexHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(codexHome, "auth.json"), []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mode, err := resolveAuthMode(AuthAuto, ai.Runtime{
		Provider:  ai.ProviderCodexCLI,
		APIKeyEnv: "OPENAI_API_KEY",
	}, codexHome, map[string]string{})
	if err != nil {
		t.Fatalf("resolve auth mode failed: %v", err)
	}
	if mode != AuthAccount {
		t.Fatalf("expected account, got %s", mode)
	}
}

func TestResolveAuthMode_AutoAPIKey(t *testing.T) {
	mode, err := resolveAuthMode(AuthAuto, ai.Runtime{
		Provider:  ai.ProviderOpenAICompatible,
		APIKeyEnv: "OPENAI_API_KEY",
	}, t.TempDir(), map[string]string{"OPENAI_API_KEY": "x"})
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
	}, ai.Runtime{Provider: ai.ProviderCodexCLI, APIKeyEnv: "OPENAI_API_KEY"}, AuthAccount, true)
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "OPENAI_API_KEY") {
		t.Fatalf("expected OPENAI_API_KEY to be excluded for account mode")
	}
	if !strings.Contains(joined, "HTTPS_PROXY=http://proxy.local:8080") {
		t.Fatalf("expected HTTPS_PROXY to be forwarded")
	}
	if !strings.Contains(joined, "PATH="+defaultPathInImage) {
		t.Fatalf("expected fixed PATH in environment")
	}
}

func TestBuildContainerEnv_APIKeysNotForwardedWhenAINotRequired(t *testing.T) {
	env := buildContainerEnv(map[string]string{
		"OPENAI_API_KEY": "placeholder_api_key_value",
		"CODEX_API_KEY":  "placeholder_codex_key",
		"HTTPS_PROXY":    "http://proxy.local:8080",
	}, ai.Runtime{
		Provider:  ai.ProviderOpenAICompatible,
		APIKeyEnv: "OPENAI_API_KEY",
		Profile:   "openai",
	}, AuthAPIKey, false)

	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "OPENAI_API_KEY=") {
		t.Fatalf("did not expect OPENAI_API_KEY when aiRequired=false")
	}
	if strings.Contains(joined, "CODEX_API_KEY=") {
		t.Fatalf("did not expect CODEX_API_KEY when aiRequired=false")
	}
	if !strings.Contains(joined, "HTTPS_PROXY=http://proxy.local:8080") {
		t.Fatalf("expected proxy env var to remain forwarded")
	}
	if !strings.Contains(joined, "AI_PROFILE=openai") {
		t.Fatalf("expected AI profile metadata to be forwarded")
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
	overrides := []string{"PATH=/usr/bin:/bin", "CODEX_HOME=/ai-home"}
	merged := mergeEnv(base, overrides)
	joined := strings.Join(merged, "\n")
	if !strings.Contains(joined, "PATH=/usr/bin:/bin") {
		t.Fatalf("expected overridden PATH in merged env")
	}
	if !strings.Contains(joined, "CODEX_HOME=/ai-home") {
		t.Fatalf("expected CODEX_HOME in merged env")
	}
}

func TestBuildEntrypointScript_ContainsSeedCopy(t *testing.T) {
	script := buildEntrypointScript([]string{"audit", "/input"}, true)
	if !strings.Contains(script, "/ai-seed") {
		t.Fatalf("expected seed copy logic in script")
	}
	if !strings.Contains(script, "exec 'governor' 'audit' '/input'") {
		t.Fatalf("unexpected exec command: %s", script)
	}
}

func TestBuildInnerGovernorArgs_UsesHostExecutionByDefault(t *testing.T) {
	args := buildInnerGovernorArgs(AuditOptions{
		Workers:  3,
		MaxFiles: 10,
		MaxBytes: 1000,
		Timeout:  30 * time.Second,
	}, false)

	got := strings.Join(args, " ")
	if !strings.Contains(got, "--execution-mode host") {
		t.Fatalf("expected host execution mode, got: %s", got)
	}
	if strings.Contains(got, "--ai-sandbox") {
		t.Fatalf("did not expect ai-sandbox flag in host mode, got: %s", got)
	}
	if strings.Contains(got, "--sandbox-deny-host-fallback") {
		t.Fatalf("did not expect sandbox-deny-host-fallback flag in host mode, got: %s", got)
	}
	if !strings.Contains(got, "--allow-existing-out-dir") {
		t.Fatalf("expected allow-existing-out-dir flag in isolated mode, got: %s", got)
	}
	if strings.Contains(got, "--keep-workspace-error") {
		t.Fatalf("did not expect keep-workspace-error by default, got: %s", got)
	}
}

func TestBuildInnerGovernorArgs_SandboxedEnablesHostFallbackFlag(t *testing.T) {
	args := buildInnerGovernorArgs(AuditOptions{
		Workers:       3,
		MaxFiles:      10,
		MaxBytes:      1000,
		Timeout:       30 * time.Second,
		ExecutionMode: "sandboxed",
		SandboxMode:   "read-only",
	}, false)

	got := strings.Join(args, " ")
	if !strings.Contains(got, "--ai-sandbox read-only") {
		t.Fatalf("expected read-only sandbox in isolated mode, got: %s", got)
	}
	if !strings.Contains(got, "--sandbox-deny-host-fallback") {
		t.Fatalf("expected sandbox-deny-host-fallback flag in isolated mode, got: %s", got)
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

func TestBuildInnerGovernorArgs_ForwardsZeroTimeout(t *testing.T) {
	args := buildInnerGovernorArgs(AuditOptions{
		Workers:  3,
		MaxFiles: 10,
		MaxBytes: 1000,
		Timeout:  0,
	}, false)

	got := strings.Join(args, " ")
	if !strings.Contains(got, "--timeout 0s") {
		t.Fatalf("expected explicit zero timeout forwarding, got: %s", got)
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

func TestValidateOptions_AllowsZeroTimeout(t *testing.T) {
	opts := normalizeOptions(AuditOptions{
		InputPath: "/tmp/input",
		Workers:   1,
		MaxFiles:  1,
		MaxBytes:  1,
		Timeout:   0,
	})
	if err := validateOptions(opts); err != nil {
		t.Fatalf("validate options with zero timeout failed: %v", err)
	}
}

func TestNormalizeOptions_PreservesZeroTimeout(t *testing.T) {
	opts := normalizeOptions(AuditOptions{
		InputPath: "/tmp/input",
		Timeout:   0,
	})
	if opts.Timeout != 0 {
		t.Fatalf("expected zero timeout to be preserved, got %s", opts.Timeout)
	}
}

func TestValidateOptions_RejectsNegativeTimeout(t *testing.T) {
	opts := normalizeOptions(AuditOptions{
		InputPath: "/tmp/input",
		Workers:   1,
		MaxFiles:  1,
		MaxBytes:  1,
		Timeout:   -1 * time.Second,
	})
	err := validateOptions(opts)
	if err == nil {
		t.Fatal("expected error for negative timeout")
	}
	if !strings.Contains(err.Error(), "--timeout must be >= 0") {
		t.Fatalf("unexpected error: %v", err)
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
	if opts.AuthMode != AuthAccount {
		t.Fatalf("expected default auth account, got %s", opts.AuthMode)
	}
	if opts.ExecutionMode != "host" {
		t.Fatalf("expected default execution mode host, got %s", opts.ExecutionMode)
	}
	if opts.SandboxMode != "" {
		t.Fatalf("expected default sandbox mode empty for host execution, got %s", opts.SandboxMode)
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

func TestRunPreflight_NetworkNoneSkipsProbe(t *testing.T) {
	result := runPreflight(
		t.Context(),
		"docker",
		AuditOptions{NetworkPolicy: NetworkNone},
		ai.Runtime{Provider: ai.ProviderCodexCLI},
		AuthAPIKey,
		"",
		nil,
		true,
	)

	joinedWarnings := strings.Join(result.Warnings, "\n")
	if !strings.Contains(joinedWarnings, "network policy is none") {
		t.Fatalf("expected network-none warning, got: %v", result.Warnings)
	}
}

func TestRunPreflight_DeterministicSelectionSkipsCodexProbe(t *testing.T) {
	result := runPreflight(
		t.Context(),
		"docker",
		AuditOptions{NetworkPolicy: NetworkUnrestricted},
		ai.Runtime{Provider: ai.ProviderCodexCLI},
		AuthAccount,
		"",
		nil,
		false,
	)
	if len(result.Warnings) != 0 {
		t.Fatalf("expected no warnings for deterministic-only preflight, got %v", result.Warnings)
	}
	joinedNotes := strings.Join(result.Notes, "\n")
	if !strings.Contains(joinedNotes, "deterministic only") {
		t.Fatalf("expected deterministic-only note, got %v", result.Notes)
	}
}

func TestIsolateSelectionRequiresAI_OnlyPromptInjectionBuiltin(t *testing.T) {
	required, warnings, err := isolateSelectionRequiresAI(AuditOptions{
		NoCustomChecks: true,
		OnlyChecks:     []string{"prompt_injection"},
	})
	if err != nil {
		t.Fatalf("isolateSelectionRequiresAI failed: %v", err)
	}
	if required {
		t.Fatal("expected prompt_injection-only selection to not require codex")
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
}

func TestParseEndpointProbeOutput_WithPrefixLogs(t *testing.T) {
	raw := []byte("[governor] debug line\n{\"dns_ok\":true,\"https_ok\":true,\"status\":401,\"error\":\"\"}")
	got, err := parseEndpointProbeOutput(raw)
	if err != nil {
		t.Fatalf("parse probe output failed: %v", err)
	}
	if !got.DNSOK || !got.HTTPSOK || got.Status != 401 {
		t.Fatalf("unexpected parsed result: %+v", got)
	}
}

func TestParseCodexProbeOutput_WithPrefixLogs(t *testing.T) {
	raw := []byte("[governor] debug line\n{\"ok\":false,\"exit_code\":2,\"has_ca_bundle\":false,\"stdout\":\"\",\"stderr\":\"certificate verify failed\"}")
	got, err := parseCodexProbeOutput(raw)
	if err != nil {
		t.Fatalf("parse codex probe output failed: %v", err)
	}
	if got.OK || got.ExitCode != 2 || got.HasCABundle {
		t.Fatalf("unexpected parsed codex probe result: %+v", got)
	}
}

func TestClassifyCodexProbeFailure_TLS(t *testing.T) {
	label, reason := classifyCodexProbeFailure(codexProbeResult{
		OK:       false,
		ExitCode: 2,
		Stderr:   "certificate verify failed: unable to get local issuer certificate",
	})
	if label != "infra.tls_trust" {
		t.Fatalf("expected infra.tls_trust label, got %q", label)
	}
	if !strings.Contains(strings.ToLower(reason), "tls trust") {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestClassifyCodexProbeFailure_Auth(t *testing.T) {
	label, _ := classifyCodexProbeFailure(codexProbeResult{
		OK:       false,
		ExitCode: 2,
		Stderr:   "ERROR: unauthorized 401",
	})
	if label != "auth.account" {
		t.Fatalf("expected auth.account label, got %q", label)
	}
}

func TestClassifyCodexProbeFailure_Stream(t *testing.T) {
	label, _ := classifyCodexProbeFailure(codexProbeResult{
		OK:       false,
		ExitCode: 2,
		Stderr:   "ERROR: stream disconnected before completion",
	})
	if label != "stream.transient" {
		t.Fatalf("expected stream.transient label, got %q", label)
	}
}

// ── shellQuote ──────────────────────────────────────────────────────

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "''"},
		{"simple", "hello", "'hello'"},
		{"with single quotes", "it's", `'it'"'"'s'`},
		{"special chars", "foo bar;baz", "'foo bar;baz'"},
		{"backslash", `a\b`, `'a\b'`},
		{"newline", "a\nb", "'a\nb'"},
		{"dollar sign", "$HOME", "'$HOME'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.in)
			if got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ── shellJoin ───────────────────────────────────────────────────────

func TestShellJoin(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"empty slice", nil, ""},
		{"single element", []string{"hello"}, "'hello'"},
		{"multiple elements", []string{"a", "b c", "d"}, "'a' 'b c' 'd'"},
		{"elements with quotes", []string{"it's", "fine"}, `'it'"'"'s' 'fine'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellJoin(tt.in)
			if got != tt.want {
				t.Errorf("shellJoin(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ── envToMap ────────────────────────────────────────────────────────

func TestEnvToMap(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want map[string]string
	}{
		{"valid pairs", []string{"A=1", "B=2"}, map[string]string{"A": "1", "B": "2"}},
		{"value with equals", []string{"A=1=2=3"}, map[string]string{"A": "1=2=3"}},
		{"no equals skipped", []string{"INVALID", "A=1"}, map[string]string{"A": "1"}},
		{"empty key skipped", []string{"=value"}, map[string]string{}},
		{"duplicates last wins", []string{"A=1", "A=2"}, map[string]string{"A": "2"}},
		{"empty slice", nil, map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := envToMap(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("envToMap() len = %d, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("envToMap()[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// ── normalizeExecutionMode ──────────────────────────────────────────

func TestNormalizeExecutionMode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"sandboxed", "sandboxed"},
		{"host", "host"},
		{"  SANDBOXED  ", "sandboxed"},
		{"  Host  ", "host"},
		{"invalid", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := normalizeExecutionMode(tt.in)
			if got != tt.want {
				t.Errorf("normalizeExecutionMode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ── normalizeSandboxMode ────────────────────────────────────────────

func TestNormalizeSandboxMode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"read-only", "read-only"},
		{"workspace-write", "workspace-write"},
		{"danger-full-access", "danger-full-access"},
		{"  READ-ONLY  ", "read-only"},
		{"  Workspace-Write  ", "workspace-write"},
		{"invalid", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := normalizeSandboxMode(tt.in)
			if got != tt.want {
				t.Errorf("normalizeSandboxMode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ── sanitizeErr ─────────────────────────────────────────────────────

func TestSanitizeErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"simple", errors.New("oops"), "oops"},
		{"newlines", errors.New("line1\nline2\rline3"), "line1 line2 line3"},
		{"empty message", errors.New(""), "unknown error"},
		{"whitespace only", errors.New("   "), "unknown error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeErr(tt.err)
			if got != tt.want {
				t.Errorf("sanitizeErr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeErr_Truncation(t *testing.T) {
	long := strings.Repeat("x", 400)
	got := sanitizeErr(errors.New(long))
	if len(got) != 303 { // 300 + "..."
		t.Errorf("expected truncation to 303 chars, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected ... suffix, got %q", got[len(got)-10:])
	}
}

// ── hasAnyPattern ───────────────────────────────────────────────────

func TestHasAnyPattern(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		patterns []string
		want     bool
	}{
		{"match first", "certificate verify failed", []string{"certificate verify failed", "timeout"}, true},
		{"match second", "connection timed out", []string{"certificate", "timed out"}, true},
		{"no match", "everything is fine", []string{"error", "failed"}, false},
		{"empty text", "", []string{"something"}, false},
		{"empty patterns", "text", nil, false},
		{"case sensitive", "ERROR", []string{"error"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAnyPattern(tt.text, tt.patterns...)
			if got != tt.want {
				t.Errorf("hasAnyPattern(%q, %v) = %v, want %v", tt.text, tt.patterns, got, tt.want)
			}
		})
	}
}

// ── isLikelyLocalBaseURL ────────────────────────────────────────────

func TestIsLikelyLocalBaseURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://localhost:8080", true},
		{"http://127.0.0.1:11434", true},
		{"https://api.openai.com", false},
		{"", false},
		{"   ", false},
		{"http://localhost", true},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := isLikelyLocalBaseURL(tt.url)
			if got != tt.want {
				t.Errorf("isLikelyLocalBaseURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

// ── extractTrailingJSON ─────────────────────────────────────────────

func TestExtractTrailingJSON(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		want    string
		wantErr bool
	}{
		{"simple json", []byte(`{"ok":true}`), `{"ok":true}`, false},
		{"prefix logs", []byte("[governor] debug\n{\"ok\":true}"), `{"ok":true}`, false},
		{"no json", []byte("just text"), "", true},
		{"empty", []byte(""), "", true},
		{"trailing json after logs", []byte("log line\n{\"status\":\"ok\",\"count\":5}"), `{"status":"ok","count":5}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractTrailingJSON(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("extractTrailingJSON() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAppendWarningsToAuditArtifacts_AppendsDedupedWarnings(t *testing.T) {
	outDir := t.TempDir()
	jsonPath := filepath.Join(outDir, "audit.json")

	initial := model.AuditReport{
		Findings:         []model.Finding{},
		CountsBySeverity: map[string]int{},
		CountsByCategory: map[string]int{},
	}
	b, err := json.Marshal(initial)
	if err != nil {
		t.Fatalf("marshal initial report: %v", err)
	}
	if err := os.WriteFile(jsonPath, b, 0o600); err != nil {
		t.Fatalf("write initial audit.json: %v", err)
	}

	err = appendWarningsToAuditArtifacts(outDir, []string{
		"stream probe warning",
		"stream probe warning",
		"  ",
		"network warning",
	})
	if err != nil {
		t.Fatalf("append warnings failed: %v", err)
	}

	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read updated audit.json: %v", err)
	}
	var got model.AuditReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal updated report: %v", err)
	}
	if len(got.Errors) != 2 {
		t.Fatalf("expected 2 unique warnings, got %d (%v)", len(got.Errors), got.Errors)
	}
	if got.Errors[0] != "stream probe warning" || got.Errors[1] != "network warning" {
		t.Fatalf("unexpected warning order/content: %v", got.Errors)
	}

	for _, path := range []string{
		filepath.Join(outDir, "audit.md"),
		filepath.Join(outDir, "audit.html"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected rendered artifact %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Fatalf("expected non-empty rendered artifact %s", path)
		}
	}
}
