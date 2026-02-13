package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"governor/internal/app"
	"governor/internal/checks"
	"governor/internal/model"
)

func TestPrintAuditSummary_IncludesHTMLPath(t *testing.T) {
	report := model.AuditReport{
		RunMetadata: model.RunMetadata{
			RunID:         "20260213-123456",
			EnabledChecks: 2,
			BuiltInChecks: 2,
			CustomChecks:  0,
		},
	}
	paths := app.ArtifactPaths{
		RunDir:       "/tmp/run",
		MarkdownPath: "/tmp/run/audit.md",
		JSONPath:     "/tmp/run/audit.json",
		HTMLPath:     "/tmp/run/audit.html",
	}

	out := captureStdout(t, func() {
		printAuditSummary(report, paths)
	})

	if !strings.Contains(out, "audit html:     /tmp/run/audit.html") {
		t.Fatalf("expected summary to include HTML artifact path, got:\n%s", out)
	}
}

func TestResolveIsolateOutDir_Default(t *testing.T) {
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
	got, err := resolveIsolateOutDir("", now)
	if err != nil {
		t.Fatalf("resolve isolate out dir: %v", err)
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

func TestResolveIsolateOutDir_ExplicitPath(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()

	got, err := resolveIsolateOutDir("my-output", time.Now().UTC())
	if err != nil {
		t.Fatalf("resolve isolate out dir: %v", err)
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

func TestPrintIsolateAuditSummaryFromHost_UsesHostPaths(t *testing.T) {
	outDir := t.TempDir()
	report := model.AuditReport{
		RunMetadata: model.RunMetadata{
			RunID:         "20260213-123456",
			EnabledChecks: 3,
			BuiltInChecks: 3,
			CustomChecks:  0,
		},
		CountsBySeverity: map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"info":     0,
		},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "audit.json"), raw, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	out := captureStdout(t, func() {
		if err := printIsolateAuditSummaryFromHost(outDir); err != nil {
			t.Fatalf("print isolate summary: %v", err)
		}
	})

	if !strings.Contains(out, "artifacts dir:  "+outDir) {
		t.Fatalf("expected host artifacts dir in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "audit markdown: "+filepath.Join(outDir, "audit.md")) {
		t.Fatalf("expected host markdown path in summary, got:\n%s", out)
	}
}

func TestPrintUsage_IncludesKeepWorkspaceErrorFlag(t *testing.T) {
	out := captureStdout(t, func() {
		printUsage()
	})

	if !strings.Contains(out, "--keep-workspace-error") {
		t.Fatalf("expected usage to include keep-workspace-error flag, got:\n%s", out)
	}
}

func TestRunChecksStatus_DefaultPrefersRepoCheck(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o700); err != nil {
		t.Fatalf("create .git dir: %v", err)
	}
	homeRoot := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", homeRoot)

	repoChecks := filepath.Join(repoRoot, ".governor", "checks")
	homeChecks := filepath.Join(homeRoot, ".governor", "checks")

	if _, err := checks.WriteDefinition(repoChecks, checks.Definition{
		APIVersion:   checks.APIVersion,
		ID:           "status-check",
		Name:         "Repo",
		Status:       checks.StatusDraft,
		Source:       checks.SourceCustom,
		Instructions: "repo",
	}, false); err != nil {
		t.Fatalf("write repo check: %v", err)
	}
	if _, err := checks.WriteDefinition(homeChecks, checks.Definition{
		APIVersion:   checks.APIVersion,
		ID:           "status-check",
		Name:         "Home",
		Status:       checks.StatusDisabled,
		Source:       checks.SourceCustom,
		Instructions: "home",
	}, false); err != nil {
		t.Fatalf("write home check: %v", err)
	}

	restoreWD := setWorkingDir(t, repoRoot)
	defer restoreWD()

	_ = captureStdout(t, func() {
		if err := runChecksStatus([]string{"status-check"}, checks.StatusEnabled); err != nil {
			t.Fatalf("runChecksStatus failed: %v", err)
		}
	})

	repoDef, err := checks.ReadDefinition(filepath.Join(repoChecks, "status-check.check.yaml"))
	if err != nil {
		t.Fatalf("read repo check: %v", err)
	}
	if repoDef.Status != checks.StatusEnabled {
		t.Fatalf("expected repo check enabled, got %s", repoDef.Status)
	}

	homeDef, err := checks.ReadDefinition(filepath.Join(homeChecks, "status-check.check.yaml"))
	if err != nil {
		t.Fatalf("read home check: %v", err)
	}
	if homeDef.Status != checks.StatusDisabled {
		t.Fatalf("expected home check unchanged, got %s", homeDef.Status)
	}
}

func TestRunChecksStatus_DefaultNotFoundIncludesAllDirs(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o700); err != nil {
		t.Fatalf("create .git dir: %v", err)
	}
	homeRoot := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", homeRoot)

	restoreWD := setWorkingDir(t, repoRoot)
	defer restoreWD()

	err := runChecksStatus([]string{"missing-check"}, checks.StatusEnabled)
	if err == nil {
		t.Fatal("expected missing-check error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "missing-check") || !strings.Contains(msg, "not found in:") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(msg, filepath.Join(repoRoot, ".governor", "checks")) {
		t.Fatalf("expected repo checks dir in error: %v", err)
	}
	if !strings.Contains(msg, filepath.Join(homeRoot, ".governor", "checks")) {
		t.Fatalf("expected home checks dir in error: %v", err)
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

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	out := <-done
	_ = r.Close()

	return out
}
