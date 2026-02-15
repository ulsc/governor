package worker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"governor/internal/checks"
	"governor/internal/model"
	"governor/internal/progress"
	"governor/internal/safefile"
)

// --- Malformed AI Output Parsing Tests ---

func TestParseWorkerOutput_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.json")
	mustWriteWorkerTest(t, path, "")

	_, _, parsed, err := parseWorkerOutput(path)
	if parsed {
		t.Error("expected parsed=false for empty file")
	}
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestParseWorkerOutput_InvalidJSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.json")
	mustWriteWorkerTest(t, path, `{"summary": "test", "findings": [{invalid}]}`)

	_, _, parsed, err := parseWorkerOutput(path)
	if parsed {
		t.Error("expected parsed=false for invalid JSON")
	}
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseWorkerOutput_MissingFile(t *testing.T) {
	_, _, parsed, err := parseWorkerOutput("/nonexistent/path/output.json")
	if parsed {
		t.Error("expected parsed=false for missing file")
	}
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseWorkerOutput_ValidOutput(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.json")
	payload := workerOutput{
		Summary: "test summary",
		Notes:   []string{"note1"},
		Findings: []model.Finding{
			{
				ID:       "test-1",
				Title:    "Test Finding",
				Severity: "high",
				Category: "security",
				Evidence: "found issue",
			},
		},
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	mustWriteWorkerTest(t, path, string(b))

	result, _, parsed, err := parseWorkerOutput(path)
	if !parsed {
		t.Fatal("expected parsed=true for valid output")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "test summary" {
		t.Errorf("expected summary 'test summary', got %q", result.Summary)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestParseWorkerOutput_HugeFindings(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.json")

	// Create output with many findings to test memory behavior
	findings := make([]model.Finding, 500)
	for i := range findings {
		findings[i] = model.Finding{
			ID:       "test",
			Title:    strings.Repeat("A", 1000),
			Severity: "info",
			Category: "test",
			Evidence: strings.Repeat("B", 5000),
		}
	}
	payload := workerOutput{
		Summary:  "big output",
		Notes:    []string{},
		Findings: findings,
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	mustWriteWorkerTest(t, path, string(b))

	_, _, parsed, err := parseWorkerOutput(path)
	if !parsed {
		t.Error("expected parsed=true even for large output")
	}
	if err != nil {
		t.Errorf("unexpected error for large output: %v", err)
	}
}

func TestParseWorkerOutput_WithSecretsInFindings(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.json")
	payload := workerOutput{
		Summary: "found hardcoded secret token=sk_live_abcdefghijklmnopqrstuvwxyz",
		Notes:   []string{"Bearer abcdefghijklmnopqrstuvwxyz was found"},
		Findings: []model.Finding{
			{
				ID:       "secret-1",
				Title:    "Hardcoded API key: AKIAIOSFODNN7EXAMPLE",
				Severity: "critical",
				Category: "secrets",
				Evidence: "api_key = 'sk_live_abcdefghijklmnopqrstuvwxyz'",
			},
		},
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	mustWriteWorkerTest(t, path, string(b))

	result, _, parsed, err := parseWorkerOutput(path)
	if !parsed {
		t.Fatal("expected parsed=true")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Summary should be redacted
	if strings.Contains(result.Summary, "sk_live_abcdefghijklmnopqrstuvwxyz") {
		t.Error("REDACTION FAILURE: secret leaked in summary")
	}
	// Notes should be redacted
	for _, note := range result.Notes {
		if strings.Contains(note, "Bearer abcdefghijklmnopqrstuvwxyz") {
			t.Error("REDACTION FAILURE: bearer token leaked in notes")
		}
	}
	// Finding evidence should be redacted
	for _, f := range result.Findings {
		if strings.Contains(f.Evidence, "sk_live_abcdefghijklmnopqrstuvwxyz") {
			t.Error("REDACTION FAILURE: secret leaked in finding evidence")
		}
		if strings.Contains(f.Title, "AKIAIOSFODNN7EXAMPLE") {
			t.Error("REDACTION FAILURE: AWS key leaked in finding title")
		}
	}
}

// --- Finding Normalization Tests ---

func TestNormalizeFindings_EmptyInput(t *testing.T) {
	result := normalizeFindings(nil, "test-track")
	if len(result) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result))
	}
}

func TestNormalizeFindings_SetsSourceTrack(t *testing.T) {
	findings := []model.Finding{
		{Title: "test", Severity: "high"},
	}
	result := normalizeFindings(findings, "my-track")
	if len(result) != 1 {
		t.Fatal("expected 1 finding")
	}
	if result[0].SourceTrack != "my-track" {
		t.Errorf("expected SourceTrack 'my-track', got %q", result[0].SourceTrack)
	}
}

func TestNormalizeFindings_ClampsConfidence(t *testing.T) {
	findings := []model.Finding{
		{Title: "test1", Severity: "high", Confidence: -0.5},
		{Title: "test2", Severity: "high", Confidence: 1.5},
		{Title: "test3", Severity: "high", Confidence: 0.8},
	}
	result := normalizeFindings(findings, "track")
	if result[0].Confidence != 0 {
		t.Errorf("expected confidence clamped to 0, got %f", result[0].Confidence)
	}
	if result[1].Confidence != 1 {
		t.Errorf("expected confidence clamped to 1, got %f", result[1].Confidence)
	}
	if result[2].Confidence != 0.8 {
		t.Errorf("expected confidence 0.8, got %f", result[2].Confidence)
	}
}

func TestNormalizeFindings_SkipsEmptyTitles(t *testing.T) {
	findings := []model.Finding{
		{Title: "", Severity: "high"},
		{Title: "   ", Severity: "high"},
		{Title: "valid", Severity: "high"},
	}
	result := normalizeFindings(findings, "track")
	if len(result) != 1 {
		t.Errorf("expected 1 finding (only the valid one), got %d", len(result))
	}
}

func TestNormalizeSeverity_Comprehensive(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"Critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"moderate", "medium"},
		{"low", "low"},
		{"info", "info"},
		{"", "info"},
		{"unknown", "info"},
		{"  high  ", "high"},
		{"WARNING", "info"}, // not a recognized severity
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeSeverity(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// --- Auto ID Generation Tests ---

func TestAutoID_Truncation(t *testing.T) {
	longTitle := strings.Repeat("a", 100)
	id := autoID("track", longTitle)
	if len(id) > len("track-")+50 {
		t.Errorf("autoID should truncate long titles, got len=%d", len(id))
	}
}

func TestAutoID_SpecialChars(t *testing.T) {
	id := autoID("track", "Finding with / slashes")
	if strings.Contains(id, "/") {
		t.Error("autoID should replace slashes")
	}
	if strings.Contains(id, " ") {
		t.Error("autoID should replace spaces")
	}
}

// --- Concurrency Safety Tests ---

func TestRunAll_ConcurrentWorkers(t *testing.T) {
	// Test that RunAll handles concurrent execution without races
	// This test uses rule engine checks (no AI needed)
	workspace := t.TempDir()
	mustWriteWorkerTest(t, filepath.Join(workspace, "test.go"), `package main
func main() {
    // TODO: fix this
    password := "hardcoded"
    _ = password
}`)

	manifest := model.InputManifest{
		RootPath: workspace,
		Files: []model.ManifestFile{
			{Path: "test.go", Size: 100},
		},
	}

	// Create multiple rule checks
	checkDefs := make([]checks.Definition, 5)
	for i := range checkDefs {
		checkDefs[i] = checks.Definition{
			APIVersion: checks.APIVersion,
			ID:         "test-check-" + string(rune('a'+i)),
			Name:       "Test Check",
			Status:     checks.StatusEnabled,
			Source:     checks.SourceCustom,
			Engine:     checks.EngineRule,
			Rule: checks.Rule{
				Target: checks.RuleTargetFileContent,
				Detectors: []checks.RuleDetector{
					{
						ID:      "detector-1",
						Kind:    checks.RuleDetectorContains,
						Pattern: "TODO",
					},
				},
			},
		}
	}

	outDir := t.TempDir()
	results := RunAll(context.Background(), workspace, manifest, checkDefs, RunOptions{
		OutDir:      outDir,
		MaxParallel: 3,
		Timeout:     30 * time.Second,
		Sink:        progress.NoopSink{},
		Mode:        ExecutionModeSandboxed,
		SandboxMode: DefaultSandboxMode,
	})

	if len(results) != 5 {
		t.Errorf("expected 5 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Status != "success" {
			t.Errorf("check %s status=%s, expected success", r.Track, r.Status)
		}
	}
}

func TestRunAll_EmptyChecks(t *testing.T) {
	results := RunAll(context.Background(), t.TempDir(), model.InputManifest{}, nil, RunOptions{
		OutDir:      t.TempDir(),
		MaxParallel: 3,
		Timeout:     30 * time.Second,
	})
	if results != nil {
		t.Errorf("expected nil results for empty checks, got %v", results)
	}
}

func TestRunAll_ContextCancellation(t *testing.T) {
	workspace := t.TempDir()
	mustWriteWorkerTest(t, filepath.Join(workspace, "test.go"), "package main")

	manifest := model.InputManifest{
		RootPath: workspace,
		Files:    []model.ManifestFile{{Path: "test.go", Size: 12}},
	}

	checkDefs := []checks.Definition{
		{
			APIVersion: checks.APIVersion,
			ID:         "test-check",
			Name:       "Test",
			Status:     checks.StatusEnabled,
			Source:     checks.SourceCustom,
			Engine:     checks.EngineRule,
			Rule: checks.Rule{
				Target: checks.RuleTargetFileContent,
				Detectors: []checks.RuleDetector{
					{ID: "d1", Kind: checks.RuleDetectorContains, Pattern: "nonexistent-pattern"},
				},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	outDir := t.TempDir()
	results := RunAll(ctx, workspace, manifest, checkDefs, RunOptions{
		OutDir:      outDir,
		MaxParallel: 1,
		Timeout:     30 * time.Second,
		Sink:        progress.NoopSink{},
		Mode:        ExecutionModeSandboxed,
		SandboxMode: DefaultSandboxMode,
	})

	// Should still get results (may be timeout/failed)
	if len(results) == 0 {
		t.Error("expected results even with cancelled context")
	}
}

// --- Heartbeat Tests ---

func TestEmitWorkerHeartbeats_StopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sink := &countingSink{}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		emitWorkerHeartbeats(ctx, sink, "test-track", time.Now())
	}()

	deadline := time.Now().Add(9 * time.Second)
	for sink.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	wg.Wait()

	if sink.count() == 0 {
		t.Fatal("expected at least one heartbeat before timeout")
	}
}

func TestEmitWorkerHeartbeats_NilSink(t *testing.T) {
	// Should not panic
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	emitWorkerHeartbeats(ctx, nil, "test", time.Now())
}

func TestEmitWorkerHeartbeats_EmptyTrack(t *testing.T) {
	// Should return immediately
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	emitWorkerHeartbeats(ctx, progress.NoopSink{}, "", time.Now())
}

// --- Retry Logic Tests ---

func TestRetryDelay(t *testing.T) {
	tests := []struct {
		base    time.Duration
		attempt int
		max     time.Duration
	}{
		{2 * time.Second, 1, 0},
		{2 * time.Second, 2, 2 * time.Second},
		{2 * time.Second, 3, 4 * time.Second},
		{2 * time.Second, 4, 8 * time.Second},
		{2 * time.Second, 10, maxRetryBackoff},
	}
	for _, tt := range tests {
		delay := retryDelay(tt.base, tt.attempt)
		if delay > maxRetryBackoff {
			t.Errorf("retryDelay(%v, %d) = %v > max %v", tt.base, tt.attempt, delay, maxRetryBackoff)
		}
		if delay != tt.max {
			t.Errorf("retryDelay(%v, %d) = %v, want %v", tt.base, tt.attempt, delay, tt.max)
		}
	}
}

func TestRetryDelay_ZeroBase(t *testing.T) {
	if d := retryDelay(0, 5); d != 0 {
		t.Errorf("expected 0 delay for zero base, got %v", d)
	}
}

func TestRetryDelay_NegativeBase(t *testing.T) {
	if d := retryDelay(-time.Second, 5); d != 0 {
		t.Errorf("expected 0 delay for negative base, got %v", d)
	}
}

// --- Classification Tests ---

func TestClassifyCodexFailure_AllPatterns(t *testing.T) {
	tests := []struct {
		name      string
		errMsg    string
		retryable bool
		label     string
	}{
		{"sandbox restriction", "landlock error", false, "infra.sandbox_access"},
		{"sandbox blocked", "shell access is blocked by sandbox", false, "infra.sandbox_access"},
		{"tls failure", "unable to get local issuer certificate", false, "infra.tls_trust"},
		{"x509", "x509: certificate signed by unknown authority", false, "infra.tls_trust"},
		{"auth failed", "authentication failed", false, "auth.account"},
		{"401", "401 unauthorized", false, "auth.account"},
		{"403", "403 forbidden", false, "auth.account"},
		{"network unreachable", "network is unreachable", true, "infra.network"},
		{"dns failure", "temporary failure in name resolution", true, "infra.network"},
		{"connection refused", "connection refused", true, "infra.network"},
		{"stream disconnect", "stream disconnected before completion", true, "stream.transient"},
		{"empty output", "missing worker output", true, "stream.transient"},
		{"unknown error", "some random error", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := classifyCodexFailure(
				nil,
				[]byte(tt.errMsg),
				nil,
			)
			if c.Retryable != tt.retryable {
				t.Errorf("retryable=%v, want %v for %q", c.Retryable, tt.retryable, tt.errMsg)
			}
			if c.Label != tt.label {
				t.Errorf("label=%q, want %q for %q", c.Label, tt.label, tt.errMsg)
			}
		})
	}
}

func TestClassifyCodexFailure_NilInputs(t *testing.T) {
	c := classifyCodexFailure(nil, nil, nil)
	if c.Retryable || c.Label != "" {
		t.Error("expected empty classification for nil inputs")
	}
}

// --- Sleep With Context Tests ---

func TestSleepWithContext_ZeroDuration(t *testing.T) {
	ctx := context.Background()
	if !sleepWithContext(ctx, 0) {
		t.Error("expected true for zero duration")
	}
}

func TestSleepWithContext_NegativeDuration(t *testing.T) {
	ctx := context.Background()
	if !sleepWithContext(ctx, -time.Second) {
		t.Error("expected true for negative duration")
	}
}

func TestSleepWithContext_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepWithContext(ctx, time.Hour) {
		t.Error("expected false for cancelled context")
	}
}

// --- Join Error Tests ---

func TestJoinErr(t *testing.T) {
	tests := []struct {
		name  string
		base  error
		next  error
		isNil bool
	}{
		{"both nil", nil, nil, true},
		{"base nil", nil, os.ErrNotExist, false},
		{"next nil", os.ErrNotExist, nil, false},
		{"both set", os.ErrNotExist, os.ErrPermission, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := joinErr(tt.base, tt.next)
			if (result == nil) != tt.isNil {
				t.Errorf("joinErr nil=%v, want nil=%v", result == nil, tt.isNil)
			}
		})
	}
}

// --- Execution Mode Normalization Tests ---

func TestNormalizeExecutionMode_DevilEdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sandboxed", "sandboxed"},
		{"SANDBOXED", "sandboxed"},
		{"host", "host"},
		{"HOST", "host"},
		{"  sandboxed  ", "sandboxed"},
		{"", ""},
		{"invalid", ""},
		{"  HOST  ", "host"},
		{"Sandboxed", "sandboxed"},
	}
	for _, tt := range tests {
		result := normalizeExecutionMode(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeExecutionMode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestNormalizeSandboxMode_DevilEdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"read-only", "read-only"},
		{"workspace-write", "workspace-write"},
		{"danger-full-access", "danger-full-access"},
		{"READ-ONLY", "read-only"},
		{"", ""},
		{"invalid", ""},
		{" DANGER-FULL-ACCESS ", "danger-full-access"},
	}
	for _, tt := range tests {
		result := normalizeSandboxMode(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeSandboxMode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// --- Redact Worker Output Tests ---

func TestRedactWorkerOutput_RedactsAllFields(t *testing.T) {
	payload := workerOutput{
		Summary: "Found token=abcdefghijklmnopqrstuvwxyz1234",
		Notes:   []string{"Bearer abcdefghijklmnopqrstuvwxyz found in config"},
		Findings: []model.Finding{
			{
				Title:       "API key AKIAIOSFODNN7EXAMPLE found",
				Evidence:    "api_key='abcdefghijklmnopqrstuvwxyz1234'",
				Impact:      "token=abcdefghijklmnopqrstuvwxyz1234 could be exposed",
				Remediation: "Remove token=abcdefghijklmnopqrstuvwxyz1234",
			},
		},
	}

	redacted := redactWorkerOutput(payload)

	if strings.Contains(redacted.Summary, "abcdefghijklmnopqrstuvwxyz1234") {
		t.Error("summary not redacted")
	}
	for _, note := range redacted.Notes {
		if strings.Contains(note, "Bearer abcdefghijklmnopqrstuvwxyz") {
			t.Error("notes not redacted")
		}
	}
	for _, f := range redacted.Findings {
		if strings.Contains(f.Title, "AKIAIOSFODNN7EXAMPLE") {
			t.Error("finding title not redacted")
		}
		if strings.Contains(f.Evidence, "abcdefghijklmnopqrstuvwxyz1234") {
			t.Error("finding evidence not redacted")
		}
	}
}

// Helpers

type countingSink struct {
	mu sync.Mutex
	n  int
}

func (s *countingSink) Emit(e progress.Event) {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
}

func (s *countingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func mustWriteWorkerTest(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safefile.WriteFileAtomic(path, []byte(content), 0o600); err != nil {
		// Fallback to direct write if safefile fails
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
