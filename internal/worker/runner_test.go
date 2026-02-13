package worker

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeExecutionMode(t *testing.T) {
	if got := normalizeExecutionMode("sandboxed"); got != ExecutionModeSandboxed {
		t.Fatalf("expected sandboxed, got %q", got)
	}
	if got := normalizeExecutionMode("host"); got != ExecutionModeHost {
		t.Fatalf("expected host, got %q", got)
	}
	if got := normalizeExecutionMode("invalid"); got != "" {
		t.Fatalf("expected empty for invalid mode, got %q", got)
	}
}

func TestBuildWorkerEnv_Allowlist(t *testing.T) {
	env := buildWorkerEnv([]string{
		"PATH=/usr/bin",
		"HOME=/tmp/home",
		"OPENAI_API_KEY=test-secret",
		"OPENAI_ADMIN_TOKEN=should-not-pass",
		"UNRELATED_SECRET=should-not-pass",
	})

	foundPath := false
	foundOpenAI := false
	foundOpenAIAdmin := false
	foundUnrelated := false
	for _, kv := range env {
		switch kv {
		case "PATH=/usr/bin":
			foundPath = true
		case "OPENAI_API_KEY=test-secret":
			foundOpenAI = true
		case "OPENAI_ADMIN_TOKEN=should-not-pass":
			foundOpenAIAdmin = true
		case "UNRELATED_SECRET=should-not-pass":
			foundUnrelated = true
		}
	}
	if !foundPath {
		t.Fatal("expected PATH to be included")
	}
	if !foundOpenAI {
		t.Fatal("expected OPENAI_API_KEY to be included")
	}
	if foundOpenAIAdmin {
		t.Fatal("did not expect OPENAI_ADMIN_TOKEN in worker env")
	}
	if foundUnrelated {
		t.Fatal("did not expect unrelated secret variable in worker env")
	}
}

func TestRetryDelay_ExponentialBackoff(t *testing.T) {
	base := 2 * time.Second
	if got := retryDelay(base, 1); got != 0 {
		t.Fatalf("attempt 1 should have no delay, got %s", got)
	}
	if got := retryDelay(base, 2); got != 2*time.Second {
		t.Fatalf("attempt 2 should have base delay, got %s", got)
	}
	if got := retryDelay(base, 3); got != 4*time.Second {
		t.Fatalf("attempt 3 should double delay, got %s", got)
	}
	if got := retryDelay(base, 10); got != maxRetryBackoff {
		t.Fatalf("delay should cap at maxRetryBackoff, got %s", got)
	}
}

func TestIsRetryableStreamFailure_MatchesKnownPatterns(t *testing.T) {
	err := errors.New("stream disconnected before completion")
	if !isRetryableStreamFailure(err, nil, nil) {
		t.Fatal("expected stream disconnection error to be retryable")
	}
	log := []byte("ERROR: no last agent message; wrote empty content to output")
	if !isRetryableStreamFailure(nil, log, nil) {
		t.Fatal("expected empty-content warning to be retryable")
	}
	raw := []byte(`{"bad_json":`)
	if !isRetryableStreamFailure(errors.New("invalid worker json output: unexpected end of json input"), nil, raw) {
		t.Fatal("expected truncated JSON parse failure to be retryable")
	}
}

func TestIsRetryableStreamFailure_DoesNotMatchUnrelatedErrors(t *testing.T) {
	if isRetryableStreamFailure(errors.New("permission denied"), nil, nil) {
		t.Fatal("did not expect unrelated errors to be retryable")
	}
}

func TestBuildStreamFallbackOutput(t *testing.T) {
	out := buildStreamFallbackOutput("appsec", 3)
	if len(out.Findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(out.Findings))
	}
	if !strings.Contains(strings.ToLower(out.Summary), "transient codex stream failures") {
		t.Fatalf("unexpected summary: %s", out.Summary)
	}
	if len(out.Notes) == 0 {
		t.Fatal("expected fallback notes")
	}
}
