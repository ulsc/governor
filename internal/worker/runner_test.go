package worker

import "testing"

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
