package envsafe

import (
	"os"
	"strings"
	"testing"
)

func TestCodexEnv_ExplicitAllowlist(t *testing.T) {
	env := CodexEnv([]string{
		"PATH=.:relative:/usr/bin:/usr/bin",
		"OPENAI_API_KEY=ok",
		"OPENAI_ADMIN_TOKEN=nope",
		"CODEX_PROFILE=dev",
		"UNRELATED_SECRET=blocked",
	})

	allowed := map[string]bool{}
	for _, kv := range env {
		allowed[kv] = true
	}

	if !allowed["PATH=/usr/bin"] {
		t.Fatal("expected PATH to be sanitized and forwarded")
	}
	if !allowed["OPENAI_API_KEY=ok"] {
		t.Fatal("expected OPENAI_API_KEY to be forwarded")
	}
	if !allowed["CODEX_PROFILE=dev"] {
		t.Fatal("expected CODEX_PROFILE to be forwarded")
	}
	if allowed["OPENAI_ADMIN_TOKEN=nope"] {
		t.Fatal("did not expect OPENAI_ADMIN_TOKEN to be forwarded")
	}
	if allowed["UNRELATED_SECRET=blocked"] {
		t.Fatal("did not expect unrelated secret variable to be forwarded")
	}
}

func TestCodexEnv_DefaultPathWhenMissing(t *testing.T) {
	env := CodexEnv([]string{"OPENAI_API_KEY=test"})
	found := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			found = true
			if strings.TrimSpace(strings.TrimPrefix(kv, "PATH=")) == "" {
				t.Fatal("expected non-empty default PATH")
			}
		}
	}
	if !found {
		t.Fatal("expected PATH to be injected")
	}
}

func TestSanitizePathValue_UsesFallbackWhenUnsafe(t *testing.T) {
	got := sanitizePathValue(".:relative:")
	if got != defaultSafePath() {
		t.Fatalf("expected safe default path, got %q", got)
	}
}

func TestSanitizePathValue_KeepsAbsoluteEntries(t *testing.T) {
	tmpDir := t.TempDir()
	abs := tmpDir + string(os.PathListSeparator) + "/usr/bin"
	got := sanitizePathValue(abs)
	if !strings.Contains(got, "/usr/bin") {
		t.Fatalf("expected sanitized path to contain /usr/bin, got %q", got)
	}
}
