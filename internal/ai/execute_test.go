package ai

import (
	"strings"
	"testing"
)

// ── extractMessageContent ───────────────────────────────────────────

func TestExtractMessageContent_String(t *testing.T) {
	got := extractMessageContent("  hello world  ")
	if got != "hello world" {
		t.Errorf("expected trimmed string, got %q", got)
	}
}

func TestExtractMessageContent_ArrayOfText(t *testing.T) {
	input := []any{
		map[string]any{"text": "hello "},
		map[string]any{"text": "world"},
	}
	got := extractMessageContent(input)
	if got != "hello world" {
		t.Errorf("expected 'hello world', got %q", got)
	}
}

func TestExtractMessageContent_ArrayOfContent(t *testing.T) {
	input := []any{
		map[string]any{"content": "hello"},
	}
	got := extractMessageContent(input)
	if got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}
}

func TestExtractMessageContent_Nil(t *testing.T) {
	got := extractMessageContent(nil)
	if got != "" {
		t.Errorf("expected empty string for nil, got %q", got)
	}
}

func TestExtractMessageContent_EmptyArray(t *testing.T) {
	got := extractMessageContent([]any{})
	if got != "" {
		t.Errorf("expected empty string for empty array, got %q", got)
	}
}

func TestExtractMessageContent_NonMapItems(t *testing.T) {
	input := []any{"not a map", 42, nil}
	got := extractMessageContent(input)
	if got != "" {
		t.Errorf("expected empty string for non-map items, got %q", got)
	}
}

func TestExtractMessageContent_Integer(t *testing.T) {
	got := extractMessageContent(42)
	if got != "" {
		t.Errorf("expected empty string for integer, got %q", got)
	}
}

// ── extractJSONObject ───────────────────────────────────────────────

func TestExtractJSONObject_Simple(t *testing.T) {
	got, err := extractJSONObject(`{"key": "value"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != `{"key": "value"}` {
		t.Errorf("unexpected result: %q", got)
	}
}

func TestExtractJSONObject_MarkdownFences(t *testing.T) {
	input := "```json\n{\"key\": \"value\"}\n```"
	got, err := extractJSONObject(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != `{"key": "value"}` {
		t.Errorf("unexpected result: %q", got)
	}
}

func TestExtractJSONObject_TextBeforeAndAfter(t *testing.T) {
	input := "Here is the result:\n{\"findings\": []}\nDone."
	got, err := extractJSONObject(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != `{"findings": []}` {
		t.Errorf("unexpected result: %q", got)
	}
}

func TestExtractJSONObject_NoBraces(t *testing.T) {
	_, err := extractJSONObject("no json here")
	if err == nil {
		t.Error("expected error for no braces")
	}
}

func TestExtractJSONObject_Empty(t *testing.T) {
	_, err := extractJSONObject("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestExtractJSONObject_WhitespaceOnly(t *testing.T) {
	_, err := extractJSONObject("   \n\t  ")
	if err == nil {
		t.Error("expected error for whitespace-only input")
	}
}

// ── joinURLPath ─────────────────────────────────────────────────────

func TestJoinURLPath(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		suffix  string
		want    string
		wantErr bool
	}{
		{"simple", "https://api.openai.com", "/chat/completions", "https://api.openai.com/chat/completions", false},
		{"trailing slash", "https://api.openai.com/", "/chat/completions", "https://api.openai.com/chat/completions", false},
		{"base with path", "https://api.openai.com/v1", "/chat/completions", "https://api.openai.com/v1/chat/completions", false},
		{"empty base", "", "/chat/completions", "", true},
		{"localhost", "http://127.0.0.1:11434/v1", "/chat/completions", "http://127.0.0.1:11434/v1/chat/completions", false},
		{"whitespace base", "  https://api.openai.com  ", "/chat/completions", "https://api.openai.com/chat/completions", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := joinURLPath(tt.base, tt.suffix)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("joinURLPath(%q, %q) = %q, want %q", tt.base, tt.suffix, got, tt.want)
			}
		})
	}
}

// ── buildCodexExecArgs ──────────────────────────────────────────────

func TestBuildCodexExecArgs_SandboxedReadOnly(t *testing.T) {
	args := buildCodexExecArgs(Runtime{
		ExecutionMode: "sandboxed",
		SandboxMode:   "read-only",
	}, ExecutionInput{
		Workspace:  "/work",
		SchemaPath: "/schema.json",
		OutputPath: "/output.json",
	})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-s read-only") {
		t.Errorf("expected read-only sandbox, got: %s", joined)
	}
	if !strings.Contains(joined, "-C /work") {
		t.Errorf("expected workspace binding, got: %s", joined)
	}
}

func TestBuildCodexExecArgs_WorkspaceWrite(t *testing.T) {
	args := buildCodexExecArgs(Runtime{
		ExecutionMode: "sandboxed",
		SandboxMode:   "workspace-write",
	}, ExecutionInput{
		Workspace:  "/work",
		SchemaPath: "/schema.json",
		OutputPath: "/output.json",
	})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-s workspace-write") {
		t.Errorf("expected workspace-write sandbox, got: %s", joined)
	}
}

func TestBuildCodexExecArgs_HostMode(t *testing.T) {
	args := buildCodexExecArgs(Runtime{
		ExecutionMode: "host",
	}, ExecutionInput{
		Workspace:  "/work",
		SchemaPath: "/schema.json",
		OutputPath: "/output.json",
	})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-s danger-full-access") {
		t.Errorf("expected danger-full-access for host mode, got: %s", joined)
	}
}

func TestBuildCodexExecArgs_EmptyMode(t *testing.T) {
	args := buildCodexExecArgs(Runtime{}, ExecutionInput{
		Workspace:  "/work",
		SchemaPath: "/schema.json",
		OutputPath: "/output.json",
	})
	joined := strings.Join(args, " ")
	// Default should be read-only
	if !strings.Contains(joined, "-s read-only") {
		t.Errorf("expected default read-only sandbox, got: %s", joined)
	}
}

func TestBuildCodexExecArgs_AlwaysHasSkipGitRepoCheck(t *testing.T) {
	args := buildCodexExecArgs(Runtime{}, ExecutionInput{
		Workspace:  "/work",
		SchemaPath: "/schema.json",
		OutputPath: "/output.json",
	})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--skip-git-repo-check") {
		t.Errorf("expected --skip-git-repo-check flag, got: %s", joined)
	}
}
