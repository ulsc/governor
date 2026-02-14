package ai

import (
	"errors"
	"strings"
	"testing"
	"time"
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

// ── isRetryableHTTPError ────────────────────────────────────────────

func TestIsRetryableHTTPError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		want   bool
	}{
		{"network error", errors.New("connection refused"), 0, true},
		{"429 rate limit", nil, 429, true},
		{"500 server error", nil, 500, true},
		{"502 bad gateway", nil, 502, true},
		{"503 service unavailable", nil, 503, true},
		{"400 bad request", nil, 400, false},
		{"401 unauthorized", nil, 401, false},
		{"403 forbidden", nil, 403, false},
		{"200 success", nil, 200, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRetryableHTTPError(tt.err, tt.status)
			if got != tt.want {
				t.Errorf("isRetryableHTTPError(%v, %d) = %v, want %v", tt.err, tt.status, got, tt.want)
			}
		})
	}
}

// ── parseRetryAfter ─────────────────────────────────────────────────

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"empty", "", 0},
		{"seconds", "5", 5 * time.Second},
		{"large seconds capped", "120", 30 * time.Second},
		{"zero", "0", 0},
		{"negative", "-1", 0},
		{"whitespace", "  3  ", 3 * time.Second},
		{"invalid string", "not-a-number", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRetryAfter(tt.header)
			if got != tt.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

// ── calculateBackoff ────────────────────────────────────────────────

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		name    string
		attempt int
		base    time.Duration
		want    time.Duration
	}{
		{"attempt 0", 0, time.Second, time.Second},
		{"attempt 1", 1, time.Second, 2 * time.Second},
		{"attempt 2", 2, time.Second, 4 * time.Second},
		{"attempt 3", 3, time.Second, 8 * time.Second},
		{"capped at max", 10, time.Second, 30 * time.Second},
		{"custom base", 1, 2 * time.Second, 4 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateBackoff(tt.attempt, tt.base)
			if got != tt.want {
				t.Errorf("calculateBackoff(%d, %v) = %v, want %v", tt.attempt, tt.base, got, tt.want)
			}
		})
	}
}
