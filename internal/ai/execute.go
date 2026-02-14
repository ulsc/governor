package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"governor/internal/envsafe"
	"governor/internal/safefile"
)

type ExecutionInput struct {
	Workspace  string
	SchemaPath string
	OutputPath string
	PromptText string
	Env        []string
}

func ExecuteTrack(ctx context.Context, runtime Runtime, input ExecutionInput) ([]byte, error) {
	runtime = normalizeRuntime(runtime)
	switch runtime.Provider {
	case ProviderCodexCLI:
		return executeCodexCLI(ctx, runtime, input)
	case ProviderOpenAICompatible:
		return executeOpenAICompatible(ctx, runtime, input)
	default:
		return nil, fmt.Errorf("unsupported ai provider %q", runtime.Provider)
	}
}

func buildCodexExecArgs(runtime Runtime, input ExecutionInput) []string {
	args := []string{"exec", "--skip-git-repo-check"}
	mode := strings.ToLower(strings.TrimSpace(runtime.ExecutionMode))
	sandbox := strings.ToLower(strings.TrimSpace(runtime.SandboxMode))
	switch mode {
	case "host":
		args = append(args, "-s", "danger-full-access")
	default:
		if sandbox == "" {
			sandbox = "read-only"
		}
		args = append(args, "-s", sandbox)
	}
	args = append(args,
		"-C", input.Workspace,
		"--output-schema", input.SchemaPath,
		"-o", input.OutputPath,
		"--color", "never",
		"-",
	)
	return args
}

func executeCodexCLI(ctx context.Context, runtime Runtime, input ExecutionInput) ([]byte, error) {
	args := buildCodexExecArgs(runtime, input)
	cmd := exec.CommandContext(ctx, runtime.Bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = strings.NewReader(input.PromptText)
	cmd.Env = envsafe.AIEnv(input.Env)
	cmdDone := make(chan struct{})
	defer close(cmdDone)
	go func() {
		select {
		case <-ctx.Done():
			killCommandProcessGroup(cmd)
		case <-cmdDone:
		}
	}()
	return cmd.CombinedOutput()
}

type openAIChatCompletionsRequest struct {
	Model          string                `json:"model"`
	Messages       []openAIChatMessage   `json:"messages"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
	Temperature    float64               `json:"temperature,omitempty"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponseFormat struct {
	Type       string            `json:"type"`
	JSONSchema openAIJSONSchema  `json:"json_schema"`
}

type openAIJSONSchema struct {
	Name   string `json:"name"`
	Strict bool   `json:"strict"`
	Schema any    `json:"schema"`
}

type openAIChatCompletionsResponse struct {
	Choices []struct {
		Message struct {
			Content any `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    any    `json:"code"`
	} `json:"error,omitempty"`
}

func executeOpenAICompatible(ctx context.Context, runtime Runtime, input ExecutionInput) ([]byte, error) {
	apiKey, includeAuth, err := resolveAPIKey(runtime)
	if err != nil {
		return nil, err
	}

	schemaData, err := os.ReadFile(input.SchemaPath)
	if err != nil {
		return nil, fmt.Errorf("read output schema: %w", err)
	}
	var schemaObj any
	if err := json.Unmarshal(schemaData, &schemaObj); err != nil {
		return nil, fmt.Errorf("parse output schema: %w", err)
	}

	reqBody := openAIChatCompletionsRequest{
		Model: runtime.Model,
		Messages: []openAIChatMessage{
			{
				Role: "system",
				Content: "Return only JSON that conforms to the provided schema. Do not wrap JSON in markdown fences.",
			},
			{
				Role:    "user",
				Content: input.PromptText,
			},
		},
		ResponseFormat: &openAIResponseFormat{
			Type: "json_schema",
			JSONSchema: openAIJSONSchema{
				Name:   "governor_worker_output",
				Strict: true,
				Schema: schemaObj,
			},
		},
		Temperature: 0,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal ai request: %w", err)
	}

	endpoint, err := joinURLPath(runtime.BaseURL, "/chat/completions")
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build ai request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if includeAuth {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	for k, v := range runtime.Headers {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		httpReq.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("execute ai request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read ai response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		reason := strings.TrimSpace(string(respBody))
		if reason == "" {
			reason = "empty response body"
		}
		if len(reason) > 1000 {
			reason = reason[:1000] + "..."
		}
		return respBody, fmt.Errorf("ai provider returned HTTP %d: %s", resp.StatusCode, reason)
	}

	parsed := openAIChatCompletionsResponse{}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return respBody, fmt.Errorf("parse ai response: %w", err)
	}
	if parsed.Error != nil && strings.TrimSpace(parsed.Error.Message) != "" {
		return respBody, fmt.Errorf("ai provider error: %s", strings.TrimSpace(parsed.Error.Message))
	}
	if len(parsed.Choices) == 0 {
		return respBody, fmt.Errorf("ai response has no choices")
	}

	content := extractMessageContent(parsed.Choices[0].Message.Content)
	if strings.TrimSpace(content) == "" {
		return respBody, fmt.Errorf("ai response message content is empty")
	}

	jsonPayload, err := extractJSONObject(content)
	if err != nil {
		return respBody, fmt.Errorf("extract json from ai response: %w", err)
	}

	var out any
	if err := json.Unmarshal([]byte(jsonPayload), &out); err != nil {
		return respBody, fmt.Errorf("parse ai json payload: %w", err)
	}
	pretty, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return respBody, fmt.Errorf("format ai json payload: %w", err)
	}
	if err := safefile.WriteFileAtomic(input.OutputPath, pretty, 0o600); err != nil {
		return respBody, fmt.Errorf("write ai output: %w", err)
	}

	return respBody, nil
}

func resolveAPIKey(runtime Runtime) (apiKey string, includeAuth bool, err error) {
	apiKey = strings.TrimSpace(os.Getenv(runtime.APIKeyEnv))
	switch runtime.AuthMode {
	case AuthAccount:
		if runtime.UsesOpenAICompatibleAPI() {
			return "", false, fmt.Errorf("auth mode %q is not supported for provider %q", AuthAccount, runtime.Provider)
		}
		return apiKey, apiKey != "", nil
	case AuthAPIKey:
		if apiKey == "" {
			return "", false, fmt.Errorf("api-key auth selected but %s is empty", runtime.APIKeyEnv)
		}
		return apiKey, true, nil
	case AuthAuto:
		if apiKey == "" {
			return "", false, nil
		}
		return apiKey, true, nil
	default:
		return "", false, fmt.Errorf("unsupported ai auth mode %q", runtime.AuthMode)
	}
}

func extractMessageContent(raw any) string {
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		var b strings.Builder
		for _, item := range v {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if txt, ok := obj["text"].(string); ok {
				b.WriteString(txt)
				continue
			}
			if txt, ok := obj["content"].(string); ok {
				b.WriteString(txt)
			}
		}
		return strings.TrimSpace(b.String())
	default:
		return ""
	}
}

func extractJSONObject(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty content")
	}

	if strings.HasPrefix(raw, "```") {
		raw = strings.TrimPrefix(raw, "```")
		raw = strings.TrimSpace(raw)
		if idx := strings.IndexByte(raw, '\n'); idx >= 0 {
			raw = strings.TrimSpace(raw[idx+1:])
		}
		raw = strings.TrimSuffix(raw, "```")
		raw = strings.TrimSpace(raw)
	}

	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end < 0 || end < start {
		return "", errors.New("content does not contain a json object")
	}
	candidate := strings.TrimSpace(raw[start : end+1])
	if candidate == "" {
		return "", errors.New("empty json candidate")
	}
	return candidate, nil
}

func joinURLPath(base string, suffix string) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", fmt.Errorf("ai base URL cannot be empty")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse ai base URL %q: %w", base, err)
	}
	suffix = "/" + strings.TrimLeft(strings.TrimSpace(suffix), "/")
	u.Path = strings.TrimRight(u.Path, "/") + suffix
	return u.String(), nil
}

func killCommandProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
