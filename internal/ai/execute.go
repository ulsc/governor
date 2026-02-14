package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"governor/internal/envsafe"
	"governor/internal/safefile"
)

const (
	httpMaxRetries = 3
	httpBaseBackoff = 1 * time.Second
	httpMaxBackoff  = 30 * time.Second
	httpClientTimeout = 90 * time.Second
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
	cmd.SysProcAttr = sysProcAttr()
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

	respBody, statusCode, err := doOpenAIHTTPRequestWithRetry(ctx, endpoint, bodyBytes, apiKey, includeAuth, runtime.Headers)
	if err != nil {
		return respBody, err
	}
	_ = statusCode

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

func doOpenAIHTTPRequestWithRetry(
	ctx context.Context,
	endpoint string,
	bodyBytes []byte,
	apiKey string,
	includeAuth bool,
	headers map[string]string,
) ([]byte, int, error) {
	client := &http.Client{Timeout: httpClientTimeout}
	var lastBody []byte
	var lastErr error

	for attempt := 0; attempt <= httpMaxRetries; attempt++ {
		if attempt > 0 {
			if err := ctx.Err(); err != nil {
				return lastBody, 0, fmt.Errorf("ai request cancelled before retry: %w", err)
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, 0, fmt.Errorf("build ai request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")
		if includeAuth {
			httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		}
		for k, v := range headers {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if k == "" || v == "" {
				continue
			}
			httpReq.Header.Set(k, v)
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("execute ai request: %w", err)
			if !isRetryableHTTPError(err, 0) || attempt >= httpMaxRetries {
				return nil, 0, lastErr
			}
			sleepWithJitter(ctx, calculateBackoff(attempt, httpBaseBackoff))
			continue
		}

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		_ = resp.Body.Close()
		if err != nil {
			return nil, resp.StatusCode, fmt.Errorf("read ai response: %w", err)
		}
		lastBody = respBody

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return respBody, resp.StatusCode, nil
		}

		reason := strings.TrimSpace(string(respBody))
		if reason == "" {
			reason = "empty response body"
		}
		if len(reason) > 1000 {
			reason = reason[:1000] + "..."
		}
		lastErr = fmt.Errorf("ai provider returned HTTP %d: %s", resp.StatusCode, reason)

		if !isRetryableHTTPError(nil, resp.StatusCode) || attempt >= httpMaxRetries {
			return respBody, resp.StatusCode, lastErr
		}

		backoff := calculateBackoff(attempt, httpBaseBackoff)
		if resp.StatusCode == 429 {
			if retryAfter := parseRetryAfter(resp.Header.Get("Retry-After")); retryAfter > 0 {
				backoff = retryAfter
			}
		}
		sleepWithJitter(ctx, backoff)
	}
	return lastBody, 0, lastErr
}

func isRetryableHTTPError(err error, statusCode int) bool {
	if err != nil {
		return true // network errors are retryable
	}
	if statusCode == 429 {
		return true // rate limited
	}
	if statusCode >= 500 {
		return true // server errors
	}
	return false
}

func parseRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil && secs > 0 {
		d := time.Duration(secs) * time.Second
		if d > httpMaxBackoff {
			d = httpMaxBackoff
		}
		return d
	}
	if t, err := time.Parse(time.RFC1123, header); err == nil {
		d := time.Until(t)
		if d <= 0 {
			return 0
		}
		if d > httpMaxBackoff {
			d = httpMaxBackoff
		}
		return d
	}
	return 0
}

func calculateBackoff(attempt int, base time.Duration) time.Duration {
	backoff := base
	for i := 0; i < attempt; i++ {
		backoff *= 2
	}
	if backoff > httpMaxBackoff {
		backoff = httpMaxBackoff
	}
	return backoff
}

func sleepWithJitter(ctx context.Context, d time.Duration) {
	// Add ±10% jitter
	jitter := time.Duration(float64(d) * (0.9 + rand.Float64()*0.2))
	select {
	case <-ctx.Done():
	case <-time.After(jitter):
	}
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

