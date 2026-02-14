package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"governor/internal/ai"
	"governor/internal/checks"
	"governor/internal/envsafe"
	"governor/internal/model"
	"governor/internal/progress"
	"governor/internal/prompt"
	"governor/internal/redact"
	"governor/internal/safefile"
)

type RunOptions struct {
	AIRuntime    ai.Runtime
	CodexBin     string
	OutDir       string
	MaxParallel  int
	Timeout      time.Duration
	RetryCount   int
	RetryBackoff time.Duration
	Verbose      bool
	Sink         progress.Sink
	Mode         string
	SandboxMode  string

	SandboxDenyHostFallback bool
}

const (
	ExecutionModeSandboxed = "sandboxed"
	ExecutionModeHost      = "host"
	DefaultSandboxMode     = "read-only"
	defaultRetryCount      = 3
	defaultRetryBackoff    = 2 * time.Second
	maxRetryBackoff        = 15 * time.Second
)

type workerOutput struct {
	Summary  string          `json:"summary"`
	Notes    []string        `json:"notes"`
	Findings []model.Finding `json:"findings"`
}

type indexedResult struct {
	idx int
	res model.WorkerResult
}

func RunAll(ctx context.Context, workspace string, manifest model.InputManifest, checkDefs []checks.Definition, opts RunOptions) []model.WorkerResult {
	if opts.CodexBin == "" {
		opts.CodexBin = "codex"
	}
	if strings.TrimSpace(opts.AIRuntime.Provider) == "" {
		opts.AIRuntime.Provider = ai.ProviderCodexCLI
	}
	if strings.TrimSpace(opts.AIRuntime.Bin) == "" {
		opts.AIRuntime.Bin = opts.CodexBin
	}
	if strings.TrimSpace(opts.AIRuntime.ExecutionMode) == "" {
		opts.AIRuntime.ExecutionMode = opts.Mode
	}
	if strings.TrimSpace(opts.AIRuntime.SandboxMode) == "" {
		opts.AIRuntime.SandboxMode = opts.SandboxMode
	}
	if opts.Sink == nil {
		opts.Sink = progress.NoopSink{}
	}
	if len(checkDefs) == 0 {
		return nil
	}
	if opts.MaxParallel < 1 {
		opts.MaxParallel = len(checkDefs)
	}
	if opts.MaxParallel > len(checkDefs) {
		opts.MaxParallel = len(checkDefs)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 4 * time.Minute
	}
	if opts.RetryCount < 1 {
		opts.RetryCount = defaultRetryCount
	}
	if opts.RetryBackoff <= 0 {
		opts.RetryBackoff = defaultRetryBackoff
	}
	if opts.RetryBackoff > maxRetryBackoff {
		opts.RetryBackoff = maxRetryBackoff
	}
	if normalizeExecutionMode(opts.Mode) == "" {
		opts.Mode = ExecutionModeSandboxed
	}
	if normalizeSandboxMode(opts.SandboxMode) == "" {
		opts.SandboxMode = DefaultSandboxMode
	}

	schemaPath, schemaErr := writeSchema(opts.OutDir)
	results := make([]model.WorkerResult, 0, len(checkDefs))
	if schemaErr != nil {
		for _, checkDef := range checkDefs {
			res := model.WorkerResult{
				Track:       checks.NormalizeDefinition(checkDef).ID,
				Status:      "failed",
				Error:       fmt.Sprintf("write schema: %v", schemaErr),
				StartedAt:   time.Now().UTC(),
				CompletedAt: time.Now().UTC(),
			}
			opts.Sink.Emit(progress.Event{
				Type:   progress.EventWorkerFinished,
				At:     res.CompletedAt,
				Track:  res.Track,
				Status: res.Status,
				Error:  res.Error,
			})
			results = append(results, res)
		}
		return results
	}

	sem := make(chan struct{}, opts.MaxParallel)
	resCh := make(chan indexedResult, len(checkDefs))
	var wg sync.WaitGroup

	for idx, checkDef := range checkDefs {
		wg.Add(1)
		go func(idx int, checkDef checks.Definition) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resCh <- indexedResult{
				idx: idx,
				res: runOneTrack(ctx, workspace, manifest, checkDef, schemaPath, opts),
			}
		}(idx, checkDef)
	}

	wg.Wait()
	close(resCh)

	ordered := make([]model.WorkerResult, len(checkDefs))
	for item := range resCh {
		if item.idx < 0 || item.idx >= len(ordered) {
			continue
		}
		ordered[item.idx] = item.res
	}

	for _, res := range ordered {
		if strings.TrimSpace(res.Track) == "" {
			continue
		}
		results = append(results, res)
	}

	return results
}

func runOneTrack(parent context.Context, workspace string, manifest model.InputManifest, checkDef checks.Definition, schemaPath string, opts RunOptions) model.WorkerResult {
	checkDef = checks.NormalizeDefinition(checkDef)
	started := time.Now().UTC()
	ctx, cancel := context.WithTimeout(parent, opts.Timeout)
	defer cancel()

	trackName := checkDef.ID
	opts.Sink.Emit(progress.Event{
		Type:  progress.EventWorkerStarted,
		At:    started,
		Track: trackName,
	})
	heartbeatCtx, heartbeatCancel := context.WithCancel(context.Background())
	defer heartbeatCancel()
	go emitWorkerHeartbeats(heartbeatCtx, opts.Sink, trackName, started)

	logPath := filepath.Join(opts.OutDir, fmt.Sprintf("worker-%s.log", trackName))
	outputPath := filepath.Join(opts.OutDir, fmt.Sprintf("worker-%s-output.json", trackName))
	if checkDef.Engine == checks.EngineRule {
		return runRuleTrack(ctx, workspace, manifest, checkDef, opts, started, logPath, outputPath)
	}
	promptText := prompt.BuildForCheck(checkDef, manifest)
	execRes := executeTrackWithRetries(
		ctx,
		opts,
		trackName,
		workspace,
		schemaPath,
		outputPath,
		promptText,
	)
	heartbeatCancel()

	redactedLog := execRes.logBytes
	if writeErr := safefile.WriteFileAtomic(logPath, redactedLog, 0o600); writeErr != nil {
		redactedLog = append(redactedLog, []byte("\n[governor] failed to write worker log: "+writeErr.Error())...)
	}

	payload := execRes.payload
	parsedOutput := execRes.parsedOutput
	rawOutputBytes := execRes.rawOutputBytes
	err := execRes.err

	if parsedOutput {
		opts.Sink.Emit(progress.Event{
			Type:    progress.EventWorkerOutput,
			Track:   trackName,
			Message: outputPath,
		})
	}

	normalized := normalizeFindings(payload.Findings, trackName)
	completed := time.Now().UTC()
	res := model.WorkerResult{
		Track:        trackName,
		StartedAt:    started,
		CompletedAt:  completed,
		DurationMS:   completed.Sub(started).Milliseconds(),
		FindingCount: len(normalized),
		Findings:     normalized,
		RawOutput:    strings.TrimSpace(redact.Text(string(rawOutputBytes))),
		LogPath:      logPath,
		OutputPath:   outputPath,
	}
	if execRes.hostFallbackUsed {
		res.Error = redact.Text(execRes.hostFallbackMessage)
	}

	switch {
	case execRes.fallbackUsed:
		res.Status = "warning"
		res.Error = redact.Text(execRes.fallbackMessage)
	case err == nil:
		res.Status = "success"
	case parsedOutput:
		// If Codex produced valid schema-compliant JSON before the process was
		// terminated (for example by timeout), treat output as successful.
		res.Status = "success"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.Status = "timeout"
		res.Error = redact.Text(err.Error())
	case len(normalized) > 0:
		res.Status = "partial"
		res.Error = redact.Text(err.Error())
	default:
		res.Status = "failed"
		res.Error = redact.Text(err.Error())
	}

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "[governor] track=%s status=%s findings=%d duration=%dms\n", res.Track, res.Status, res.FindingCount, res.DurationMS)
	}
	opts.Sink.Emit(progress.Event{
		Type:         progress.EventWorkerFinished,
		At:           completed,
		Track:        res.Track,
		Status:       res.Status,
		FindingCount: res.FindingCount,
		DurationMS:   res.DurationMS,
		Error:        res.Error,
	})

	return res
}

func runRuleTrack(
	ctx context.Context,
	workspace string,
	manifest model.InputManifest,
	checkDef checks.Definition,
	opts RunOptions,
	started time.Time,
	logPath string,
	outputPath string,
) model.WorkerResult {
	execRes := executeRuleCheck(ctx, workspace, manifest, checkDef)
	logBytes := []byte(strings.TrimSpace(redact.Text(execRes.logText)) + "\n")
	if strings.TrimSpace(execRes.logText) == "" {
		logBytes = []byte("[governor] deterministic rule engine produced no log output\n")
	}
	if writeErr := safefile.WriteFileAtomic(logPath, logBytes, 0o600); writeErr != nil {
		logBytes = append(logBytes, []byte("\n[governor] failed to write worker log: "+writeErr.Error())...)
	}

	payload := redactWorkerOutput(execRes.payload)
	marshaled, marshalErr := json.MarshalIndent(payload, "", "  ")
	if marshalErr == nil {
		if writeErr := safefile.WriteFileAtomic(outputPath, marshaled, 0o600); writeErr != nil {
			execRes.err = joinErr(execRes.err, fmt.Errorf("write deterministic worker output: %w", writeErr))
		}
	} else {
		execRes.err = joinErr(execRes.err, fmt.Errorf("marshal deterministic worker output: %w", marshalErr))
	}

	payload, rawOutputBytes, parsedOutput, parseErr := parseWorkerOutput(outputPath)
	if parseErr != nil {
		execRes.err = joinErr(execRes.err, parseErr)
	}
	if parsedOutput {
		opts.Sink.Emit(progress.Event{
			Type:    progress.EventWorkerOutput,
			Track:   checkDef.ID,
			Message: outputPath,
		})
	}

	normalized := normalizeFindings(payload.Findings, checkDef.ID)
	completed := time.Now().UTC()
	res := model.WorkerResult{
		Track:        checkDef.ID,
		StartedAt:    started,
		CompletedAt:  completed,
		DurationMS:   completed.Sub(started).Milliseconds(),
		FindingCount: len(normalized),
		Findings:     normalized,
		RawOutput:    strings.TrimSpace(redact.Text(string(rawOutputBytes))),
		LogPath:      logPath,
		OutputPath:   outputPath,
	}

	switch {
	case execRes.err == nil:
		res.Status = "success"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.Status = "timeout"
		res.Error = redact.Text(execRes.err.Error())
	case parsedOutput:
		res.Status = "partial"
		res.Error = redact.Text(execRes.err.Error())
	default:
		res.Status = "failed"
		res.Error = redact.Text(execRes.err.Error())
	}

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "[governor] track=%s status=%s findings=%d duration=%dms\n", res.Track, res.Status, res.FindingCount, res.DurationMS)
	}
	opts.Sink.Emit(progress.Event{
		Type:         progress.EventWorkerFinished,
		At:           completed,
		Track:        res.Track,
		Status:       res.Status,
		FindingCount: res.FindingCount,
		DurationMS:   res.DurationMS,
		Error:        res.Error,
	})
	return res
}

type trackExecutionResult struct {
	payload         workerOutput
	rawOutputBytes  []byte
	parsedOutput    bool
	logBytes        []byte
	err             error
	fallbackUsed    bool
	fallbackMessage string

	hostFallbackUsed    bool
	hostFallbackMessage string
}

type codexFailureClassification struct {
	Retryable bool
	Label     string
	Message   string
}

func executeTrackWithRetries(
	ctx context.Context,
	opts RunOptions,
	trackName string,
	workspace string,
	schemaPath string,
	outputPath string,
	promptText string,
) trackExecutionResult {
	attempts := opts.RetryCount
	if attempts < 1 {
		attempts = defaultRetryCount
	}
	backoff := opts.RetryBackoff
	if backoff <= 0 {
		backoff = defaultRetryBackoff
	}
	if backoff > maxRetryBackoff {
		backoff = maxRetryBackoff
	}

	var result trackExecutionResult
	var logBuf strings.Builder
	var lastErr error
	var sawRetryableFailure bool
	lastRetryableLabel := "stream.transient"
	lastRetryableMessage := "retryable Codex transport failure"
	attempted := 0

	for attempt := 1; attempt <= attempts; attempt++ {
		attempted = attempt
		if attempt > 1 {
			delay := retryDelay(backoff, attempt)
			msg := fmt.Sprintf("retrying %s attempt %d/%d after %s", trackName, attempt, attempts, lastRetryableMessage)
			opts.Sink.Emit(progress.Event{
				Type:    progress.EventRunWarning,
				At:      time.Now().UTC(),
				Track:   trackName,
				Status:  "warning",
				Message: msg,
			})
			if !sleepWithContext(ctx, delay) {
				lastErr = joinErr(lastErr, fmt.Errorf("retry canceled by context"))
				break
			}
		}

		_ = os.Remove(outputPath)
		combinedOut, cmdErr := runCodexAttempt(ctx, opts, workspace, schemaPath, outputPath, promptText)
		appendAttemptLog(&logBuf, attempt, attempts, combinedOut, cmdErr)

		payload, rawOutputBytes, parsedOutput, parseErr := parseWorkerOutput(outputPath)
		attemptErr := joinErr(cmdErr, parseErr)
		if parsedOutput {
			if shouldHostFallbackForSandboxDeny(opts, payload, attemptErr, combinedOut) {
				msg := "[infra.sandbox_access] sandbox denied workspace access; rerunning track in host mode"
				opts.Sink.Emit(progress.Event{
					Type:    progress.EventRunWarning,
					At:      time.Now().UTC(),
					Track:   trackName,
					Status:  "warning",
					Message: msg,
				})
				appendHostFallbackLog(&logBuf, msg)

				_ = os.Remove(outputPath)
				hostOpts := opts
				hostOpts.Mode = ExecutionModeHost
				hostOpts.SandboxMode = ""
				hostOut, hostCmdErr := runCodexAttempt(ctx, hostOpts, workspace, schemaPath, outputPath, promptText)
				appendHostFallbackLogResult(&logBuf, hostOut, hostCmdErr)

				hostPayload, hostRawOutputBytes, hostParsedOutput, hostParseErr := parseWorkerOutput(outputPath)
				hostAttemptErr := joinErr(hostCmdErr, hostParseErr)
				if hostParsedOutput {
					result.payload = hostPayload
					result.rawOutputBytes = hostRawOutputBytes
					result.parsedOutput = true
					result.err = hostAttemptErr
					result.hostFallbackUsed = true
					result.hostFallbackMessage = "[infra.sandbox_access] reran in host mode after sandbox access denial"
					result.logBytes = []byte(strings.TrimSpace(logBuf.String()) + "\n")
					return result
				}

				result.rawOutputBytes = hostRawOutputBytes
				lastErr = joinErr(lastErr, fmt.Errorf("host fallback after sandbox denial: %w", hostAttemptErr))
				classification := classifyCodexFailure(hostAttemptErr, hostOut, hostRawOutputBytes)
				if classification.Retryable {
					sawRetryableFailure = true
					if strings.TrimSpace(classification.Label) != "" {
						lastRetryableLabel = classification.Label
					}
					if strings.TrimSpace(classification.Message) != "" {
						lastRetryableMessage = classification.Message
					}
				} else if strings.TrimSpace(classification.Label) != "" {
					lastErr = joinErr(lastErr, fmt.Errorf("[%s] %s", classification.Label, classification.Message))
				}
				break
			}

			result.payload = payload
			result.rawOutputBytes = rawOutputBytes
			result.parsedOutput = true
			result.err = attemptErr
			result.logBytes = []byte(strings.TrimSpace(logBuf.String()) + "\n")
			return result
		}

		result.rawOutputBytes = rawOutputBytes
		lastErr = joinErr(lastErr, fmt.Errorf("attempt %d/%d: %w", attempt, attempts, attemptErr))
		classification := classifyCodexFailure(attemptErr, combinedOut, rawOutputBytes)
		if classification.Retryable {
			sawRetryableFailure = true
			if strings.TrimSpace(classification.Label) != "" {
				lastRetryableLabel = classification.Label
			}
			if strings.TrimSpace(classification.Message) != "" {
				lastRetryableMessage = classification.Message
			}
		} else if strings.TrimSpace(classification.Label) != "" {
			lastErr = joinErr(lastErr, fmt.Errorf("[%s] %s", classification.Label, classification.Message))
		}
		retryable := classification.Retryable
		if !retryable || attempt >= attempts || ctx.Err() != nil {
			break
		}
	}

	if sawRetryableFailure && ctx.Err() == nil {
		if attempted < 1 {
			attempted = attempts
		}
		fallback := buildRetryFallbackOutput(trackName, attempted)
		fallback = redactWorkerOutput(fallback)
		b, err := json.MarshalIndent(fallback, "", "  ")
		if err == nil {
			if writeErr := safefile.WriteFileAtomic(outputPath, b, 0o600); writeErr == nil {
				result.payload = fallback
				result.rawOutputBytes = b
				result.parsedOutput = true
				result.err = nil
				result.fallbackUsed = true
				result.fallbackMessage = fmt.Sprintf("[%s] used fallback output after %d %s attempt(s)", lastRetryableLabel, attempted, lastRetryableMessage)
				result.logBytes = []byte(strings.TrimSpace(logBuf.String()) + "\n")
				return result
			} else {
				lastErr = joinErr(lastErr, fmt.Errorf("write fallback worker output: %w", writeErr))
			}
		} else {
			lastErr = joinErr(lastErr, fmt.Errorf("marshal fallback worker output: %w", err))
		}
	}

	if strings.TrimSpace(logBuf.String()) == "" {
		logBuf.WriteString("[governor] no worker log output\n")
	}
	result.logBytes = []byte(strings.TrimSpace(logBuf.String()) + "\n")
	result.err = joinErr(lastErr, ctx.Err())
	return result
}

func runCodexAttempt(
	ctx context.Context,
	opts RunOptions,
	workspace string,
	schemaPath string,
	outputPath string,
	promptText string,
) ([]byte, error) {
	runtime := opts.AIRuntime
	if strings.TrimSpace(runtime.Provider) == "" {
		runtime.Provider = ai.ProviderCodexCLI
	}
	if strings.TrimSpace(runtime.Bin) == "" {
		runtime.Bin = opts.CodexBin
	}
	if strings.TrimSpace(runtime.ExecutionMode) == "" {
		runtime.ExecutionMode = opts.Mode
	}
	if strings.TrimSpace(runtime.SandboxMode) == "" {
		runtime.SandboxMode = opts.SandboxMode
	}
	return ai.ExecuteTrack(ctx, runtime, ai.ExecutionInput{
		Workspace:  workspace,
		SchemaPath: schemaPath,
		OutputPath: outputPath,
		PromptText: promptText,
		Env:        buildWorkerEnv(os.Environ()),
	})
}

func buildCodexExecArgs(opts RunOptions, workspace string, schemaPath string, outputPath string) []string {
	args := []string{"exec", "--skip-git-repo-check"}
	switch normalizeExecutionMode(opts.Mode) {
	case ExecutionModeSandboxed:
		args = append(args, "-s", normalizeSandboxMode(opts.SandboxMode))
	case ExecutionModeHost:
		// Codex defaults to sandboxed execution when no sandbox flag is provided.
		// Force host-equivalent execution explicitly for governor's host mode.
		args = append(args, "-s", "danger-full-access")
	}
	args = append(args,
		"-C", workspace,
		"--output-schema", schemaPath,
		"-o", outputPath,
		"--color", "never",
		"-",
	)
	return args
}

func parseWorkerOutput(path string) (workerOutput, []byte, bool, error) {
	rawOutputBytes, readErr := os.ReadFile(path)
	if readErr != nil {
		return workerOutput{}, nil, false, fmt.Errorf("missing worker output: %w", readErr)
	}

	payload := workerOutput{}
	if jsonErr := json.Unmarshal(rawOutputBytes, &payload); jsonErr != nil {
		return workerOutput{}, rawOutputBytes, false, fmt.Errorf("invalid worker JSON output: %w", jsonErr)
	}

	payload = redactWorkerOutput(payload)
	redactedBytes, marshalErr := json.MarshalIndent(payload, "", "  ")
	if marshalErr == nil {
		rawOutputBytes = redactedBytes
		if writeErr := safefile.WriteFileAtomic(path, rawOutputBytes, 0o600); writeErr != nil {
			return payload, rawOutputBytes, true, fmt.Errorf("rewrite redacted worker output: %w", writeErr)
		}
		return payload, rawOutputBytes, true, nil
	}

	rawOutputBytes = []byte(redact.Text(string(rawOutputBytes)))
	if writeErr := safefile.WriteFileAtomic(path, rawOutputBytes, 0o600); writeErr != nil {
		return payload, rawOutputBytes, true, fmt.Errorf("rewrite redacted worker output fallback: %w", writeErr)
	}
	return payload, rawOutputBytes, true, nil
}

func appendAttemptLog(logBuf *strings.Builder, attempt int, attempts int, combinedOut []byte, cmdErr error) {
	if logBuf.Len() > 0 {
		logBuf.WriteString("\n")
	}
	fmt.Fprintf(logBuf, "[governor] attempt %d/%d\n", attempt, attempts)
	out := strings.TrimSpace(redact.Text(string(combinedOut)))
	if out != "" {
		logBuf.WriteString(out)
		logBuf.WriteString("\n")
	} else {
		logBuf.WriteString("[governor] no output\n")
	}
	if cmdErr != nil {
		logBuf.WriteString("[governor] command error: ")
		logBuf.WriteString(redact.Text(cmdErr.Error()))
		logBuf.WriteString("\n")
	}
}

func appendHostFallbackLog(logBuf *strings.Builder, message string) {
	if logBuf.Len() > 0 {
		logBuf.WriteString("\n")
	}
	logBuf.WriteString("[governor] host fallback attempt\n")
	logBuf.WriteString(redact.Text(strings.TrimSpace(message)))
	logBuf.WriteString("\n")
}

func appendHostFallbackLogResult(logBuf *strings.Builder, combinedOut []byte, cmdErr error) {
	out := strings.TrimSpace(redact.Text(string(combinedOut)))
	if out != "" {
		logBuf.WriteString(out)
		logBuf.WriteString("\n")
	} else {
		logBuf.WriteString("[governor] no output\n")
	}
	if cmdErr != nil {
		logBuf.WriteString("[governor] command error: ")
		logBuf.WriteString(redact.Text(cmdErr.Error()))
		logBuf.WriteString("\n")
	}
}

func retryDelay(base time.Duration, attempt int) time.Duration {
	if attempt <= 1 || base <= 0 {
		return 0
	}
	delay := base
	for i := 2; i < attempt; i++ {
		if delay >= maxRetryBackoff/2 {
			return maxRetryBackoff
		}
		delay *= 2
	}
	if delay > maxRetryBackoff {
		return maxRetryBackoff
	}
	return delay
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func classifyCodexFailure(err error, combinedOut []byte, rawOutput []byte) codexFailureClassification {
	var b strings.Builder
	if err != nil {
		b.WriteString(strings.ToLower(err.Error()))
		b.WriteString("\n")
	}
	if len(combinedOut) > 0 {
		b.WriteString(strings.ToLower(string(combinedOut)))
		b.WriteString("\n")
	}
	if len(rawOutput) > 0 {
		b.WriteString(strings.ToLower(string(rawOutput)))
	}
	text := b.String()
	if strings.TrimSpace(text) == "" {
		return codexFailureClassification{}
	}

	if hasAnyPattern(text,
		"landlock",
		"sandbox restriction",
		"sandbox restrictions",
		"shell access is blocked by sandbox",
		"repository file access was blocked",
		"blocked by sandbox",
	) {
		return codexFailureClassification{
			Retryable: false,
			Label:     "infra.sandbox_access",
			Message:   "sandbox denied repository file access for this track",
		}
	}

	if hasAnyPattern(text,
		"unable to get local issuer certificate",
		"certificate verify failed",
		"x509:",
		"unknown certificate",
		"self signed certificate",
		"tls handshake failure",
	) {
		return codexFailureClassification{
			Retryable: false,
			Label:     "infra.tls_trust",
			Message:   "TLS trust validation failed while Codex attempted HTTPS",
		}
	}

	if hasAnyPattern(text,
		"authentication failed",
		"unauthorized",
		"forbidden",
		"invalid api key",
		"run codex login",
		"no auth available",
		"401",
		"403",
	) {
		return codexFailureClassification{
			Retryable: false,
			Label:     "auth.subscription",
			Message:   "authentication is unavailable for Codex in this execution context",
		}
	}

	if hasAnyPattern(text,
		"temporary failure in name resolution",
		"network is unreachable",
		"no route to host",
		"connection refused",
		"connection reset by peer",
		"tls handshake timeout",
		"context deadline exceeded",
		"timed out",
	) {
		return codexFailureClassification{
			Retryable: true,
			Label:     "infra.network",
			Message:   "retryable Codex network failure",
		}
	}

	if hasAnyPattern(text,
		"stream disconnected before completion",
		"error sending request for url",
		"no last agent message; wrote empty content",
		"invalid worker json output: unexpected end of json input",
		"missing worker output",
	) {
		return codexFailureClassification{
			Retryable: true,
			Label:     "stream.transient",
			Message:   "retryable Codex stream failure",
		}
	}

	return codexFailureClassification{}
}

func shouldHostFallbackForSandboxDeny(opts RunOptions, payload workerOutput, attemptErr error, combinedOut []byte) bool {
	if !opts.SandboxDenyHostFallback {
		return false
	}
	if normalizeExecutionMode(opts.Mode) != ExecutionModeSandboxed {
		return false
	}

	var b strings.Builder
	b.WriteString(strings.ToLower(strings.TrimSpace(payload.Summary)))
	b.WriteString("\n")
	for _, note := range payload.Notes {
		b.WriteString(strings.ToLower(strings.TrimSpace(note)))
		b.WriteString("\n")
	}
	if attemptErr != nil {
		b.WriteString(strings.ToLower(strings.TrimSpace(attemptErr.Error())))
		b.WriteString("\n")
	}
	if len(combinedOut) > 0 {
		b.WriteString(strings.ToLower(string(combinedOut)))
	}

	return hasAnyPattern(b.String(),
		"landlock",
		"sandbox restriction",
		"sandbox restrictions",
		"shell access is blocked by sandbox",
		"repository file access was blocked",
		"all shell commands failed",
		"blocked by sandbox",
	)
}

func hasAnyPattern(text string, patterns ...string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

func buildRetryFallbackOutput(trackName string, attempts int) workerOutput {
	return workerOutput{
		Summary: fmt.Sprintf("No findings generated for %s due to retryable Codex transport failures.", trackName),
		Notes: []string{
			fmt.Sprintf("Governor retried %d time(s) after retryable Codex stream/network errors.", attempts),
			"This fallback output prevents empty or invalid worker output artifacts.",
			"Re-run this audit when Codex network connectivity is stable.",
		},
		Findings: []model.Finding{},
	}
}

func emitWorkerHeartbeats(ctx context.Context, sink progress.Sink, track string, started time.Time) {
	if sink == nil || strings.TrimSpace(track) == "" || started.IsZero() {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ts := <-ticker.C:
			at := ts.UTC()
			sink.Emit(progress.Event{
				Type:       progress.EventWorkerHeartbeat,
				At:         at,
				Track:      track,
				Status:     "running",
				DurationMS: at.Sub(started).Milliseconds(),
			})
		}
	}
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

func writeSchema(outDir string) (string, error) {
	const schema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["summary", "notes", "findings"],
  "properties": {
    "summary": {"type": "string"},
    "notes": {"type": "array", "items": {"type": "string"}},
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "title", "severity", "category", "evidence", "impact", "remediation", "file_refs", "confidence"],
        "properties": {
          "id": {"type": "string"},
          "title": {"type": "string"},
          "severity": {"type": "string"},
          "category": {"type": "string"},
          "evidence": {"type": "string"},
          "impact": {"type": "string"},
          "remediation": {"type": "string"},
          "file_refs": {"type": "array", "items": {"type": "string"}},
          "confidence": {"type": "number"}
        }
      }
    }
  }
}`

	path := filepath.Join(outDir, "worker-output-schema.json")
	if err := safefile.WriteFileAtomic(path, []byte(schema), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func normalizeFindings(in []model.Finding, track string) []model.Finding {
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		sev := normalizeSeverity(f.Severity)
		f.Severity = sev
		f.Category = strings.TrimSpace(strings.ToLower(f.Category))
		if f.Category == "" {
			f.Category = "general"
		}
		f.Title = strings.TrimSpace(f.Title)
		f.Evidence = strings.TrimSpace(f.Evidence)
		f.Impact = strings.TrimSpace(f.Impact)
		f.Remediation = strings.TrimSpace(f.Remediation)
		if f.ID == "" {
			f.ID = autoID(track, f.Title)
		}
		if f.Confidence < 0 {
			f.Confidence = 0
		}
		if f.Confidence > 1 {
			f.Confidence = 1
		}
		f.SourceTrack = track
		if len(f.FileRefs) > 0 {
			for i := range f.FileRefs {
				f.FileRefs[i] = filepath.ToSlash(strings.TrimSpace(f.FileRefs[i]))
			}
		}
		f.Title = redact.Text(f.Title)
		f.Evidence = redact.Text(f.Evidence)
		f.Impact = redact.Text(f.Impact)
		f.Remediation = redact.Text(f.Remediation)
		if f.Title == "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func redactWorkerOutput(in workerOutput) workerOutput {
	in.Summary = redact.Text(strings.TrimSpace(in.Summary))
	in.Notes = redact.Strings(in.Notes)
	if len(in.Findings) > 0 {
		findings := make([]model.Finding, 0, len(in.Findings))
		for _, f := range in.Findings {
			f.Title = redact.Text(strings.TrimSpace(f.Title))
			f.Category = strings.TrimSpace(strings.ToLower(f.Category))
			f.Evidence = redact.Text(strings.TrimSpace(f.Evidence))
			f.Impact = redact.Text(strings.TrimSpace(f.Impact))
			f.Remediation = redact.Text(strings.TrimSpace(f.Remediation))
			findings = append(findings, f)
		}
		in.Findings = findings
	}
	return in
}

func normalizeExecutionMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ExecutionModeHost:
		return ExecutionModeHost
	case ExecutionModeSandboxed:
		return ExecutionModeSandboxed
	default:
		return ""
	}
}

func normalizeSandboxMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "read-only":
		return "read-only"
	case "workspace-write":
		return "workspace-write"
	case "danger-full-access":
		return "danger-full-access"
	default:
		return ""
	}
}

func buildWorkerEnv(in []string) []string {
	return envsafe.AIEnv(in)
}

func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	case "moderate":
		return "medium"
	default:
		return "info"
	}
}

func autoID(track, title string) string {
	title = strings.ToLower(strings.TrimSpace(title))
	title = strings.ReplaceAll(title, " ", "-")
	title = strings.ReplaceAll(title, "/", "-")
	if len(title) > 50 {
		title = title[:50]
	}
	return fmt.Sprintf("%s-%s", track, title)
}

func joinErr(base error, next error) error {
	if base == nil {
		return next
	}
	if next == nil {
		return base
	}
	return fmt.Errorf("%v; %w", base, next)
}
