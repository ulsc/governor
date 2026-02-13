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

	"governor/internal/checks"
	"governor/internal/envsafe"
	"governor/internal/model"
	"governor/internal/progress"
	"governor/internal/prompt"
	"governor/internal/redact"
	"governor/internal/safefile"
)

type RunOptions struct {
	CodexBin    string
	OutDir      string
	MaxParallel int
	Timeout     time.Duration
	Verbose     bool
	Sink        progress.Sink
	Mode        string
	SandboxMode string
}

const (
	ExecutionModeSandboxed = "sandboxed"
	ExecutionModeHost      = "host"
	DefaultSandboxMode     = "read-only"
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
	promptText := prompt.BuildForCheck(checkDef, manifest)

	args := []string{"exec", "--skip-git-repo-check"}
	if normalizeExecutionMode(opts.Mode) == ExecutionModeSandboxed {
		args = append(args, "-s", normalizeSandboxMode(opts.SandboxMode))
	}
	args = append(args,
		"-C", workspace,
		"--output-schema", schemaPath,
		"-o", outputPath,
		"--color", "never",
		"-",
	)
	cmd := exec.CommandContext(ctx, opts.CodexBin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = strings.NewReader(promptText)
	cmd.Env = buildWorkerEnv(os.Environ())
	cmdDone := make(chan struct{})
	defer close(cmdDone)
	go func() {
		select {
		case <-ctx.Done():
			killCommandProcessGroup(cmd)
		case <-cmdDone:
		}
	}()
	combinedOut, err := cmd.CombinedOutput()
	heartbeatCancel()
	redactedLog := []byte(redact.Text(string(combinedOut)))

	if writeErr := safefile.WriteFileAtomic(logPath, redactedLog, 0o600); writeErr != nil {
		redactedLog = append(redactedLog, []byte("\n[governor] failed to write worker log: "+writeErr.Error())...)
	}

	payload := workerOutput{}
	parsedOutput := false
	rawOutputBytes, readErr := os.ReadFile(outputPath)
	if readErr == nil {
		if jsonErr := json.Unmarshal(rawOutputBytes, &payload); jsonErr != nil {
			err = joinErr(err, fmt.Errorf("invalid worker JSON output: %w", jsonErr))
		} else {
			payload = redactWorkerOutput(payload)
			redactedBytes, marshalErr := json.MarshalIndent(payload, "", "  ")
			if marshalErr == nil {
				rawOutputBytes = redactedBytes
				if writeErr := safefile.WriteFileAtomic(outputPath, rawOutputBytes, 0o600); writeErr != nil {
					err = joinErr(err, fmt.Errorf("rewrite redacted worker output: %w", writeErr))
				}
			} else {
				rawOutputBytes = []byte(redact.Text(string(rawOutputBytes)))
				if writeErr := safefile.WriteFileAtomic(outputPath, rawOutputBytes, 0o600); writeErr != nil {
					err = joinErr(err, fmt.Errorf("rewrite redacted worker output fallback: %w", writeErr))
				}
			}
			parsedOutput = true
			opts.Sink.Emit(progress.Event{
				Type:    progress.EventWorkerOutput,
				Track:   trackName,
				Message: outputPath,
			})
		}
	} else {
		err = joinErr(err, fmt.Errorf("missing worker output: %w", readErr))
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

	switch {
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
	return envsafe.CodexEnv(in)
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
