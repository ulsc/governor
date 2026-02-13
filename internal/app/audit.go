package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"governor/internal/checks"
	"governor/internal/intake"
	"governor/internal/model"
	"governor/internal/progress"
	"governor/internal/prompt"
	"governor/internal/redact"
	reportpkg "governor/internal/report"
	"governor/internal/worker"
)

type AuditOptions struct {
	InputPath     string
	OutDir        string
	CodexBin      string
	CodexVersion  string
	CodexSHA256   string
	CodexRequest  string
	Workers       int
	MaxFiles      int
	MaxBytes      int64
	Timeout       time.Duration
	Verbose       bool
	ExecutionMode string
	SandboxMode   string
	Progress      progress.Sink
	ChecksDir     string

	NoCustomChecks bool
	OnlyChecks     []string
	SkipChecks     []string
}

type ArtifactPaths struct {
	RunDir       string
	ManifestPath string
	JSONPath     string
	MarkdownPath string
	HTMLPath     string
}

func RunAudit(ctx context.Context, opts AuditOptions) (report model.AuditReport, paths ArtifactPaths, err error) {
	sink := opts.Progress
	if sink == nil {
		sink = progress.NoopSink{}
	}

	started := time.Now().UTC()
	runID := started.Format("20060102-150405")
	sink.Emit(progress.Event{
		Type:    progress.EventRunStarted,
		At:      started,
		RunID:   runID,
		Message: strings.TrimSpace(opts.InputPath),
	})

	defer func() {
		findingCount := 0
		status := "success"
		errMsg := ""

		if err != nil {
			status = "failed"
			errMsg = err.Error()
		} else if len(report.Errors) > 0 {
			status = "warning"
			findingCount = len(report.Findings)
		} else {
			findingCount = len(report.Findings)
		}

		sink.Emit(progress.Event{
			Type:         progress.EventRunFinished,
			At:           time.Now().UTC(),
			RunID:        runID,
			Status:       status,
			FindingCount: findingCount,
			DurationMS:   time.Since(started).Milliseconds(),
			Error:        errMsg,
		})
	}()

	if strings.TrimSpace(opts.InputPath) == "" {
		err = fmt.Errorf("input path is required")
		return
	}
	if strings.TrimSpace(opts.ExecutionMode) == "" {
		opts.ExecutionMode = worker.ExecutionModeSandboxed
	}
	if strings.TrimSpace(opts.SandboxMode) == "" && opts.ExecutionMode == worker.ExecutionModeSandboxed {
		opts.SandboxMode = worker.DefaultSandboxMode
	}

	runDir, runErr := resolveRunDir(opts.OutDir, runID)
	if runErr != nil {
		err = runErr
		return
	}
	if mkErr := os.MkdirAll(runDir, 0o700); mkErr != nil {
		err = fmt.Errorf("create run dir: %w", mkErr)
		return
	}

	stage, stageErr := intake.Stage(intake.StageOptions{
		InputPath: opts.InputPath,
		OutDir:    runDir,
		MaxFiles:  opts.MaxFiles,
		MaxBytes:  opts.MaxBytes,
	})
	if stageErr != nil {
		err = stageErr
		return
	}
	defer func() { _ = stage.Cleanup() }()

	manifestPath := filepath.Join(runDir, "manifest.json")
	if writeManifestErr := intake.WriteManifest(manifestPath, stage.Manifest); writeManifestErr != nil {
		err = writeManifestErr
		return
	}

	checksDir, dirErr := checks.ResolveDir(opts.ChecksDir)
	if dirErr != nil {
		err = dirErr
		return
	}

	customDefs, checkWarnings, loadErr := checks.LoadCustomDir(checksDir)
	if loadErr != nil {
		err = loadErr
		return
	}

	builtinDefs := checks.Builtins()
	selection, selectionErr := checks.BuildSelection(builtinDefs, customDefs, checks.SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   !opts.NoCustomChecks,
		OnlyIDs:         opts.OnlyChecks,
		SkipIDs:         opts.SkipChecks,
	})
	if selectionErr != nil {
		err = selectionErr
		return
	}

	runWarnings := make([]string, 0, len(checkWarnings)+len(selection.Warnings)+8)
	for _, msg := range checkWarnings {
		runWarnings = append(runWarnings, msg)
		sink.Emit(progress.Event{
			Type:    progress.EventRunWarning,
			RunID:   runID,
			Status:  "warning",
			Message: msg,
		})
	}
	for _, msg := range selection.Warnings {
		runWarnings = append(runWarnings, msg)
		sink.Emit(progress.Event{
			Type:    progress.EventRunWarning,
			RunID:   runID,
			Status:  "warning",
			Message: msg,
		})
	}

	enabledCheckIDs := make([]string, 0, len(selection.Checks))
	builtinCount := 0
	customCount := 0
	for _, def := range selection.Checks {
		enabledCheckIDs = append(enabledCheckIDs, def.ID)
		switch def.Source {
		case checks.SourceBuiltin:
			builtinCount++
		default:
			customCount++
		}
	}

	workerResults := worker.RunAll(ctx, stage.WorkspacePath, stage.Manifest, selection.Checks, worker.RunOptions{
		CodexBin:    opts.CodexBin,
		OutDir:      runDir,
		MaxParallel: opts.Workers,
		Timeout:     opts.Timeout,
		Verbose:     opts.Verbose,
		Sink:        sink,
		Mode:        opts.ExecutionMode,
		SandboxMode: opts.SandboxMode,
	})

	findings := make([]model.Finding, 0, 128)
	for idx := range workerResults {
		wr := redactWorkerResult(workerResults[idx])
		workerResults[idx] = wr
		findings = append(findings, wr.Findings...)
		if wr.Error != "" {
			msg := redact.Text(fmt.Sprintf("%s: %s", wr.Track, wr.Error))
			runWarnings = append(runWarnings, msg)
			sink.Emit(progress.Event{
				Type:    progress.EventRunWarning,
				RunID:   runID,
				Track:   wr.Track,
				Status:  wr.Status,
				Message: msg,
			})
		}
	}

	findings = dedupeFindings(findings)
	findings = redactFindings(findings)
	runWarnings = redact.Strings(runWarnings)
	countsBySeverity := buildSeverityCounts(findings)
	countsByCategory := buildCategoryCounts(findings)
	completed := time.Now().UTC()

	report = model.AuditReport{
		RunMetadata: model.RunMetadata{
			RunID:             runID,
			StartedAt:         started,
			CompletedAt:       completed,
			DurationMS:        completed.Sub(started).Milliseconds(),
			PromptVersion:     prompt.Version,
			CodexBin:          opts.CodexBin,
			CodexRequestedBin: opts.CodexRequest,
			CodexVersion:      opts.CodexVersion,
			CodexSHA256:       opts.CodexSHA256,
			ExecutionMode:     opts.ExecutionMode,
			CodexSandbox:      opts.SandboxMode,
			Workers:           opts.Workers,
			EnabledChecks:     len(enabledCheckIDs),
			BuiltInChecks:     builtinCount,
			CustomChecks:      customCount,
			CheckIDs:          enabledCheckIDs,
		},
		InputSummary: model.InputSummary{
			InputType:     stage.InputType,
			InputPath:     stage.InputPath,
			WorkspacePath: stage.WorkspacePath,
			ManifestPath:  manifestPath,
			IncludedFiles: stage.Manifest.IncludedFiles,
			IncludedBytes: stage.Manifest.IncludedBytes,
			SkippedFiles:  stage.Manifest.SkippedFiles,
		},
		Findings:         findings,
		CountsBySeverity: countsBySeverity,
		CountsByCategory: countsByCategory,
		WorkerSummaries:  workerResults,
		Errors:           runWarnings,
	}

	jsonPath := filepath.Join(runDir, "audit.json")
	mdPath := filepath.Join(runDir, "audit.md")
	htmlPath := filepath.Join(runDir, "audit.html")

	if jsonErr := reportpkg.WriteJSON(jsonPath, report); jsonErr != nil {
		err = jsonErr
		return
	}
	if mdErr := reportpkg.WriteMarkdown(mdPath, report); mdErr != nil {
		err = mdErr
		return
	}
	if htmlErr := reportpkg.WriteHTML(htmlPath, report); htmlErr != nil {
		err = htmlErr
		return
	}

	paths = ArtifactPaths{
		RunDir:       runDir,
		ManifestPath: manifestPath,
		JSONPath:     jsonPath,
		MarkdownPath: mdPath,
		HTMLPath:     htmlPath,
	}
	return
}

func resolveRunDir(out string, runID string) (string, error) {
	if strings.TrimSpace(out) != "" {
		return filepath.Abs(out)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	return filepath.Join(cwd, ".governor", "runs", runID), nil
}

func redactFindings(in []model.Finding) []model.Finding {
	if len(in) == 0 {
		return in
	}
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		f.Title = redact.Text(strings.TrimSpace(f.Title))
		f.Evidence = redact.Text(strings.TrimSpace(f.Evidence))
		f.Impact = redact.Text(strings.TrimSpace(f.Impact))
		f.Remediation = redact.Text(strings.TrimSpace(f.Remediation))
		out = append(out, f)
	}
	return out
}

func redactWorkerResult(in model.WorkerResult) model.WorkerResult {
	in.Error = redact.Text(strings.TrimSpace(in.Error))
	in.RawOutput = redact.Text(strings.TrimSpace(in.RawOutput))
	in.Findings = redactFindings(in.Findings)
	return in
}

func dedupeFindings(in []model.Finding) []model.Finding {
	seen := make(map[string]int, len(in))
	out := make([]model.Finding, 0, len(in))

	for _, f := range in {
		key := dedupeKey(f)
		if idx, ok := seen[key]; ok {
			existing := out[idx]
			if severityWeight(f.Severity) < severityWeight(existing.Severity) {
				existing.Severity = f.Severity
			}
			if f.Confidence > existing.Confidence {
				existing.Confidence = f.Confidence
			}
			existing.SourceTrack = mergeSourceTracks(existing.SourceTrack, f.SourceTrack)
			if len(existing.FileRefs) == 0 && len(f.FileRefs) > 0 {
				existing.FileRefs = append([]string{}, f.FileRefs...)
			}
			out[idx] = existing
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}

	sort.SliceStable(out, func(i, j int) bool {
		wi := severityWeight(out[i].Severity)
		wj := severityWeight(out[j].Severity)
		if wi != wj {
			return wi < wj
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Title < out[j].Title
	})

	return out
}

func dedupeKey(f model.Finding) string {
	refs := append([]string{}, f.FileRefs...)
	sort.Strings(refs)
	evidence := strings.ToLower(strings.TrimSpace(f.Evidence))
	if len(evidence) > 200 {
		evidence = evidence[:200]
	}
	return strings.ToLower(strings.TrimSpace(f.Title)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Category)) + "|" +
		strings.Join(refs, ",") + "|" + evidence
}

func mergeSourceTracks(a, b string) string {
	set := map[string]struct{}{}
	for _, s := range strings.Split(a, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			set[s] = struct{}{}
		}
	}
	for _, s := range strings.Split(b, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			set[s] = struct{}{}
		}
	}
	merged := make([]string, 0, len(set))
	for s := range set {
		merged = append(merged, s)
	}
	sort.Strings(merged)
	return strings.Join(merged, ",")
}

func severityWeight(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func buildSeverityCounts(findings []model.Finding) map[string]int {
	m := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if _, ok := m[sev]; !ok {
			sev = "info"
		}
		m[sev]++
	}
	return m
}

func buildCategoryCounts(findings []model.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range findings {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		if cat == "" {
			cat = "general"
		}
		m[cat]++
	}
	return m
}
