package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"governor/internal/ai"
	"governor/internal/checks"
	"governor/internal/intake"
	"governor/internal/model"
	"governor/internal/progress"
	"governor/internal/prompt"
	"governor/internal/redact"
	reportpkg "governor/internal/report"
	"governor/internal/safefile"
	"governor/internal/worker"
)

type AuditOptions struct {
	InputPath     string
	OutDir        string
	AIRuntime     ai.Runtime
	AIBin         string
	AIVersion     string
	AISHA256      string
	AIRequest     string
	Workers       int
	MaxFiles      int
	MaxBytes      int64
	Timeout       time.Duration
	Verbose       bool
	ExecutionMode string
	SandboxMode   string
	Progress      progress.Sink
	ChecksDir     string

	NoCustomChecks       bool
	OnlyChecks           []string
	SkipChecks           []string
	KeepWorkspaceOnError bool
	AllowExistingOutDir  bool

	SandboxDenyHostFallback bool
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
	if opts.AllowExistingOutDir {
		runDir, runErr = safefile.EnsureDir(runDir, 0o700, true)
	} else {
		runDir, runErr = safefile.EnsureFreshDir(runDir, 0o700)
	}
	if runErr != nil {
		err = fmt.Errorf("create run dir: %w", runErr)
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
	defer func() {
		if !shouldCleanupWorkspace(err, report.Errors, opts.KeepWorkspaceOnError) {
			return
		}
		if cleanupErr := stage.Cleanup(); cleanupErr != nil {
			msg := fmt.Sprintf("cleanup staged workspace: %v", cleanupErr)
			sink.Emit(progress.Event{
				Type:    progress.EventRunWarning,
				RunID:   runID,
				Status:  "warning",
				Message: msg,
			})
			fmt.Fprintf(os.Stderr, "[governor] warning: %s\n", msg)
		}
	}()

	manifestPath := filepath.Join(runDir, "manifest.json")
	if writeManifestErr := intake.WriteManifest(manifestPath, stage.Manifest); writeManifestErr != nil {
		err = writeManifestErr
		return
	}

	selection, selectionErr := checks.ResolveAuditSelection(checks.AuditSelectionOptions{
		ChecksDir:      opts.ChecksDir,
		NoCustomChecks: opts.NoCustomChecks,
		OnlyIDs:        opts.OnlyChecks,
		SkipIDs:        opts.SkipChecks,
	})
	if selectionErr != nil {
		err = selectionErr
		return
	}

	runWarnings := make([]string, 0, len(selection.Warnings)+8)
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
	for _, def := range selection.Checks {
		enabledCheckIDs = append(enabledCheckIDs, def.ID)
	}
	builtinCount, customCount := checks.CountChecksBySource(selection.Checks)
	aiCount, ruleCount := checks.CountChecksByEngine(selection.Checks)
	aiRequired := checks.SelectionRequiresAI(selection.Checks)

	workerResults := worker.RunAll(ctx, stage.WorkspacePath, stage.Manifest, selection.Checks, worker.RunOptions{
		AIRuntime:   opts.AIRuntime,
		CodexBin:    opts.AIBin,
		OutDir:      runDir,
		MaxParallel: opts.Workers,
		Timeout:     opts.Timeout,
		Verbose:     opts.Verbose,
		Sink:        sink,
		Mode:        opts.ExecutionMode,
		SandboxMode: opts.SandboxMode,

		SandboxDenyHostFallback: opts.SandboxDenyHostFallback,
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
			RunID:          runID,
			StartedAt:      started,
			CompletedAt:    completed,
			DurationMS:     completed.Sub(started).Milliseconds(),
			PromptVersion:  prompt.Version,
			AIProfile:      opts.AIRuntime.Profile,
			AIProvider:     opts.AIRuntime.Provider,
			AIModel:        opts.AIRuntime.Model,
			AIAuthMode:     opts.AIRuntime.AuthMode,
			AIBin:          opts.AIBin,
			AIRequestedBin: opts.AIRequest,
			AIVersion:      opts.AIVersion,
			AISHA256:       opts.AISHA256,
			ExecutionMode:  opts.ExecutionMode,
			AISandbox:      opts.SandboxMode,
			AIRequired:     aiRequired,
			AIUsed:         aiRequired,
			Workers:        opts.Workers,
			EnabledChecks:  len(enabledCheckIDs),
			BuiltInChecks:  builtinCount,
			CustomChecks:   customCount,
			AIChecks:       aiCount,
			RuleChecks:     ruleCount,
			CheckIDs:       enabledCheckIDs,
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

func shouldCleanupWorkspace(runErr error, runWarnings []string, keepWorkspaceOnError bool) bool {
	if keepWorkspaceOnError {
		if runErr != nil || len(runWarnings) > 0 {
			return false
		}
	}
	return true
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
