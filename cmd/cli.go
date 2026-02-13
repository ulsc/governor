package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"governor/internal/app"
	"governor/internal/checks"
	"governor/internal/extractor"
	"governor/internal/isolation"
	"governor/internal/model"
	"governor/internal/progress"
	"governor/internal/trust"
	"governor/internal/tui"
)

func Execute(args []string) error {
	if len(args) == 0 {
		return usageError("missing command")
	}

	switch args[0] {
	case "audit":
		return runAudit(args[1:])
	case "isolate":
		return runIsolate(args[1:])
	case "checks":
		return runChecks(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return usageError(fmt.Sprintf("unknown command %q", args[0]))
	}
}

func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	out := fs.String("out", "", "Output directory for run artifacts (default ./.governor/runs/<timestamp>)")
	workers := fs.Int("workers", 3, "Max concurrent worker processes (1-3)")
	codexBin := fs.String("codex-bin", "codex", "Codex executable path")
	allowCustomCodexBin := fs.Bool("allow-custom-codex-bin", false, "Allow non-default codex binary path (for testing only)")
	executionMode := fs.String("execution-mode", "sandboxed", "Codex execution mode: sandboxed|host")
	codexSandbox := fs.String("codex-sandbox", "read-only", "Codex sandbox mode for sandboxed execution: read-only|workspace-write|danger-full-access")
	maxFiles := fs.Int("max-files", 20000, "Maximum included file count")
	maxBytes := fs.Int64("max-bytes", 250*1024*1024, "Maximum included file bytes")
	timeout := fs.Duration("timeout", 4*time.Minute, "Per-worker timeout")
	verbose := fs.Bool("verbose", false, "Enable verbose logs")
	enableTUI := fs.Bool("tui", false, "Enable interactive terminal UI")
	disableTUI := fs.Bool("no-tui", false, "Disable interactive terminal UI")
	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks + ~/.governor/checks, repo first)")
	noCustomChecks := fs.Bool("no-custom-checks", false, "Run built-in checks only")
	keepWorkspaceError := fs.Bool("keep-workspace-error", false, "Retain staged workspace only when run ends with warning/failed status")
	allowExistingOutDir := fs.Bool("allow-existing-out-dir", false, "Allow using an existing empty output directory (internal use)")
	sandboxDenyHostFallback := fs.Bool("sandbox-deny-host-fallback", false, "Automatically rerun tracks in host mode when sandbox denies file access (internal use)")

	var onlyChecks listFlag
	var skipChecks listFlag
	fs.Var(&onlyChecks, "only-check", "Only run specific check ID(s) (repeatable or comma-separated)")
	fs.Var(&skipChecks, "skip-check", "Skip specific check ID(s) (repeatable or comma-separated)")

	var positionalInput string
	parseArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		positionalInput = args[0]
		parseArgs = args[1:]
	}

	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	remaining := fs.Args()
	switch {
	case positionalInput == "" && len(remaining) == 1:
		positionalInput = remaining[0]
	case positionalInput != "" && len(remaining) == 0:
		// valid
	default:
		return usageError("usage: governor audit <path-or-zip> [flags]")
	}

	if *workers < 1 || *workers > 3 {
		return errors.New("--workers must be between 1 and 3")
	}
	if *maxFiles <= 0 {
		return errors.New("--max-files must be > 0")
	}
	if *maxBytes <= 0 {
		return errors.New("--max-bytes must be > 0")
	}
	if *timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}
	if strings.TrimSpace(*codexBin) == "" {
		return errors.New("--codex-bin cannot be empty")
	}
	if *enableTUI && *disableTUI {
		return errors.New("cannot set both --tui and --no-tui")
	}

	modeValue, err := normalizeExecutionModeFlag(*executionMode)
	if err != nil {
		return err
	}
	sandboxValue, err := normalizeSandboxModeFlag(*codexSandbox)
	if err != nil {
		return err
	}
	if modeValue == "host" {
		sandboxValue = ""
	}

	codexInfo, err := trust.ResolveCodexBinary(context.Background(), *codexBin, *allowCustomCodexBin)
	if err != nil {
		return err
	}

	useTUI := isatty.IsTerminal(os.Stdout.Fd()) && isatty.IsTerminal(os.Stderr.Fd()) && isatty.IsTerminal(os.Stdin.Fd())
	if *enableTUI {
		useTUI = true
	}
	if *disableTUI {
		useTUI = false
	}

	auditOpts := app.AuditOptions{
		InputPath:     positionalInput,
		OutDir:        *out,
		CodexBin:      codexInfo.ResolvedPath,
		CodexVersion:  codexInfo.Version,
		CodexSHA256:   codexInfo.SHA256,
		CodexRequest:  codexInfo.RequestedPath,
		Workers:       *workers,
		MaxFiles:      *maxFiles,
		MaxBytes:      *maxBytes,
		Timeout:       *timeout,
		Verbose:       *verbose,
		ExecutionMode: modeValue,
		SandboxMode:   sandboxValue,

		ChecksDir:            *checksDir,
		NoCustomChecks:       *noCustomChecks,
		OnlyChecks:           onlyChecks.Values(),
		SkipChecks:           skipChecks.Values(),
		KeepWorkspaceOnError: *keepWorkspaceError,
		AllowExistingOutDir:  *allowExistingOutDir,

		SandboxDenyHostFallback: *sandboxDenyHostFallback,
	}

	if useTUI {
		events := make(chan progress.Event, 128)
		auditOpts.Progress = progress.NewChannelSink(events)

		type runResult struct {
			report model.AuditReport
			paths  app.ArtifactPaths
			err    error
		}
		runDone := make(chan runResult, 1)
		go func() {
			defer close(events)
			report, paths, err := app.RunAudit(context.Background(), auditOpts)
			runDone <- runResult{report: report, paths: paths, err: err}
		}()

		if err := tui.Run(tui.Options{Events: events}); err != nil {
			return err
		}
		result := <-runDone
		if result.err != nil {
			return result.err
		}
		printAuditSummary(result.report, result.paths)
		return nil
	}

	auditOpts.Progress = progress.NewPlainSink(os.Stderr)
	report, paths, err := app.RunAudit(context.Background(), auditOpts)
	if err != nil {
		return err
	}
	printAuditSummary(report, paths)

	return nil
}

func runIsolate(args []string) error {
	if len(args) == 0 {
		return usageError("usage: governor isolate <audit> [flags]")
	}
	switch args[0] {
	case "audit":
		return runIsolateAudit(args[1:])
	default:
		return usageError(fmt.Sprintf("unknown isolate subcommand %q", args[0]))
	}
}

func runIsolateAudit(args []string) error {
	fs := flag.NewFlagSet("isolate audit", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	out := fs.String("out", "", "Output directory for run artifacts (default ./.governor/runs/<timestamp>)")
	runtimeName := fs.String("runtime", "auto", "Container runtime: auto|docker|podman")
	image := fs.String("image", isolation.DefaultImage, "Container image for isolated governor runner")
	network := fs.String("network", "none", "Network policy: unrestricted|none")
	pull := fs.String("pull", "never", "Image pull policy: always|if-missing|never")
	cleanImage := fs.Bool("clean-image", false, "Remove runner image after execution")
	authMode := fs.String("auth-mode", "subscription", "Auth mode: auto|subscription|api-key")
	codexHome := fs.String("codex-home", "~/.codex", "Host codex home used for subscription auth bundle")

	workers := fs.Int("workers", 3, "Max concurrent worker processes inside isolated run (1-3)")
	executionMode := fs.String("execution-mode", "host", "Inner worker execution mode: sandboxed|host")
	codexSandbox := fs.String("codex-sandbox", "read-only", "Inner sandbox mode (sandboxed execution): read-only|workspace-write|danger-full-access")
	maxFiles := fs.Int("max-files", 20000, "Maximum included file count")
	maxBytes := fs.Int64("max-bytes", 250*1024*1024, "Maximum included file bytes")
	timeout := fs.Duration("timeout", 4*time.Minute, "Per-worker timeout")
	verbose := fs.Bool("verbose", false, "Enable verbose logs")
	checksDir := fs.String("checks-dir", "", "Checks directory mounted read-only (optional)")
	noCustomChecks := fs.Bool("no-custom-checks", false, "Run built-in checks only")
	keepWorkspaceError := fs.Bool("keep-workspace-error", false, "Retain staged workspace only when run ends with warning/failed status")

	var onlyChecks listFlag
	var skipChecks listFlag
	fs.Var(&onlyChecks, "only-check", "Only run specific check ID(s) (repeatable or comma-separated)")
	fs.Var(&skipChecks, "skip-check", "Skip specific check ID(s) (repeatable or comma-separated)")

	var positionalInput string
	parseArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		positionalInput = args[0]
		parseArgs = args[1:]
	}

	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	remaining := fs.Args()
	switch {
	case positionalInput == "" && len(remaining) == 1:
		positionalInput = remaining[0]
	case positionalInput != "" && len(remaining) == 0:
		// valid
	default:
		return usageError("usage: governor isolate audit <path-or-zip> [flags]")
	}

	runtimeValue, err := normalizeIsolationRuntimeFlag(*runtimeName)
	if err != nil {
		return err
	}
	networkValue, err := normalizeIsolationNetworkFlag(*network)
	if err != nil {
		return err
	}
	pullValue, err := normalizeIsolationPullFlag(*pull)
	if err != nil {
		return err
	}
	authValue, err := normalizeIsolationAuthFlag(*authMode)
	if err != nil {
		return err
	}
	modeValue, err := normalizeExecutionModeFlag(*executionMode)
	if err != nil {
		return err
	}
	sandboxValue, err := normalizeSandboxModeFlag(*codexSandbox)
	if err != nil {
		return err
	}
	if modeValue == "host" {
		sandboxValue = ""
	}
	outDir, err := resolveIsolateOutDir(*out, time.Now().UTC())
	if err != nil {
		return err
	}

	if err := isolation.RunAudit(context.Background(), isolation.AuditOptions{
		InputPath: positionalInput,
		OutDir:    outDir,
		ChecksDir: *checksDir,

		Runtime:       runtimeValue,
		Image:         strings.TrimSpace(*image),
		NetworkPolicy: networkValue,
		PullPolicy:    pullValue,
		CleanImage:    *cleanImage,

		AuthMode:  authValue,
		CodexHome: strings.TrimSpace(*codexHome),

		Workers:       *workers,
		ExecutionMode: modeValue,
		SandboxMode:   sandboxValue,
		MaxFiles:      *maxFiles,
		MaxBytes:      *maxBytes,
		Timeout:       *timeout,
		Verbose:       *verbose,

		NoCustomChecks:       *noCustomChecks,
		OnlyChecks:           onlyChecks.Values(),
		SkipChecks:           skipChecks.Values(),
		KeepWorkspaceOnError: *keepWorkspaceError,
	}); err != nil {
		return err
	}
	if err := printIsolateAuditSummaryFromHost(outDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		printIsolateArtifactPaths(outDir)
	}
	return nil
}

func printAuditSummary(report model.AuditReport, paths app.ArtifactPaths) {
	fmt.Printf("run id:         %s\n", report.RunMetadata.RunID)
	fmt.Printf("artifacts dir:  %s\n", paths.RunDir)
	fmt.Printf("audit markdown: %s\n", filepath.Clean(paths.MarkdownPath))
	fmt.Printf("audit json:     %s\n", filepath.Clean(paths.JSONPath))
	fmt.Printf("audit html:     %s\n", filepath.Clean(paths.HTMLPath))
	if strings.TrimSpace(report.RunMetadata.CodexRequestedBin) != "" {
		fmt.Printf("codex request:  %s\n", report.RunMetadata.CodexRequestedBin)
	}
	if strings.TrimSpace(report.RunMetadata.CodexBin) != "" {
		fmt.Printf("codex resolved: %s\n", report.RunMetadata.CodexBin)
	}
	if strings.TrimSpace(report.RunMetadata.CodexVersion) != "" {
		fmt.Printf("codex version:  %s\n", report.RunMetadata.CodexVersion)
	}
	if strings.TrimSpace(report.RunMetadata.ExecutionMode) != "" {
		mode := report.RunMetadata.ExecutionMode
		if strings.TrimSpace(report.RunMetadata.CodexSandbox) != "" {
			mode += " (sandbox=" + report.RunMetadata.CodexSandbox + ")"
		}
		fmt.Printf("execution:      %s\n", mode)
	}
	fmt.Printf("checks:         %d (builtin=%d custom=%d)\n",
		report.RunMetadata.EnabledChecks,
		report.RunMetadata.BuiltInChecks,
		report.RunMetadata.CustomChecks,
	)
	fmt.Printf("findings:       %d (critical=%d high=%d medium=%d low=%d info=%d)\n",
		len(report.Findings),
		report.CountsBySeverity["critical"],
		report.CountsBySeverity["high"],
		report.CountsBySeverity["medium"],
		report.CountsBySeverity["low"],
		report.CountsBySeverity["info"],
	)

	for _, ws := range report.WorkerSummaries {
		fmt.Printf("worker %-24s status=%-9s findings=%d duration=%dms\n", ws.Track, ws.Status, ws.FindingCount, ws.DurationMS)
	}

	if len(report.Errors) > 0 {
		fmt.Printf("warnings: %d\n", len(report.Errors))
	}
}

func resolveIsolateOutDir(raw string, now time.Time) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return filepath.Abs(raw)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	return filepath.Join(cwd, ".governor", "runs", now.UTC().Format("20060102-150405")), nil
}

func isolateArtifactPaths(outDir string) app.ArtifactPaths {
	outDir = filepath.Clean(outDir)
	return app.ArtifactPaths{
		RunDir:       outDir,
		MarkdownPath: filepath.Join(outDir, "audit.md"),
		JSONPath:     filepath.Join(outDir, "audit.json"),
		HTMLPath:     filepath.Join(outDir, "audit.html"),
	}
}

func printIsolateArtifactPaths(outDir string) {
	paths := isolateArtifactPaths(outDir)
	fmt.Printf("artifacts dir:  %s\n", paths.RunDir)
	fmt.Printf("audit markdown: %s\n", filepath.Clean(paths.MarkdownPath))
	fmt.Printf("audit json:     %s\n", filepath.Clean(paths.JSONPath))
	fmt.Printf("audit html:     %s\n", filepath.Clean(paths.HTMLPath))
}

func printIsolateAuditSummaryFromHost(outDir string) error {
	paths := isolateArtifactPaths(outDir)
	raw, err := os.ReadFile(paths.JSONPath)
	if err != nil {
		return fmt.Errorf("read isolated report %s: %w", paths.JSONPath, err)
	}
	var report model.AuditReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return fmt.Errorf("parse isolated report %s: %w", paths.JSONPath, err)
	}
	printAuditSummary(report, paths)
	return nil
}

func runChecks(args []string) error {
	if len(args) == 0 {
		return usageError("usage: governor checks <init|add|extract|list|validate|doctor|explain|enable|disable> [flags]")
	}

	switch args[0] {
	case "init":
		return runChecksInit(args[1:])
	case "add":
		return runChecksAdd(args[1:])
	case "extract":
		return runChecksExtract(args[1:])
	case "list":
		return runChecksList(args[1:])
	case "validate":
		return runChecksValidate(args[1:])
	case "doctor":
		return runChecksDoctor(args[1:])
	case "explain":
		return runChecksExplain(args[1:])
	case "enable":
		return runChecksStatus(args[1:], checks.StatusEnabled)
	case "disable":
		return runChecksStatus(args[1:], checks.StatusDisabled)
	default:
		return usageError(fmt.Sprintf("unknown checks subcommand %q", args[0]))
	}
}

func runChecksInit(args []string) error {
	fs := flag.NewFlagSet("checks init", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks in repo, otherwise ~/.governor/checks)")
	templateID := fs.String("template", "", "Check template ID")
	listTemplates := fs.Bool("list-templates", false, "List available templates and exit")
	nonInteractive := fs.Bool("non-interactive", false, "Disable interactive prompts")
	overwrite := fs.Bool("overwrite", false, "Overwrite existing check file with same ID")

	id := fs.String("id", "", "Check ID (slug)")
	name := fs.String("name", "", "Check name")
	description := fs.String("description", "", "Check description")
	instructions := fs.String("instructions", "", "Check instructions text")
	instructionsFile := fs.String("instructions-file", "", "Path to instructions file")
	statusRaw := fs.String("status", "draft", "Check status: draft|enabled|disabled")
	severityHint := fs.String("severity-hint", "", "Severity hint: critical|high|medium|low|info")
	confidenceHint := fs.Float64("confidence-hint", -1, "Confidence hint (0..1), default from template")

	var includeGlobs listFlag
	var excludeGlobs listFlag
	var categories listFlag
	fs.Var(&includeGlobs, "include-glob", "Include glob (repeatable or comma-separated)")
	fs.Var(&excludeGlobs, "exclude-glob", "Exclude glob (repeatable or comma-separated)")
	fs.Var(&categories, "category", "Category hint (repeatable or comma-separated)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks init does not accept positional args")
	}
	if *listTemplates {
		for _, template := range checks.Templates() {
			fmt.Printf("%-24s %s\n", template.ID, template.Name)
		}
		return nil
	}
	if strings.TrimSpace(*instructions) != "" && strings.TrimSpace(*instructionsFile) != "" {
		return errors.New("use either --instructions or --instructions-file")
	}

	input := checkCreateInput{
		ChecksDir:         *checksDir,
		TemplateID:        strings.TrimSpace(*templateID),
		ID:                strings.TrimSpace(*id),
		Name:              strings.TrimSpace(*name),
		Description:       strings.TrimSpace(*description),
		Instructions:      strings.TrimSpace(*instructions),
		InstructionsFile:  strings.TrimSpace(*instructionsFile),
		StatusRaw:         strings.TrimSpace(*statusRaw),
		SeverityHint:      strings.TrimSpace(*severityHint),
		ConfidenceHint:    *confidenceHint,
		IncludeGlobs:      includeGlobs.Values(),
		ExcludeGlobs:      excludeGlobs.Values(),
		CategoriesHint:    categories.Values(),
		Overwrite:         *overwrite,
		Interactive:       !*nonInteractive && isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd()),
		PromptForTemplate: strings.TrimSpace(*templateID) == "",
	}

	path, status, err := runCheckCreateFlow(input)
	if err != nil {
		return err
	}
	fmt.Printf("created check: %s\n", path)
	fmt.Printf("status: %s\n", status)
	fmt.Println("next: governor checks doctor")
	return nil
}

func runChecksAdd(args []string) error {
	fs := flag.NewFlagSet("checks add", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks in repo, otherwise ~/.governor/checks)")
	templateID := fs.String("template", "blank", "Check template ID")
	overwrite := fs.Bool("overwrite", false, "Overwrite existing check file with same ID")
	id := fs.String("id", "", "Check ID (slug)")
	name := fs.String("name", "", "Check name")
	description := fs.String("description", "", "Check description")
	instructions := fs.String("instructions", "", "Check instructions text")
	instructionsFile := fs.String("instructions-file", "", "Path to instructions file")
	severityHint := fs.String("severity-hint", "", "severity hint (critical|high|medium|low|info)")
	confidenceHint := fs.Float64("confidence-hint", -1, "confidence hint (0..1), default from template")

	var includeGlobs listFlag
	var excludeGlobs listFlag
	var categories listFlag
	fs.Var(&includeGlobs, "include-glob", "Include glob (repeatable or comma-separated)")
	fs.Var(&excludeGlobs, "exclude-glob", "Exclude glob (repeatable or comma-separated)")
	fs.Var(&categories, "category", "Category hint (repeatable or comma-separated)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks add does not accept positional args")
	}

	if strings.TrimSpace(*id) == "" {
		return errors.New("--id is required")
	}
	if strings.TrimSpace(*instructions) != "" && strings.TrimSpace(*instructionsFile) != "" {
		return errors.New("use either --instructions or --instructions-file")
	}

	instructionsText := strings.TrimSpace(*instructions)
	if strings.TrimSpace(*instructionsFile) != "" {
		b, err := os.ReadFile(strings.TrimSpace(*instructionsFile))
		if err != nil {
			return fmt.Errorf("read --instructions-file: %w", err)
		}
		instructionsText = strings.TrimSpace(string(b))
	}
	path, status, err := runCheckCreateFlow(checkCreateInput{
		ChecksDir:      *checksDir,
		TemplateID:     strings.TrimSpace(*templateID),
		ID:             strings.TrimSpace(*id),
		Name:           strings.TrimSpace(*name),
		Description:    strings.TrimSpace(*description),
		Instructions:   instructionsText,
		StatusRaw:      "draft",
		SeverityHint:   strings.TrimSpace(*severityHint),
		ConfidenceHint: *confidenceHint,
		IncludeGlobs:   includeGlobs.Values(),
		ExcludeGlobs:   excludeGlobs.Values(),
		CategoriesHint: categories.Values(),
		Overwrite:      *overwrite,
		Interactive:    false,
	})
	if err != nil {
		return err
	}

	fmt.Printf("created check: %s\n", path)
	fmt.Printf("status: %s\n", status)
	return nil
}

func runChecksExtract(args []string) error {
	fs := flag.NewFlagSet("checks extract", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks in repo, otherwise ~/.governor/checks)")
	codexBin := fs.String("codex-bin", "codex", "Codex executable path")
	allowCustomCodexBin := fs.Bool("allow-custom-codex-bin", false, "Allow non-default codex binary path (for testing only)")
	executionMode := fs.String("execution-mode", "sandboxed", "Codex execution mode: sandboxed|host")
	codexSandbox := fs.String("codex-sandbox", "read-only", "Codex sandbox mode for sandboxed execution: read-only|workspace-write|danger-full-access")
	maxChecks := fs.Int("max-checks", 10, "Maximum generated checks")
	replace := fs.Bool("replace", false, "Overwrite existing check files with same ID")
	allowPDF := fs.Bool("allow-pdf", false, "Allow PDF parsing via local pdftotext (disabled by default)")

	var inputs listFlag
	fs.Var(&inputs, "input", "Input file/folder (.md/.txt/.pdf) (repeatable)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	inputValues := inputs.Values()
	for _, tail := range fs.Args() {
		tail = strings.TrimSpace(tail)
		if tail != "" {
			inputValues = append(inputValues, tail)
		}
	}

	if len(inputValues) == 0 {
		return errors.New("at least one --input (or positional input path) is required")
	}
	if strings.TrimSpace(*codexBin) == "" {
		return errors.New("--codex-bin cannot be empty")
	}
	modeValue, err := normalizeExecutionModeFlag(*executionMode)
	if err != nil {
		return err
	}
	sandboxValue, err := normalizeSandboxModeFlag(*codexSandbox)
	if err != nil {
		return err
	}
	if modeValue == "host" {
		sandboxValue = ""
	}
	codexInfo, err := trust.ResolveCodexBinary(context.Background(), *codexBin, *allowCustomCodexBin)
	if err != nil {
		return err
	}

	res, err := extractor.Run(context.Background(), extractor.Options{
		Inputs:    inputValues,
		ChecksDir: *checksDir,
		CodexBin:  codexInfo.ResolvedPath,
		MaxChecks: *maxChecks,
		Replace:   *replace,
		Mode:      modeValue,
		Sandbox:   sandboxValue,
		AllowPDF:  *allowPDF,
	})
	if err != nil {
		if len(res.Warnings) > 0 {
			for _, w := range res.Warnings {
				fmt.Printf("warning: %s\n", w)
			}
		}
		return err
	}

	for _, path := range res.Created {
		fmt.Printf("created: %s\n", path)
	}
	for _, id := range res.Skipped {
		fmt.Printf("skipped: %s\n", id)
	}
	for _, w := range res.Warnings {
		fmt.Printf("warning: %s\n", w)
	}
	fmt.Printf("created checks: %d\n", len(res.Created))
	return nil
}

func runChecksList(args []string) error {
	fs := flag.NewFlagSet("checks list", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks + ~/.governor/checks, repo first)")
	statusFilter := fs.String("status", "", "status filter: draft|enabled|disabled")
	sourceFilter := fs.String("source", "", "source filter: builtin|custom")
	includeBuiltins := fs.Bool("include-builtins", true, "Include built-in checks")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks list does not accept positional args")
	}

	dirs, err := checks.ResolveReadDirs(*checksDir)
	if err != nil {
		return err
	}
	customDefs, warnings, err := checks.LoadCustomDirs(dirs)
	if err != nil {
		return err
	}

	defs := make([]checks.Definition, 0, len(customDefs)+3)
	if *includeBuiltins {
		defs = append(defs, checks.Builtins()...)
	}
	defs = append(defs, customDefs...)

	statusFilterValue := strings.ToLower(strings.TrimSpace(*statusFilter))
	sourceFilterValue := strings.ToLower(strings.TrimSpace(*sourceFilter))
	filtered := make([]checks.Definition, 0, len(defs))
	for _, def := range defs {
		if statusFilterValue != "" && string(def.Status) != statusFilterValue {
			continue
		}
		if sourceFilterValue != "" && string(def.Source) != sourceFilterValue {
			continue
		}
		filtered = append(filtered, checks.NormalizeDefinition(def))
	}

	sort.Slice(filtered, func(i, j int) bool { return filtered[i].ID < filtered[j].ID })
	if len(filtered) == 0 {
		fmt.Println("no checks found")
	} else {
		for _, def := range filtered {
			fmt.Printf("%-24s %-8s %-8s %s\n", def.ID, def.Status, def.Source, def.Name)
		}
	}

	for _, w := range warnings {
		fmt.Printf("warning: %s\n", w)
	}
	return nil
}

func runChecksValidate(args []string) error {
	fs := flag.NewFlagSet("checks validate", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks + ~/.governor/checks, repo first)")
	includeBuiltins := fs.Bool("include-builtins", true, "Include built-in checks in duplicate-ID validation")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks validate does not accept positional args")
	}

	dirs, err := checks.ResolveReadDirs(*checksDir)
	if err != nil {
		return err
	}
	customDefs, warnings, err := checks.LoadCustomDirs(dirs)
	if err != nil {
		return err
	}
	if len(warnings) > 0 {
		return fmt.Errorf("invalid checks:\n- %s", strings.Join(warnings, "\n- "))
	}

	defs := make([]checks.Definition, 0, len(customDefs)+3)
	if *includeBuiltins {
		defs = append(defs, checks.Builtins()...)
	}
	defs = append(defs, customDefs...)

	for _, def := range defs {
		if err := checks.ValidateDefinition(def); err != nil {
			return fmt.Errorf("invalid check %q: %w", def.ID, err)
		}
	}
	if err := checks.ValidateUniqueIDs(defs); err != nil {
		return err
	}

	fmt.Printf("validated %d checks\n", len(defs))
	return nil
}

func runChecksStatus(args []string, status checks.Status) error {
	fs := flag.NewFlagSet("checks status", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks + ~/.governor/checks, repo first)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return errors.New("expected check id")
	}
	id := fs.Args()[0]

	var path string
	if strings.TrimSpace(*checksDir) != "" {
		dir, err := checks.ResolveWriteDir(*checksDir)
		if err != nil {
			return err
		}
		path, err = checks.UpdateStatus(dir, id, status)
		if err != nil {
			return err
		}
	} else {
		dirs, err := checks.ResolveReadDirs("")
		if err != nil {
			return err
		}
		path, err = checks.UpdateStatusInDirs(dirs, id, status)
		if err != nil {
			return err
		}
	}

	fmt.Printf("updated %s -> %s\n", id, status)
	fmt.Printf("file: %s\n", path)
	return nil
}

func runChecksDoctor(args []string) error {
	fs := flag.NewFlagSet("checks doctor", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks + ~/.governor/checks, repo first)")
	format := fs.String("format", "text", "Output format: text|json")
	strict := fs.Bool("strict", false, "Treat warnings as failures")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks doctor does not accept positional args")
	}

	outFormat := strings.ToLower(strings.TrimSpace(*format))
	if outFormat != "text" && outFormat != "json" {
		return errors.New("--format must be text or json")
	}

	dirs, err := checks.ResolveReadDirs(*checksDir)
	if err != nil {
		return err
	}
	report, err := checks.BuildDoctorReport(dirs)
	if err != nil {
		return err
	}

	if outFormat == "json" {
		payload, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal checks doctor report: %w", err)
		}
		fmt.Println(string(payload))
	} else {
		fmt.Printf("searched dirs: %s\n", strings.Join(report.SearchedDirs, ", "))
		fmt.Printf("effective checks: %d\n", len(report.Effective))
		fmt.Printf("shadowed checks: %d\n", len(report.Shadowed))
		fmt.Printf("diagnostics: error=%d warning=%d info=%d\n", report.Summary.Error, report.Summary.Warning, report.Summary.Info)

		if len(report.Diagnostics) > 0 {
			fmt.Println("")
			fmt.Println("diagnostics:")
			for _, diag := range report.Diagnostics {
				location := diag.Path
				if location == "" {
					location = "(no path)"
				}
				idSuffix := ""
				if strings.TrimSpace(diag.CheckID) != "" {
					idSuffix = " id=" + diag.CheckID
				}
				fmt.Printf("- [%s] %s%s: %s\n", strings.ToUpper(string(diag.Severity)), location, idSuffix, diag.Message)
				if strings.TrimSpace(diag.Hint) != "" {
					fmt.Printf("  hint: %s\n", diag.Hint)
				}
			}
		}
	}

	if report.Summary.Error > 0 {
		return fmt.Errorf("checks doctor found %d error(s)", report.Summary.Error)
	}
	if *strict && report.Summary.Warning > 0 {
		return fmt.Errorf("checks doctor strict mode failed with %d warning(s)", report.Summary.Warning)
	}
	return nil
}

func runChecksExplain(args []string) error {
	fs := flag.NewFlagSet("checks explain", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks + ~/.governor/checks, repo first)")
	format := fs.String("format", "text", "Output format: text|json")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return errors.New("usage: governor checks explain <check-id> [--checks-dir <dir>] [--format text|json]")
	}

	outFormat := strings.ToLower(strings.TrimSpace(*format))
	if outFormat != "text" && outFormat != "json" {
		return errors.New("--format must be text or json")
	}

	checkID := strings.TrimSpace(fs.Args()[0])
	dirs, err := checks.ResolveReadDirs(*checksDir)
	if err != nil {
		return err
	}

	result, err := checks.ExplainCheck(dirs, checkID)
	if err != nil {
		return err
	}

	if outFormat == "json" {
		payload, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal checks explain output: %w", err)
		}
		fmt.Println(string(payload))
	} else {
		fmt.Printf("check id: %s\n", result.CheckID)
		fmt.Printf("searched dirs: %s\n", strings.Join(result.SearchedDirs, ", "))
		if result.Effective == nil {
			fmt.Println("effective: (not found)")
		} else {
			fmt.Printf("effective path: %s\n", result.Effective.Path)
			fmt.Printf("status: %s\n", result.Effective.Definition.Status)
			fmt.Printf("name: %s\n", result.Effective.Definition.Name)
			fmt.Printf("source: %s\n", result.Effective.Definition.Source)
		}
		if len(result.Shadowed) > 0 {
			fmt.Printf("shadowed: %d\n", len(result.Shadowed))
			for _, item := range result.Shadowed {
				fmt.Printf("- %s\n", item.Path)
			}
		}
		if len(result.Invalid) > 0 {
			fmt.Printf("invalid candidates: %d\n", len(result.Invalid))
			for _, item := range result.Invalid {
				fmt.Printf("- %s: %s\n", item.Path, item.Error)
			}
		}
	}

	if result.Effective == nil {
		return fmt.Errorf("check %q not found in: %s", result.CheckID, strings.Join(result.SearchedDirs, ", "))
	}
	return nil
}

type checkCreateInput struct {
	ChecksDir        string
	TemplateID       string
	ID               string
	Name             string
	Description      string
	Instructions     string
	InstructionsFile string
	StatusRaw        string
	SeverityHint     string
	ConfidenceHint   float64
	IncludeGlobs     []string
	ExcludeGlobs     []string
	CategoriesHint   []string
	Overwrite        bool

	Interactive       bool
	PromptForTemplate bool
}

func runCheckCreateFlow(input checkCreateInput) (string, checks.Status, error) {
	input.TemplateID = strings.TrimSpace(strings.ToLower(input.TemplateID))
	if input.TemplateID == "" {
		input.TemplateID = "blank"
	}

	if input.InstructionsFile != "" && input.Instructions == "" {
		b, err := os.ReadFile(input.InstructionsFile)
		if err != nil {
			return "", "", fmt.Errorf("read --instructions-file: %w", err)
		}
		input.Instructions = strings.TrimSpace(string(b))
	}

	reader := bufio.NewReader(os.Stdin)
	if input.Interactive && input.PromptForTemplate {
		fmt.Println("available templates:")
		for _, tmpl := range checks.Templates() {
			fmt.Printf("  - %-24s %s\n", tmpl.ID, tmpl.Name)
		}
		templateID, err := promptInput(reader, "Template ID", "blank")
		if err != nil {
			return "", "", err
		}
		input.TemplateID = strings.ToLower(strings.TrimSpace(templateID))
		if input.TemplateID == "" {
			input.TemplateID = "blank"
		}
	}

	template, ok := checks.LookupTemplate(input.TemplateID)
	if !ok {
		return "", "", fmt.Errorf("unknown template %q (available: %s)", input.TemplateID, strings.Join(checks.TemplateIDs(), ", "))
	}

	if input.Interactive {
		id, err := promptInput(reader, "Check ID (slug)", input.ID)
		if err != nil {
			return "", "", err
		}
		input.ID = strings.TrimSpace(id)

		defaultName := input.Name
		if defaultName == "" {
			defaultName = input.ID
		}
		name, err := promptInput(reader, "Check name", defaultName)
		if err != nil {
			return "", "", err
		}
		input.Name = strings.TrimSpace(name)

		defaultDescription := input.Description
		if defaultDescription == "" {
			defaultDescription = template.Description
		}
		description, err := promptInput(reader, "Description", defaultDescription)
		if err != nil {
			return "", "", err
		}
		input.Description = strings.TrimSpace(description)

		defaultInstructions := input.Instructions
		if defaultInstructions == "" {
			defaultInstructions = template.Instructions
		}
		instructions, err := promptInput(reader, "Instructions", defaultInstructions)
		if err != nil {
			return "", "", err
		}
		input.Instructions = strings.TrimSpace(instructions)
	}

	status, err := checks.ParseStatus(input.StatusRaw)
	if err != nil {
		return "", "", fmt.Errorf("--status: %w", err)
	}

	id := strings.TrimSpace(input.ID)
	if id == "" {
		return "", "", errors.New("--id is required")
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = id
	}

	description := strings.TrimSpace(input.Description)
	if description == "" {
		description = template.Description
	}

	instructions := strings.TrimSpace(input.Instructions)
	if instructions == "" {
		instructions = strings.TrimSpace(template.Instructions)
	}
	if instructions == "" {
		return "", "", errors.New("instructions are required")
	}

	categories := input.CategoriesHint
	if len(categories) == 0 {
		categories = append([]string{}, template.CategoriesHint...)
	}
	includeGlobs := input.IncludeGlobs
	if len(includeGlobs) == 0 {
		includeGlobs = append([]string{}, template.IncludeGlobs...)
	}
	excludeGlobs := input.ExcludeGlobs
	if len(excludeGlobs) == 0 {
		excludeGlobs = append([]string{}, template.ExcludeGlobs...)
	}

	severityHint := strings.TrimSpace(input.SeverityHint)
	if severityHint == "" {
		severityHint = template.SeverityHint
	}
	confidenceHint := input.ConfidenceHint
	if confidenceHint < 0 {
		confidenceHint = template.ConfidenceHint
	}

	dir, err := checks.ResolveWriteDir(input.ChecksDir)
	if err != nil {
		return "", "", err
	}

	def := checks.Definition{
		APIVersion:     checks.APIVersion,
		ID:             id,
		Name:           name,
		Status:         status,
		Source:         checks.SourceCustom,
		Description:    description,
		Instructions:   instructions,
		CategoriesHint: categories,
		SeverityHint:   severityHint,
		ConfidenceHint: confidenceHint,
		Scope: checks.Scope{
			IncludeGlobs: includeGlobs,
			ExcludeGlobs: excludeGlobs,
		},
		Origin: checks.Origin{
			Method: "manual",
		},
	}

	path, err := checks.WriteDefinition(dir, def, input.Overwrite)
	if err != nil {
		return "", "", err
	}
	return path, status, nil
}

func promptInput(reader *bufio.Reader, label string, defaultValue string) (string, error) {
	label = strings.TrimSpace(label)
	defaultValue = strings.TrimSpace(defaultValue)
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", label, defaultValue)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read input for %q: %w", label, err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue, nil
	}
	return line, nil
}

func normalizeExecutionModeFlag(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "sandboxed":
		return "sandboxed", nil
	case "host":
		return "host", nil
	default:
		return "", errors.New("--execution-mode must be sandboxed or host")
	}
}

func normalizeIsolationRuntimeFlag(raw string) (isolation.Runtime, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auto":
		return isolation.RuntimeAuto, nil
	case "docker":
		return isolation.RuntimeDocker, nil
	case "podman":
		return isolation.RuntimePodman, nil
	default:
		return "", errors.New("--runtime must be auto, docker, or podman")
	}
}

func normalizeIsolationNetworkFlag(raw string) (isolation.NetworkPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "unrestricted":
		return isolation.NetworkUnrestricted, nil
	case "none":
		return isolation.NetworkNone, nil
	default:
		return "", errors.New("--network must be unrestricted or none")
	}
}

func normalizeIsolationPullFlag(raw string) (isolation.PullPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "always":
		return isolation.PullAlways, nil
	case "if-missing":
		return isolation.PullIfMissing, nil
	case "never":
		return isolation.PullNever, nil
	default:
		return "", errors.New("--pull must be always, if-missing, or never")
	}
}

func normalizeIsolationAuthFlag(raw string) (isolation.AuthMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auto":
		return isolation.AuthAuto, nil
	case "subscription":
		return isolation.AuthSubscription, nil
	case "api-key":
		return isolation.AuthAPIKey, nil
	default:
		return "", errors.New("--auth-mode must be auto, subscription, or api-key")
	}
}

func normalizeSandboxModeFlag(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "read-only":
		return "read-only", nil
	case "workspace-write":
		return "workspace-write", nil
	case "danger-full-access":
		return "danger-full-access", nil
	default:
		return "", errors.New("--codex-sandbox must be read-only, workspace-write, or danger-full-access")
	}
}

func usageError(msg string) error {
	printUsage()
	return errors.New(msg)
}

func printUsage() {
	fmt.Println("Governor CLI")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  governor audit <path-or-zip> [flags]")
	fmt.Println("  governor isolate audit <path-or-zip> [flags]")
	fmt.Println("  governor checks <init|add|extract|list|validate|doctor|explain|enable|disable> [flags]")
	fmt.Println("")
	fmt.Println("Flags (audit):")
	fmt.Println("  --out <dir>         Output directory (default ./.governor/runs/<timestamp>)")
	fmt.Println("  --workers <1-3>     Max concurrent worker processes (default 3)")
	fmt.Println("  --codex-bin <path>  Codex executable (default codex)")
	fmt.Println("  --allow-custom-codex-bin  Allow non-default codex binary (for testing)")
	fmt.Println("  --execution-mode <sandboxed|host>  Worker execution mode (default sandboxed)")
	fmt.Println("  --codex-sandbox <read-only|workspace-write|danger-full-access>  Sandbox mode for sandboxed execution")
	fmt.Println("  --max-files <n>     Included file count cap (default 20000)")
	fmt.Println("  --max-bytes <n>     Included file bytes cap (default 262144000)")
	fmt.Println("  --timeout <dur>     Per-worker timeout (default 4m)")
	fmt.Println("  --verbose           Verbose execution logs")
	fmt.Println("  --checks-dir <dir>  Custom checks dir (default ./.governor/checks + ~/.governor/checks, repo first)")
	fmt.Println("  --only-check <id>   Run only specified check ID (repeatable)")
	fmt.Println("  --skip-check <id>   Skip specified check ID (repeatable)")
	fmt.Println("  --no-custom-checks  Disable custom check loading")
	fmt.Println("  --keep-workspace-error  Retain staged workspace on warning/failed runs (default deletes)")
	fmt.Println("  --tui               Enable interactive terminal UI")
	fmt.Println("  --no-tui            Disable interactive terminal UI")
	fmt.Println("")
	fmt.Println("Flags (isolate audit):")
	fmt.Println("  --out <dir>         Output directory for artifacts (default ./.governor/runs/<timestamp>)")
	fmt.Println("  --runtime <name>    Container runtime: auto|docker|podman (default auto)")
	fmt.Println("  --image <ref>       Runner image (default governor-runner:local)")
	fmt.Println("  --network <mode>    Network policy: unrestricted|none (default none)")
	fmt.Println("  --pull <policy>     Image pull policy: always|if-missing|never (default never)")
	fmt.Println("  --clean-image       Remove runner image after run")
	fmt.Println("  --auth-mode <mode>  Auth mode: auto|subscription|api-key (default subscription)")
	fmt.Println("  --codex-home <dir>  Host codex home for subscription auth bundle (default ~/.codex)")
	fmt.Println("  --execution-mode <sandboxed|host>  Inner worker execution mode (default host)")
	fmt.Println("  --codex-sandbox <read-only|workspace-write|danger-full-access>  Inner sandbox mode (used when execution is sandboxed)")
	fmt.Println("  --workers <1-3>     Max worker processes inside isolated run (default 3)")
	fmt.Println("  --checks-dir <dir>  Mount custom checks read-only into isolated run")
	fmt.Println("  --only-check <id>   Run only specified check ID (repeatable)")
	fmt.Println("  --skip-check <id>   Skip specified check ID (repeatable)")
	fmt.Println("  --no-custom-checks  Disable custom check loading")
	fmt.Println("  --keep-workspace-error  Retain staged workspace on warning/failed runs (default deletes)")
}

type listFlag struct {
	values []string
}

func (f *listFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(f.values, ",")
}

func (f *listFlag) Set(value string) error {
	parts := strings.Split(value, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			f.values = append(f.values, part)
		}
	}
	return nil
}

func (f *listFlag) Values() []string {
	if f == nil || len(f.values) == 0 {
		return nil
	}
	out := make([]string, 0, len(f.values))
	for _, v := range f.values {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
