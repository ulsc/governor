package cmd

import (
	"context"
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
	checksDir := fs.String("checks-dir", "", "Checks directory (default ~/.governor/checks)")
	noCustomChecks := fs.Bool("no-custom-checks", false, "Run built-in checks only")

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

		ChecksDir:      *checksDir,
		NoCustomChecks: *noCustomChecks,
		OnlyChecks:     onlyChecks.Values(),
		SkipChecks:     skipChecks.Values(),
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

	out := fs.String("out", "", "Output directory for run artifacts (required in isolate mode)")
	runtimeName := fs.String("runtime", "auto", "Container runtime: auto|docker|podman")
	image := fs.String("image", isolation.DefaultImage, "Container image for isolated governor runner")
	network := fs.String("network", "codex-only", "Network policy: codex-only|none")
	pull := fs.String("pull", "if-missing", "Image pull policy: always|if-missing|never")
	cleanImage := fs.Bool("clean-image", false, "Remove runner image after execution")
	authMode := fs.String("auth-mode", "auto", "Auth mode: auto|subscription|api-key")
	codexHome := fs.String("codex-home", "~/.codex", "Host codex home used for subscription auth bundle")

	workers := fs.Int("workers", 3, "Max concurrent worker processes inside isolated run (1-3)")
	maxFiles := fs.Int("max-files", 20000, "Maximum included file count")
	maxBytes := fs.Int64("max-bytes", 250*1024*1024, "Maximum included file bytes")
	timeout := fs.Duration("timeout", 4*time.Minute, "Per-worker timeout")
	verbose := fs.Bool("verbose", false, "Enable verbose logs")
	checksDir := fs.String("checks-dir", "", "Checks directory mounted read-only (optional)")
	noCustomChecks := fs.Bool("no-custom-checks", false, "Run built-in checks only")

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

	return isolation.RunAudit(context.Background(), isolation.AuditOptions{
		InputPath: positionalInput,
		OutDir:    *out,
		ChecksDir: *checksDir,

		Runtime:       runtimeValue,
		Image:         strings.TrimSpace(*image),
		NetworkPolicy: networkValue,
		PullPolicy:    pullValue,
		CleanImage:    *cleanImage,

		AuthMode:  authValue,
		CodexHome: strings.TrimSpace(*codexHome),

		Workers:  *workers,
		MaxFiles: *maxFiles,
		MaxBytes: *maxBytes,
		Timeout:  *timeout,
		Verbose:  *verbose,

		NoCustomChecks: *noCustomChecks,
		OnlyChecks:     onlyChecks.Values(),
		SkipChecks:     skipChecks.Values(),
	})
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

func runChecks(args []string) error {
	if len(args) == 0 {
		return usageError("usage: governor checks <add|extract|list|validate|enable|disable> [flags]")
	}

	switch args[0] {
	case "add":
		return runChecksAdd(args[1:])
	case "extract":
		return runChecksExtract(args[1:])
	case "list":
		return runChecksList(args[1:])
	case "validate":
		return runChecksValidate(args[1:])
	case "enable":
		return runChecksStatus(args[1:], checks.StatusEnabled)
	case "disable":
		return runChecksStatus(args[1:], checks.StatusDisabled)
	default:
		return usageError(fmt.Sprintf("unknown checks subcommand %q", args[0]))
	}
}

func runChecksAdd(args []string) error {
	fs := flag.NewFlagSet("checks add", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ~/.governor/checks)")
	id := fs.String("id", "", "Check ID (slug)")
	name := fs.String("name", "", "Check name")
	description := fs.String("description", "", "Check description")
	instructions := fs.String("instructions", "", "Check instructions text")
	instructionsFile := fs.String("instructions-file", "", "Path to instructions file")
	severityHint := fs.String("severity-hint", "", "severity hint (critical|high|medium|low|info)")
	confidenceHint := fs.Float64("confidence-hint", 0.8, "confidence hint (0..1)")

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
	if instructionsText == "" {
		return errors.New("instructions are required")
	}

	dir, err := checks.ResolveDir(*checksDir)
	if err != nil {
		return err
	}

	def := checks.Definition{
		APIVersion:   checks.APIVersion,
		ID:           strings.TrimSpace(*id),
		Name:         strings.TrimSpace(*name),
		Status:       checks.StatusDraft,
		Source:       checks.SourceCustom,
		Description:  strings.TrimSpace(*description),
		Instructions: instructionsText,
		Scope: checks.Scope{
			IncludeGlobs: includeGlobs.Values(),
			ExcludeGlobs: excludeGlobs.Values(),
		},
		CategoriesHint: categories.Values(),
		SeverityHint:   strings.TrimSpace(*severityHint),
		ConfidenceHint: *confidenceHint,
		Origin: checks.Origin{
			Method: "manual",
		},
	}

	path, err := checks.WriteDefinition(dir, def, false)
	if err != nil {
		return err
	}

	fmt.Printf("created check: %s\n", path)
	fmt.Println("status: draft")
	return nil
}

func runChecksExtract(args []string) error {
	fs := flag.NewFlagSet("checks extract", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ~/.governor/checks)")
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

	checksDir := fs.String("checks-dir", "", "Checks directory (default ~/.governor/checks)")
	statusFilter := fs.String("status", "", "status filter: draft|enabled|disabled")
	sourceFilter := fs.String("source", "", "source filter: builtin|custom")
	includeBuiltins := fs.Bool("include-builtins", true, "Include built-in checks")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks list does not accept positional args")
	}

	dir, err := checks.ResolveDir(*checksDir)
	if err != nil {
		return err
	}
	customDefs, warnings, err := checks.LoadCustomDir(dir)
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

	checksDir := fs.String("checks-dir", "", "Checks directory (default ~/.governor/checks)")
	includeBuiltins := fs.Bool("include-builtins", true, "Include built-in checks in duplicate-ID validation")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks validate does not accept positional args")
	}

	dir, err := checks.ResolveDir(*checksDir)
	if err != nil {
		return err
	}
	customDefs, warnings, err := checks.LoadCustomDir(dir)
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

	checksDir := fs.String("checks-dir", "", "Checks directory (default ~/.governor/checks)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return errors.New("expected check id")
	}
	id := fs.Args()[0]

	dir, err := checks.ResolveDir(*checksDir)
	if err != nil {
		return err
	}
	path, err := checks.UpdateStatus(dir, id, status)
	if err != nil {
		return err
	}

	fmt.Printf("updated %s -> %s\n", id, status)
	fmt.Printf("file: %s\n", path)
	return nil
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
	case "codex-only":
		return isolation.NetworkCodexOnly, nil
	case "none":
		return isolation.NetworkNone, nil
	default:
		return "", errors.New("--network must be codex-only or none")
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
	fmt.Println("  governor checks <add|extract|list|validate|enable|disable> [flags]")
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
	fmt.Println("  --checks-dir <dir>  Custom checks directory (default ~/.governor/checks)")
	fmt.Println("  --only-check <id>   Run only specified check ID (repeatable)")
	fmt.Println("  --skip-check <id>   Skip specified check ID (repeatable)")
	fmt.Println("  --no-custom-checks  Disable custom check loading")
	fmt.Println("  --tui               Enable interactive terminal UI")
	fmt.Println("  --no-tui            Disable interactive terminal UI")
	fmt.Println("")
	fmt.Println("Flags (isolate audit):")
	fmt.Println("  --out <dir>         Output directory for artifacts (required)")
	fmt.Println("  --runtime <name>    Container runtime: auto|docker|podman (default auto)")
	fmt.Println("  --image <ref>       Runner image (default governor-runner:local)")
	fmt.Println("  --network <mode>    Network policy: codex-only|none (default codex-only)")
	fmt.Println("  --pull <policy>     Image pull policy: always|if-missing|never (default if-missing)")
	fmt.Println("  --clean-image       Remove runner image after run")
	fmt.Println("  --auth-mode <mode>  Auth mode: auto|subscription|api-key (default auto)")
	fmt.Println("  --codex-home <dir>  Host codex home for subscription auth bundle (default ~/.codex)")
	fmt.Println("  --workers <1-3>     Max worker processes inside isolated run (default 3)")
	fmt.Println("  --checks-dir <dir>  Mount custom checks read-only into isolated run")
	fmt.Println("  --only-check <id>   Run only specified check ID (repeatable)")
	fmt.Println("  --skip-check <id>   Skip specified check ID (repeatable)")
	fmt.Println("  --no-custom-checks  Disable custom check loading")
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
