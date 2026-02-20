package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"governor/internal/ai"
	"governor/internal/app"
	"governor/internal/badge"
	"governor/internal/checks"
	"governor/internal/checkstui"
	"governor/internal/comment"
	"governor/internal/config"
	"governor/internal/detect"
	"governor/internal/diff"
	"governor/internal/doctor"
	"governor/internal/extractor"
	"governor/internal/fix"
	"governor/internal/intake"
	"governor/internal/isolation"
	"governor/internal/matrix"
	"governor/internal/model"
	"governor/internal/policy"
	"governor/internal/progress"
	reportpkg "governor/internal/report"
	"governor/internal/safefile"
	"governor/internal/scan"
	"governor/internal/suppress"
	"governor/internal/taps"
	tapstrust "governor/internal/taps/trust"
	"governor/internal/trust"
	"governor/internal/tui"
	"governor/internal/update"
	"governor/internal/version"
	"governor/internal/worker"
)

func Execute(args []string) error {
	if len(args) == 0 {
		return usageError("missing command")
	}

	switch args[0] {
	case "audit":
		return runAudit(args[1:])
	case "ci":
		return runCI(args[1:])
	case "findings":
		return runFindings(args[1:])
	case "isolate":
		return runIsolate(args[1:])
	case "checks":
		return runChecks(args[1:])
	case "hooks":
		return runHooks(args[1:])
	case "diff":
		return runDiff(args[1:])
	case "scan":
		return runScan(args[1:])
	case "fix":
		return runFix(args[1:])
	case "badge":
		return runBadge(args[1:])
	case "matrix":
		return runMatrix(args[1:])
	case "policy":
		return runPolicy(args[1:])
	case "init":
		return runInit(args[1:])
	case "quickstart":
		return runQuickstart(args[1:])
	case "clear":
		return runClear(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "version", "--version", "-v":
		fmt.Println("governor " + version.Version)
		update.PrintNotice(<-update.CheckAsync())
		return nil
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
	failOn := fs.String("fail-on", "", "Exit non-zero if any finding meets or exceeds severity: critical|high|medium|low|info")
	failOnExploitability := fs.String("fail-on-exploitability", "", "Exit non-zero if any finding meets or exceeds exploitability: confirmed-path|reachable|theoretical")
	maxNewReachable := fs.Int("max-new-reachable", -1, "Exit non-zero if reachable/confirmed-path new findings exceed this count (-1 disables)")
	minConfidenceForBlock := fs.Float64("min-confidence-for-block", -1, "Only block on findings with confidence >= threshold (0.0-1.0, default -1 disables)")
	requireAttackPathForBlocking := fs.Bool("require-attack-path-for-blocking", false, "Only block findings that include non-empty attack_path")
	baseline := fs.String("baseline", "", "Path to a previous audit.json for diff comparison")
	workers := fs.Int("workers", 3, "Max concurrent worker processes (1-3)")
	aiProfile := fs.String("ai-profile", "codex", "AI profile name (default codex)")
	aiProvider := fs.String("ai-provider", "", "AI provider override: codex-cli|openai-compatible")
	aiModel := fs.String("ai-model", "", "AI model override")
	aiAuthMode := fs.String("ai-auth-mode", "", "AI auth override: auto|account|api-key")
	aiBaseURL := fs.String("ai-base-url", "", "AI base URL override for openai-compatible providers")
	aiAPIKeyEnv := fs.String("ai-api-key-env", "", "AI API key environment variable override")

	var aiBin string
	fs.StringVar(&aiBin, "ai-bin", "codex", "AI CLI executable path (used by codex-cli provider)")
	fs.StringVar(&aiBin, "codex-bin", "codex", "Deprecated alias for --ai-bin")

	var allowCustomAIBin bool
	fs.BoolVar(&allowCustomAIBin, "allow-custom-ai-bin", false, "Allow non-default AI binary path (for testing only)")
	fs.BoolVar(&allowCustomAIBin, "allow-custom-codex-bin", false, "Deprecated alias for --allow-custom-ai-bin")

	executionMode := fs.String("execution-mode", "sandboxed", "AI execution mode: sandboxed|host")

	var aiSandbox string
	fs.StringVar(&aiSandbox, "ai-sandbox", "read-only", "AI sandbox mode for sandboxed execution: read-only|workspace-write|danger-full-access")
	fs.StringVar(&aiSandbox, "codex-sandbox", "read-only", "Deprecated alias for --ai-sandbox")

	maxFiles := fs.Int("max-files", 20000, "Maximum included file count")
	maxBytes := fs.Int64("max-bytes", 250*1024*1024, "Maximum included file bytes")
	timeout := fs.Duration("timeout", 4*time.Minute, "Per-worker timeout (0 disables timeout)")
	verbose := fs.Bool("verbose", false, "Enable verbose logs")
	enableTUI := fs.Bool("tui", false, "Enable interactive terminal UI")
	disableTUI := fs.Bool("no-tui", false, "Disable interactive terminal UI")
	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks + ~/.governor/checks, repo first)")
	noCustomChecks := fs.Bool("no-custom-checks", false, "Run built-in checks only")
	keepWorkspaceError := fs.Bool("keep-workspace-error", false, "Retain staged workspace only when run ends with warning/failed status")
	allowExistingOutDir := fs.Bool("allow-existing-out-dir", false, "Allow using an existing empty output directory (internal use)")
	sandboxDenyHostFallback := fs.Bool("sandbox-deny-host-fallback", false, "Automatically rerun tracks in host mode when sandbox denies file access (internal use)")
	includeTestFiles := fs.Bool("include-test-files", false, "Include test files in security scanning (excluded by default)")
	suppressionsPath := fs.String("suppressions", "", "Path to suppressions YAML file (default ./.governor/suppressions.yaml if present)")
	showSuppressed := fs.Bool("show-suppressed", false, "Include suppressed findings in reports")
	quick := fs.Bool("quick", false, "Run only rule-engine checks (no AI, no network)")
	policyPath := fs.String("policy", "", "Path to policy file (default ./.governor/policy.yaml if present)")
	requirePolicy := fs.Bool("require-policy", false, "Fail if no policy file is found")
	changedOnly := fs.Bool("changed-only", false, "Scan only files with uncommitted changes (vs HEAD)")
	changedSince := fs.String("changed-since", "", "Scan only files changed since a git ref")
	staged := fs.Bool("staged", false, "Scan only staged files (for pre-commit use)")
	ignoreFile := fs.String("ignore-file", "", "Path to .governorignore file (default .governorignore if present)")
	maxRuleFileBytes := fs.Int("max-rule-file-bytes", 0, "Max file size for rule-engine scanning (default 2MB, max 20MB)")

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

	// Validate mutual exclusivity of git filter flags.
	gitFilterCount := 0
	if *changedOnly {
		gitFilterCount++
	}
	if *changedSince != "" {
		gitFilterCount++
	}
	if *staged {
		gitFilterCount++
	}
	if gitFilterCount > 1 {
		return errors.New("--changed-only, --changed-since, and --staged are mutually exclusive")
	}

	// Resolve suppressions path: explicit flag > default location.
	if strings.TrimSpace(*suppressionsPath) == "" {
		defaultSuppPath := suppress.DefaultPath(".")
		if _, statErr := os.Stat(defaultSuppPath); statErr == nil {
			*suppressionsPath = defaultSuppPath
		}
	}

	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", cfgErr)
	}
	setFlags := flagsExplicitlySet(fs)
	applyConfig(cfg, setFlags, map[string]*string{
		"ai-profile":     aiProfile,
		"ai-provider":    aiProvider,
		"ai-model":       aiModel,
		"ai-auth-mode":   aiAuthMode,
		"ai-base-url":    aiBaseURL,
		"ai-api-key-env": aiAPIKeyEnv,
		"execution-mode": executionMode,
		"checks-dir":     checksDir,
		"fail-on":        failOn,
		"baseline":       baseline,
	}, map[string]*int{
		"workers":   workers,
		"max-files": maxFiles,
	}, map[string]*bool{
		"verbose":          verbose,
		"no-custom-checks": noCustomChecks,
	})
	if _, ok := setFlags["ai-bin"]; !ok && cfg.AIBin != "" {
		aiBin = cfg.AIBin
	}
	if _, ok := setFlags["ai-sandbox"]; !ok && cfg.AISandbox != "" {
		aiSandbox = cfg.AISandbox
	}
	if _, ok := setFlags["max-bytes"]; !ok && cfg.MaxBytes != nil {
		*maxBytes = *cfg.MaxBytes
	}
	if _, ok := setFlags["timeout"]; !ok && cfg.Timeout != "" {
		if d, parseErr := time.ParseDuration(cfg.Timeout); parseErr == nil {
			*timeout = d
		}
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
	if *timeout < 0 {
		return errors.New("--timeout must be >= 0 (0 disables timeout)")
	}
	if strings.TrimSpace(aiBin) == "" {
		return errors.New("--ai-bin cannot be empty")
	}
	if *maxRuleFileBytes < 0 || (*maxRuleFileBytes > 0 && *maxRuleFileBytes > worker.MaxAllowedRuleFileBytes) {
		return fmt.Errorf("--max-rule-file-bytes must be between 0 and %d", worker.MaxAllowedRuleFileBytes)
	}
	if *maxNewReachable < -1 {
		return errors.New("--max-new-reachable must be >= -1")
	}
	if *minConfidenceForBlock != -1 && (*minConfidenceForBlock < 0 || *minConfidenceForBlock > 1) {
		return errors.New("--min-confidence-for-block must be between 0.0 and 1.0 (or -1 to disable)")
	}
	if *enableTUI && *disableTUI {
		return errors.New("cannot set both --tui and --no-tui")
	}

	modeValue, err := normalizeExecutionModeFlag(*executionMode)
	if err != nil {
		return err
	}
	sandboxValue, err := normalizeSandboxModeFlag(aiSandbox)
	if err != nil {
		return err
	}
	if modeValue == "host" {
		sandboxValue = ""
	}

	resolvedPolicyPath, loadedPolicy, hasPolicy, err := resolvePolicyInput(*policyPath, *requirePolicy)
	if err != nil {
		return err
	}

	// Auto-fall-back to quick (rule-only) mode when no AI is configured.
	_, explicitQuick := setFlags["quick"]
	autoQuick := shouldAutoQuick(explicitQuick, cfg, setFlags)
	if autoQuick {
		*quick = true
	}

	updateCh := update.CheckAsync()

	selOpts := checks.AuditSelectionOptions{
		ChecksDir:      *checksDir,
		NoCustomChecks: *noCustomChecks,
		OnlyIDs:        onlyChecks.Values(),
		SkipIDs:        skipChecks.Values(),
	}
	if *quick {
		selOpts.EngineFilter = checks.EngineRule
	}
	selection, err := checks.ResolveAuditSelection(selOpts)
	if err != nil {
		return err
	}

	var aiRuntime ai.Runtime
	aiInfo := trust.AIBinary{}
	if *quick {
		// Quick mode: skip AI resolution entirely.
	} else {
		aiRequired := checks.SelectionRequiresAI(selection.Checks)
		aiRuntime, err = ai.ResolveRuntime(ai.ResolveOptions{
			Profile:       strings.TrimSpace(*aiProfile),
			Provider:      strings.TrimSpace(*aiProvider),
			Model:         strings.TrimSpace(*aiModel),
			AuthMode:      strings.TrimSpace(*aiAuthMode),
			Bin:           strings.TrimSpace(aiBin),
			BaseURL:       strings.TrimSpace(*aiBaseURL),
			APIKeyEnv:     strings.TrimSpace(*aiAPIKeyEnv),
			ExecutionMode: modeValue,
			SandboxMode:   sandboxValue,
		})
		if err != nil {
			return err
		}

		if aiRequired && aiRuntime.UsesCLI() {
			aiInfo, err = trust.ResolveAIBinary(context.Background(), aiRuntime.Bin, allowCustomAIBin)
			if err != nil {
				return err
			}
			aiRuntime.Bin = aiInfo.ResolvedPath
		}
	}

	useTUI := isInteractiveTerminal()
	if *enableTUI {
		useTUI = true
	}
	if *disableTUI {
		useTUI = false
	}

	auditOpts := app.AuditOptions{
		InputPath:     positionalInput,
		OutDir:        *out,
		AIRuntime:     aiRuntime,
		AIBin:         aiInfo.ResolvedPath,
		AIVersion:     aiInfo.Version,
		AISHA256:      aiInfo.SHA256,
		AIRequest:     aiInfo.RequestedPath,
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

		BaselinePath:     strings.TrimSpace(*baseline),
		SuppressionsPath: strings.TrimSpace(*suppressionsPath),
		ShowSuppressed:   *showSuppressed,
		IncludeTestFiles: *includeTestFiles,
		Quick:            *quick,
		ChangedOnly:      *changedOnly,
		ChangedSince:     *changedSince,
		StagedOnly:       *staged,

		IgnoreFile:       resolveIgnoreFile(*ignoreFile),
		MaxRuleFileBytes: *maxRuleFileBytes,
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
		var diffReport *diff.DiffReport
		if result.paths.DiffPath != "" {
			diffReport, err = loadDiffReport(result.paths.DiffPath)
			if err != nil {
				return err
			}
		}
		if hasPolicy {
			decision := policy.Evaluate(resolvedPolicyPath, loadedPolicy, result.report, diffReport)
			result.report.PolicyDecision = &decision
			result.report.RunMetadata.PolicyPath = resolvedPolicyPath
			result.report.RunMetadata.PolicyVersion = loadedPolicy.APIVersion
			if err := persistAuditArtifacts(result.paths, result.report); err != nil {
				return err
			}
		}
		printAuditSummary(result.report, result.paths)
		update.PrintNotice(<-updateCh)
		if err := checkPolicyDecision(result.report.PolicyDecision); err != nil {
			return err
		}
		return checkRiskGates(result.report, diffReport, riskGateOptions{
			FailOnSeverity:               *failOn,
			FailOnExploitability:         *failOnExploitability,
			MaxNewReachable:              *maxNewReachable,
			MinConfidenceForBlock:        *minConfidenceForBlock,
			RequireAttackPathForBlocking: *requireAttackPathForBlocking,
		})
	}

	auditOpts.Progress = progress.NewPlainSink(os.Stderr)
	report, paths, err := app.RunAudit(context.Background(), auditOpts)
	if err != nil {
		return err
	}
	var diffReport *diff.DiffReport
	if paths.DiffPath != "" {
		diffReport, err = loadDiffReport(paths.DiffPath)
		if err != nil {
			return err
		}
	}
	if hasPolicy {
		decision := policy.Evaluate(resolvedPolicyPath, loadedPolicy, report, diffReport)
		report.PolicyDecision = &decision
		report.RunMetadata.PolicyPath = resolvedPolicyPath
		report.RunMetadata.PolicyVersion = loadedPolicy.APIVersion
		if err := persistAuditArtifacts(paths, report); err != nil {
			return err
		}
	}
	detected := detect.Project(positionalInput)
	if detected.Label != "" {
		fmt.Printf("detected:       %s\n", detected.Label)
	}
	printAuditSummary(report, paths)
	if autoQuick {
		printAutoQuickHint(report.RunMetadata.RuleChecks)
	}
	update.PrintNotice(<-updateCh)
	if err := checkPolicyDecision(report.PolicyDecision); err != nil {
		return err
	}
	return checkRiskGates(report, diffReport, riskGateOptions{
		FailOnSeverity:               *failOn,
		FailOnExploitability:         *failOnExploitability,
		MaxNewReachable:              *maxNewReachable,
		MinConfidenceForBlock:        *minConfidenceForBlock,
		RequireAttackPathForBlocking: *requireAttackPathForBlocking,
	})
}

func printAutoQuickHint(ruleChecks int) {
	fmt.Fprintf(os.Stderr, "\n%d rule-engine checks completed (no AI key needed)\n", ruleChecks)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Want deeper analysis? Add an AI profile:")
	fmt.Fprintln(os.Stderr, "  governor init --ai-profile openai")
	fmt.Fprintln(os.Stderr, "  export OPENAI_API_KEY=sk-...")
	fmt.Fprintln(os.Stderr, "  governor audit .")
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
	failOn := fs.String("fail-on", "", "Exit non-zero if any finding meets or exceeds severity: critical|high|medium|low|info")
	runtimeName := fs.String("runtime", "auto", "Container runtime: auto|docker|podman")
	image := fs.String("image", isolation.DefaultImage, "Container image for isolated governor runner")
	network := fs.String("network", "none", "Network policy: unrestricted|none")
	pull := fs.String("pull", "never", "Image pull policy: always|if-missing|never")
	cleanImage := fs.Bool("clean-image", false, "Remove runner image after execution")
	authMode := fs.String("auth-mode", "account", "Auth mode: auto|account|api-key")
	aiHome := fs.String("ai-home", "~/.codex", "Host AI account home used for account auth bundle")
	fs.StringVar(aiHome, "codex-home", "~/.codex", "Deprecated alias for --ai-home")

	aiProfile := fs.String("ai-profile", "codex", "AI profile name (default codex)")
	aiProvider := fs.String("ai-provider", "", "AI provider override: codex-cli|openai-compatible")
	aiModel := fs.String("ai-model", "", "AI model override")
	aiAuthMode := fs.String("ai-auth-mode", "", "AI auth override: auto|account|api-key")
	aiBaseURL := fs.String("ai-base-url", "", "AI base URL override for openai-compatible providers")
	aiAPIKeyEnv := fs.String("ai-api-key-env", "", "AI API key environment variable override")

	var aiBin string
	fs.StringVar(&aiBin, "ai-bin", "codex", "AI CLI executable path for codex-cli provider")
	fs.StringVar(&aiBin, "codex-bin", "codex", "Deprecated alias for --ai-bin")

	workers := fs.Int("workers", 3, "Max concurrent worker processes inside isolated run (1-3)")
	executionMode := fs.String("execution-mode", "host", "Inner worker execution mode: sandboxed|host")

	var aiSandbox string
	fs.StringVar(&aiSandbox, "ai-sandbox", "read-only", "Inner sandbox mode (sandboxed execution): read-only|workspace-write|danger-full-access")
	fs.StringVar(&aiSandbox, "codex-sandbox", "read-only", "Deprecated alias for --ai-sandbox")

	maxFiles := fs.Int("max-files", 20000, "Maximum included file count")
	maxBytes := fs.Int64("max-bytes", 250*1024*1024, "Maximum included file bytes")
	timeout := fs.Duration("timeout", 4*time.Minute, "Per-worker timeout (0 disables timeout)")
	verbose := fs.Bool("verbose", false, "Enable verbose logs")
	checksDir := fs.String("checks-dir", "", "Checks directory mounted read-only (optional)")
	noCustomChecks := fs.Bool("no-custom-checks", false, "Run built-in checks only")
	keepWorkspaceError := fs.Bool("keep-workspace-error", false, "Retain staged workspace only when run ends with warning/failed status")

	includeTestFiles := fs.Bool("include-test-files", false, "Include test files in security scanning (excluded by default)")

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
	sandboxValue, err := normalizeSandboxModeFlag(aiSandbox)
	if err != nil {
		return err
	}
	if modeValue == "host" {
		sandboxValue = ""
	}
	aiRuntime, err := ai.ResolveRuntime(ai.ResolveOptions{
		Profile:       strings.TrimSpace(*aiProfile),
		Provider:      strings.TrimSpace(*aiProvider),
		Model:         strings.TrimSpace(*aiModel),
		AuthMode:      strings.TrimSpace(*aiAuthMode),
		Bin:           strings.TrimSpace(aiBin),
		BaseURL:       strings.TrimSpace(*aiBaseURL),
		APIKeyEnv:     strings.TrimSpace(*aiAPIKeyEnv),
		ExecutionMode: modeValue,
		SandboxMode:   sandboxValue,
		AccountHome:   strings.TrimSpace(*aiHome),
	})
	if err != nil {
		return err
	}

	updateCh := update.CheckAsync()

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
		AIRuntime: aiRuntime,
		AIHome:    strings.TrimSpace(*aiHome),

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
		IncludeTestFiles:     *includeTestFiles,
	}); err != nil {
		return err
	}
	report, reportErr := loadIsolateAuditReport(outDir)
	if reportErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", reportErr)
		printIsolateArtifactPaths(outDir)
		return nil
	}
	printAuditSummary(report, isolateArtifactPaths(outDir))
	update.PrintNotice(<-updateCh)
	return checkFailOn(*failOn, report)
}

func printAuditSummary(report model.AuditReport, paths app.ArtifactPaths) {
	fmt.Printf("run id:         %s\n", report.RunMetadata.RunID)
	fmt.Printf("artifacts dir:  %s\n", paths.RunDir)
	fmt.Printf("audit markdown: %s\n", filepath.Clean(paths.MarkdownPath))
	fmt.Printf("audit json:     %s\n", filepath.Clean(paths.JSONPath))
	fmt.Printf("audit html:     %s\n", filepath.Clean(paths.HTMLPath))
	if paths.SARIFPath != "" {
		fmt.Printf("audit sarif:    %s\n", filepath.Clean(paths.SARIFPath))
	}
	if paths.DiffPath != "" {
		fmt.Printf("audit diff:     %s\n", filepath.Clean(paths.DiffPath))
	}
	if strings.TrimSpace(report.RunMetadata.AIProfile) != "" {
		fmt.Printf("ai profile:     %s\n", report.RunMetadata.AIProfile)
	}
	if strings.TrimSpace(report.RunMetadata.AIProvider) != "" {
		fmt.Printf("ai provider:    %s\n", report.RunMetadata.AIProvider)
	}
	if strings.TrimSpace(report.RunMetadata.AIModel) != "" {
		fmt.Printf("ai model:       %s\n", report.RunMetadata.AIModel)
	}
	if strings.TrimSpace(report.RunMetadata.AIAuthMode) != "" {
		fmt.Printf("ai auth mode:   %s\n", report.RunMetadata.AIAuthMode)
	}
	if strings.TrimSpace(report.RunMetadata.AIRequestedBin) != "" {
		fmt.Printf("ai request:     %s\n", report.RunMetadata.AIRequestedBin)
	}
	if strings.TrimSpace(report.RunMetadata.AIBin) != "" {
		fmt.Printf("ai resolved:    %s\n", report.RunMetadata.AIBin)
	}
	if strings.TrimSpace(report.RunMetadata.AIVersion) != "" {
		fmt.Printf("ai version:     %s\n", report.RunMetadata.AIVersion)
	}
	fmt.Printf("ai required:    %t\n", report.RunMetadata.AIRequired)
	fmt.Printf("ai used:        %t\n", report.RunMetadata.AIUsed)
	if strings.TrimSpace(report.RunMetadata.ExecutionMode) != "" {
		mode := report.RunMetadata.ExecutionMode
		if strings.TrimSpace(report.RunMetadata.AISandbox) != "" {
			mode += " (sandbox=" + report.RunMetadata.AISandbox + ")"
		}
		fmt.Printf("execution:      %s\n", mode)
	}
	fmt.Printf("checks:         %d (builtin=%d custom=%d)\n",
		report.RunMetadata.EnabledChecks,
		report.RunMetadata.BuiltInChecks,
		report.RunMetadata.CustomChecks,
	)
	fmt.Printf("check engines:  ai=%d rule=%d\n",
		report.RunMetadata.AIChecks,
		report.RunMetadata.RuleChecks,
	)
	fmt.Printf("findings:       %d (critical=%d high=%d medium=%d low=%d info=%d)\n",
		len(report.Findings),
		report.CountsBySeverity["critical"],
		report.CountsBySeverity["high"],
		report.CountsBySeverity["medium"],
		report.CountsBySeverity["low"],
		report.CountsBySeverity["info"],
	)
	if report.SuppressedCount > 0 {
		fmt.Printf("suppressed:     %d\n", report.SuppressedCount)
	}

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
		SARIFPath:    filepath.Join(outDir, "audit.sarif"),
	}
}

func printIsolateArtifactPaths(outDir string) {
	paths := isolateArtifactPaths(outDir)
	fmt.Printf("artifacts dir:  %s\n", paths.RunDir)
	fmt.Printf("audit markdown: %s\n", filepath.Clean(paths.MarkdownPath))
	fmt.Printf("audit json:     %s\n", filepath.Clean(paths.JSONPath))
	fmt.Printf("audit html:     %s\n", filepath.Clean(paths.HTMLPath))
	fmt.Printf("audit sarif:    %s\n", filepath.Clean(paths.SARIFPath))
}

func loadIsolateAuditReport(outDir string) (model.AuditReport, error) {
	paths := isolateArtifactPaths(outDir)
	raw, err := os.ReadFile(paths.JSONPath)
	if err != nil {
		return model.AuditReport{}, fmt.Errorf("read isolated report %s: %w", paths.JSONPath, err)
	}
	var report model.AuditReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return model.AuditReport{}, fmt.Errorf("parse isolated report %s: %w", paths.JSONPath, err)
	}
	return report, nil
}

func checkSuppressionRatioCI(maxRatio float64, report model.AuditReport) error {
	if maxRatio >= 1.0 {
		return nil // disabled
	}
	total := len(report.Findings) + report.SuppressedCount
	if total == 0 {
		return nil
	}
	ratio := float64(report.SuppressedCount) / float64(total)
	if ratio > maxRatio {
		return fmt.Errorf("suppression ratio %.1f%% exceeds --max-suppression-ratio %.1f%% (%d suppressed / %d total)",
			ratio*100, maxRatio*100, report.SuppressedCount, total)
	}
	return nil
}

func checkFailOn(threshold string, report model.AuditReport) error {
	return checkFailOnWithFilters(threshold, report, -1, false)
}

type riskGateOptions struct {
	FailOnSeverity               string
	FailOnExploitability         string
	MaxNewReachable              int
	MinConfidenceForBlock        float64
	RequireAttackPathForBlocking bool
}

func checkRiskGates(report model.AuditReport, dr *diff.DiffReport, opts riskGateOptions) error {
	if err := checkFailOnWithFilters(opts.FailOnSeverity, report, opts.MinConfidenceForBlock, opts.RequireAttackPathForBlocking); err != nil {
		return err
	}
	if err := checkFailOnExploitability(opts.FailOnExploitability, report, opts.MinConfidenceForBlock, opts.RequireAttackPathForBlocking); err != nil {
		return err
	}
	if err := checkMaxNewReachable(opts.MaxNewReachable, report, dr, opts.MinConfidenceForBlock, opts.RequireAttackPathForBlocking); err != nil {
		return err
	}
	return nil
}

func checkFailOnWithFilters(threshold string, report model.AuditReport, minConfidence float64, requireAttackPath bool) error {
	threshold = strings.ToLower(strings.TrimSpace(threshold))
	if threshold == "" {
		return nil
	}
	thresholdWeight, ok := severityWeightMap[threshold]
	if !ok {
		return fmt.Errorf("invalid --fail-on severity %q (expected critical, high, medium, low, or info)", threshold)
	}
	filtered := filterBlockingCandidates(report.Findings, minConfidence, requireAttackPath)
	if len(filtered) == 0 {
		return nil
	}
	for _, f := range report.Findings {
		if !isBlockingCandidate(f, minConfidence, requireAttackPath) {
			continue
		}
		w, exists := severityWeightMap[strings.ToLower(strings.TrimSpace(f.Severity))]
		if !exists {
			w = severityWeightMap["info"]
		}
		if w <= thresholdWeight {
			return fmt.Errorf("findings exceed --fail-on threshold %q (%d finding(s) at or above %s severity)",
				threshold, countAtOrAbove(filtered, thresholdWeight), threshold)
		}
	}
	return nil
}

var severityWeightMap = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

var exploitabilityWeightMap = map[string]int{
	"confirmed-path": 0,
	"reachable":      1,
	"theoretical":    2,
}

func checkFailOnExploitability(threshold string, report model.AuditReport, minConfidence float64, requireAttackPath bool) error {
	threshold = strings.ToLower(strings.TrimSpace(threshold))
	if threshold == "" || threshold == "none" {
		return nil
	}
	thresholdWeight, ok := exploitabilityWeightMap[threshold]
	if !ok {
		return fmt.Errorf("invalid --fail-on-exploitability %q (expected confirmed-path, reachable, or theoretical)", threshold)
	}
	filtered := filterBlockingCandidates(report.Findings, minConfidence, requireAttackPath)
	if len(filtered) == 0 {
		return nil
	}
	count := 0
	for _, finding := range filtered {
		if exploitabilityWeight(finding.Exploitability) <= thresholdWeight {
			count++
		}
	}
	if count > 0 {
		return fmt.Errorf("findings exceed --fail-on-exploitability threshold %q (%d finding(s) at or above %s)", threshold, count, threshold)
	}
	return nil
}

func checkMaxNewReachable(maxNewReachable int, report model.AuditReport, dr *diff.DiffReport, minConfidence float64, requireAttackPath bool) error {
	if maxNewReachable < 0 {
		return nil
	}
	candidates := report.Findings
	scope := "active findings"
	if dr != nil {
		candidates = dr.New
		scope = "new findings"
	}
	filtered := filterBlockingCandidates(candidates, minConfidence, requireAttackPath)
	reachable := 0
	for _, finding := range filtered {
		if exploitabilityWeight(finding.Exploitability) <= exploitabilityWeightMap["reachable"] {
			reachable++
		}
	}
	if reachable > maxNewReachable {
		return fmt.Errorf("reachable %s %d exceed --max-new-reachable %d", scope, reachable, maxNewReachable)
	}
	return nil
}

func countAtOrAbove(findings []model.Finding, thresholdWeight int) int {
	n := 0
	for _, f := range findings {
		w, ok := severityWeightMap[strings.ToLower(strings.TrimSpace(f.Severity))]
		if !ok {
			w = severityWeightMap["info"]
		}
		if w <= thresholdWeight {
			n++
		}
	}
	return n
}

func countAtOrAboveCounts(counts map[string]int, thresholdWeight int) int {
	if len(counts) == 0 {
		return 0
	}
	total := 0
	for severity, count := range counts {
		weight, ok := severityWeightMap[strings.ToLower(strings.TrimSpace(severity))]
		if !ok {
			weight = severityWeightMap["info"]
		}
		if weight <= thresholdWeight {
			total += count
		}
	}
	return total
}

func filterBlockingCandidates(findings []model.Finding, minConfidence float64, requireAttackPath bool) []model.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if isBlockingCandidate(finding, minConfidence, requireAttackPath) {
			out = append(out, finding)
		}
	}
	return out
}

func isBlockingCandidate(finding model.Finding, minConfidence float64, requireAttackPath bool) bool {
	if minConfidence >= 0 && finding.Confidence < minConfidence {
		return false
	}
	if requireAttackPath {
		for _, step := range finding.AttackPath {
			if strings.TrimSpace(step) != "" {
				return true
			}
		}
		return false
	}
	return true
}

func exploitabilityWeight(value string) int {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if weight, ok := exploitabilityWeightMap[normalized]; ok {
		return weight
	}
	return len(exploitabilityWeightMap)
}

func runChecks(args []string) error {
	if len(args) == 0 {
		if isInteractiveTerminal() {
			return runChecksTUI(nil)
		}
		return runChecksList(nil)
	}

	switch args[0] {
	case "tui":
		return runChecksTUI(args[1:])
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
	case "test":
		return runChecksTest(args[1:])
	case "enable":
		return runChecksStatus(args[1:], checks.StatusEnabled)
	case "disable":
		return runChecksStatus(args[1:], checks.StatusDisabled)
	case "tap":
		return runChecksTap(args[1:])
	case "untap":
		return runChecksUntap(args[1:])
	case "install-pack":
		return runChecksInstallPack(args[1:])
	case "list-packs":
		return runChecksListPacks(args[1:])
	case "lock":
		return runChecksLock(args[1:])
	case "update-packs":
		return runChecksUpdatePacks(args[1:])
	case "trust":
		return runChecksTrust(args[1:])
	default:
		return usageError(fmt.Sprintf("unknown checks subcommand %q", args[0]))
	}
}

func runChecksTUI(args []string) error {
	fs := flag.NewFlagSet("checks tui", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks + ~/.governor/checks, repo first)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks tui does not accept positional args")
	}
	if !isInteractiveTerminal() {
		return errors.New("checks tui requires an interactive terminal")
	}
	return checkstui.Run(checkstui.Options{
		ChecksDir: *checksDir,
	})
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
	aiProfile := fs.String("ai-profile", "codex", "AI profile name (default codex)")
	aiProvider := fs.String("ai-provider", "", "AI provider override: codex-cli|openai-compatible")
	aiModel := fs.String("ai-model", "", "AI model override")
	aiAuthMode := fs.String("ai-auth-mode", "", "AI auth override: auto|account|api-key")
	aiBaseURL := fs.String("ai-base-url", "", "AI base URL override for openai-compatible providers")
	aiAPIKeyEnv := fs.String("ai-api-key-env", "", "AI API key environment variable override")

	var aiBin string
	fs.StringVar(&aiBin, "ai-bin", "codex", "AI CLI executable path (used by codex-cli provider)")
	fs.StringVar(&aiBin, "codex-bin", "codex", "Deprecated alias for --ai-bin")

	var allowCustomAIBin bool
	fs.BoolVar(&allowCustomAIBin, "allow-custom-ai-bin", false, "Allow non-default AI binary path (for testing only)")
	fs.BoolVar(&allowCustomAIBin, "allow-custom-codex-bin", false, "Deprecated alias for --allow-custom-ai-bin")

	executionMode := fs.String("execution-mode", "sandboxed", "AI execution mode: sandboxed|host")

	var aiSandbox string
	fs.StringVar(&aiSandbox, "ai-sandbox", "read-only", "AI sandbox mode for sandboxed execution: read-only|workspace-write|danger-full-access")
	fs.StringVar(&aiSandbox, "codex-sandbox", "read-only", "Deprecated alias for --ai-sandbox")

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
	if strings.TrimSpace(aiBin) == "" {
		return errors.New("--ai-bin cannot be empty")
	}
	modeValue, err := normalizeExecutionModeFlag(*executionMode)
	if err != nil {
		return err
	}
	sandboxValue, err := normalizeSandboxModeFlag(aiSandbox)
	if err != nil {
		return err
	}
	if modeValue == "host" {
		sandboxValue = ""
	}

	aiRuntime, err := ai.ResolveRuntime(ai.ResolveOptions{
		Profile:       strings.TrimSpace(*aiProfile),
		Provider:      strings.TrimSpace(*aiProvider),
		Model:         strings.TrimSpace(*aiModel),
		AuthMode:      strings.TrimSpace(*aiAuthMode),
		Bin:           strings.TrimSpace(aiBin),
		BaseURL:       strings.TrimSpace(*aiBaseURL),
		APIKeyEnv:     strings.TrimSpace(*aiAPIKeyEnv),
		ExecutionMode: modeValue,
		SandboxMode:   sandboxValue,
	})
	if err != nil {
		return err
	}

	if aiRuntime.UsesCLI() {
		aiInfo, err := trust.ResolveAIBinary(context.Background(), aiRuntime.Bin, allowCustomAIBin)
		if err != nil {
			return err
		}
		aiRuntime.Bin = aiInfo.ResolvedPath
	}

	res, err := extractor.Run(context.Background(), extractor.Options{
		AIRuntime: aiRuntime,
		Inputs:    inputValues,
		ChecksDir: *checksDir,
		CodexBin:  aiRuntime.Bin,
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

func runChecksTap(args []string) error {
	fs := flag.NewFlagSet("governor checks tap", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	list := fs.Bool("list", false, "List all registered taps")
	update := fs.Bool("update", false, "Update all registered taps")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *list {
		cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
		if err != nil {
			return err
		}
		if len(cfg.Taps) == 0 {
			fmt.Println("No taps registered. Use 'governor checks tap <source>' to add one.")
			return nil
		}
		for _, t := range cfg.Taps {
			fmt.Printf("%-30s %s\n", t.Name, t.URL)
		}
		return nil
	}

	if *update {
		cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
		if err != nil {
			return err
		}
		if len(cfg.Taps) == 0 {
			fmt.Println("No taps registered.")
			return nil
		}
		for _, t := range cfg.Taps {
			if err := taps.UpdateTap(t.Path); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to update %s: %v\n", t.Name, err)
				continue
			}
			fmt.Printf("Updated %s\n", t.Name)
		}
		return nil
	}

	if len(fs.Args()) == 0 {
		return errors.New("usage: governor checks tap [--list|--update] <source>")
	}

	source := fs.Args()[0]
	name, url := taps.ResolveSource(source)
	dest := filepath.Join(taps.DefaultTapsDir(), name)

	if err := taps.CloneTap(url, dest); err != nil {
		return err
	}

	cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
	if err != nil {
		return err
	}
	cfg.Taps = append(cfg.Taps, taps.Tap{
		Name:    name,
		URL:     url,
		Path:    dest,
		AddedAt: time.Now(),
	})
	if err := taps.SaveConfig(taps.DefaultConfigPath(), cfg); err != nil {
		return err
	}

	fmt.Printf("Tapped %s\n", name)
	return nil
}

func runChecksUntap(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: governor checks untap <name>")
	}
	name := args[0]

	cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
	if err != nil {
		return err
	}

	tap, found := taps.FindTap(cfg, name)
	if !found {
		return fmt.Errorf("tap %q not found", name)
	}

	if err := os.RemoveAll(tap.Path); err != nil {
		return fmt.Errorf("remove tap directory: %w", err)
	}

	taps.RemoveTap(cfg, name)
	if err := taps.SaveConfig(taps.DefaultConfigPath(), cfg); err != nil {
		return err
	}

	fmt.Printf("Untapped %s\n", name)
	return nil
}

func runChecksInstallPack(args []string) error {
	fs := flag.NewFlagSet("governor checks install-pack", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	unlock := fs.Bool("unlock", false, "Bypass lockfile resolution and install latest available pack")
	lockFile := fs.String("lock-file", "", "Path to checks lock file (default ./.governor/checks.lock.yaml)")
	trustPolicyPath := fs.String("trust-policy", "", "Path to check trust policy (default ./.governor/check-trust.yaml if present)")
	strictTrust := fs.Bool("strict-trust", false, "Block install when trust policy checks fail")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return errors.New("usage: governor checks install-pack [--unlock] <pack-name>")
	}
	packName := strings.TrimSpace(fs.Args()[0])

	cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
	if err != nil {
		return err
	}
	if len(cfg.Taps) == 0 {
		return errors.New("no taps registered; use 'governor checks tap <source>' first")
	}

	allPacks, err := taps.DiscoverPacks(cfg)
	if err != nil {
		return err
	}
	candidates := taps.FindPackCandidates(allPacks, packName)
	if len(candidates) == 0 {
		return fmt.Errorf("pack %q not found in any registered tap", packName)
	}

	lockPath := strings.TrimSpace(*lockFile)
	if lockPath == "" {
		lockPath = taps.DefaultLockPath()
	}
	lock, err := taps.LoadLock(lockPath)
	if err != nil {
		return err
	}

	resolvedTrustPolicyPath, trustPolicy, hasTrustPolicy, err := resolveTrustPolicy(*trustPolicyPath)
	if err != nil {
		return err
	}

	var selected taps.LocatedPack
	lockedPack, hasLocked := taps.FindLockedPack(lock, packName)
	if hasLocked && !*unlock {
		selected, err = taps.ResolveLockedPack(candidates, lockedPack)
		if err != nil {
			return fmt.Errorf("locked pack mismatch for %q: %w (run 'governor checks update-packs' or use --unlock)", packName, err)
		}
	} else {
		selected, err = taps.SelectLatestPack(candidates)
		if err != nil {
			return err
		}
	}
	if hasTrustPolicy {
		result := tapstrust.ValidatePack(lockedPack, hasLocked, selected, trustPolicy)
		emitTrustValidation(result)
		if tapstrust.ShouldBlock(trustPolicy.Mode, *strictTrust, result) {
			return fmt.Errorf("trust validation failed for pack %q (policy: %s)", packName, resolvedTrustPolicyPath)
		}
	}

	count, err := taps.CopyPackChecks(selected.Dir, ".governor/checks/")
	if err != nil {
		return err
	}

	taps.UpsertLockedPack(&lock, taps.LockedPackFromLocated(selected, time.Now().UTC()))
	if err := taps.SaveLock(lockPath, lock); err != nil {
		return err
	}

	versionLabel := strings.TrimSpace(selected.Version)
	if versionLabel == "" {
		versionLabel = "unversioned"
	}
	fmt.Printf("Installed pack %s@%s from %s (%d checks)\n", selected.Name, versionLabel, selected.TapName, count)
	fmt.Printf("lock file: %s\n", lockPath)
	return nil
}

func runChecksListPacks(args []string) error {
	if len(args) != 0 {
		return errors.New("checks list-packs does not accept positional args")
	}

	cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
	if err != nil {
		return err
	}

	if len(cfg.Taps) == 0 {
		fmt.Println("No taps registered. Use 'governor checks tap <source>' to add one.")
		return nil
	}

	fmt.Printf("%-20s %-20s %s\n", "SOURCE", "PACK", "DESCRIPTION")
	for _, t := range cfg.Taps {
		packs, err := taps.ListPacks(t.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to list packs for %s: %v\n", t.Name, err)
			continue
		}
		for _, p := range packs {
			fmt.Printf("%-20s %-20s %s\n", t.Name, p.Name, p.Description)
		}
	}
	return nil
}

func runChecksLock(args []string) error {
	fs := flag.NewFlagSet("governor checks lock", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	lockFile := fs.String("lock-file", "", "Path to checks lock file (default ./.governor/checks.lock.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks lock does not accept positional args")
	}

	cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
	if err != nil {
		return err
	}
	if len(cfg.Taps) == 0 {
		return errors.New("no taps registered; use 'governor checks tap <source>' first")
	}

	allPacks, err := taps.DiscoverPacks(cfg)
	if err != nil {
		return err
	}
	byName := make(map[string][]taps.LocatedPack, len(allPacks))
	for _, pack := range allPacks {
		key := strings.ToLower(pack.Name)
		byName[key] = append(byName[key], pack)
	}

	lock := taps.LockFile{APIVersion: taps.LockAPIVersion}
	for _, candidates := range byName {
		best, err := taps.SelectLatestPack(candidates)
		if err != nil {
			return err
		}
		taps.UpsertLockedPack(&lock, taps.LockedPackFromLocated(best, time.Now().UTC()))
	}

	lockPath := strings.TrimSpace(*lockFile)
	if lockPath == "" {
		lockPath = taps.DefaultLockPath()
	}
	if err := taps.SaveLock(lockPath, lock); err != nil {
		return err
	}

	fmt.Printf("wrote checks lock: %s (%d packs)\n", lockPath, len(lock.Packs))
	return nil
}

func runChecksUpdatePacks(args []string) error {
	fs := flag.NewFlagSet("governor checks update-packs", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	allowMajor := fs.Bool("major", false, "Allow major-version updates")
	dryRun := fs.Bool("dry-run", false, "Show updates without modifying the lock file")
	lockFile := fs.String("lock-file", "", "Path to checks lock file (default ./.governor/checks.lock.yaml)")
	trustPolicyPath := fs.String("trust-policy", "", "Path to check trust policy (default ./.governor/check-trust.yaml if present)")
	strictTrust := fs.Bool("strict-trust", false, "Block updates when trust policy checks fail")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks update-packs does not accept positional args")
	}

	lockPath := strings.TrimSpace(*lockFile)
	if lockPath == "" {
		lockPath = taps.DefaultLockPath()
	}
	lock, err := taps.LoadLock(lockPath)
	if err != nil {
		return err
	}
	if len(lock.Packs) == 0 {
		fmt.Println("no locked packs to update")
		return nil
	}
	resolvedTrustPolicyPath, trustPolicy, hasTrustPolicy, err := resolveTrustPolicy(*trustPolicyPath)
	if err != nil {
		return err
	}

	cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
	if err != nil {
		return err
	}
	allPacks, err := taps.DiscoverPacks(cfg)
	if err != nil {
		return err
	}
	byName := make(map[string][]taps.LocatedPack, len(allPacks))
	for _, pack := range allPacks {
		byName[strings.ToLower(pack.Name)] = append(byName[strings.ToLower(pack.Name)], pack)
	}

	type updateItem struct {
		old taps.LockedPack
		new taps.LocatedPack
	}
	updates := make([]updateItem, 0)

	for _, locked := range lock.Packs {
		candidates := byName[strings.ToLower(locked.Name)]
		if len(candidates) == 0 {
			fmt.Fprintf(os.Stderr, "warning: locked pack %s no longer exists in any tap\n", locked.Name)
			continue
		}
		latest, err := taps.SelectLatestPack(candidates)
		if err != nil {
			return err
		}
		versionCmp := taps.CompareVersion(strings.TrimSpace(latest.Version), strings.TrimSpace(locked.Version))
		digestChanged := strings.TrimSpace(latest.Digest) != strings.TrimSpace(locked.Digest)
		if versionCmp < 0 {
			continue
		}
		if versionCmp == 0 && !digestChanged {
			continue
		}
		if !*allowMajor && taps.IsMajorUpgrade(strings.TrimSpace(locked.Version), strings.TrimSpace(latest.Version)) {
			fmt.Printf("skipping major update for %s: %s -> %s (use --major)\n", locked.Name, locked.Version, latest.Version)
			continue
		}
		if hasTrustPolicy {
			result := tapstrust.ValidatePack(locked, true, latest, trustPolicy)
			emitTrustValidation(result)
			if tapstrust.ShouldBlock(trustPolicy.Mode, *strictTrust, result) {
				return fmt.Errorf("trust validation failed for pack %q (policy: %s)", locked.Name, resolvedTrustPolicyPath)
			}
		}
		updates = append(updates, updateItem{old: locked, new: latest})
	}

	if len(updates) == 0 {
		fmt.Println("all locked packs are up to date")
		return nil
	}

	for _, item := range updates {
		fmt.Printf("update %s: %s -> %s (%s)\n", item.old.Name, item.old.Version, item.new.Version, item.new.TapName)
	}

	if *dryRun {
		fmt.Printf("dry-run: %d update(s) available\n", len(updates))
		return nil
	}

	for _, item := range updates {
		taps.UpsertLockedPack(&lock, taps.LockedPackFromLocated(item.new, time.Now().UTC()))
	}
	if err := taps.SaveLock(lockPath, lock); err != nil {
		return err
	}
	fmt.Printf("updated lock file: %s (%d updates)\n", lockPath, len(updates))
	return nil
}

func runChecksTrust(args []string) error {
	if len(args) == 0 {
		return usageError("usage: governor checks trust <validate|pin> [flags]")
	}
	switch args[0] {
	case "validate":
		return runChecksTrustValidate(args[1:])
	case "pin":
		return runChecksTrustPin(args[1:])
	default:
		return usageError(fmt.Sprintf("unknown checks trust subcommand %q", args[0]))
	}
}

func runChecksTrustValidate(args []string) error {
	fs := flag.NewFlagSet("governor checks trust validate", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	trustPolicyPath := fs.String("trust-policy", "", "Path to check trust policy (default ./.governor/check-trust.yaml)")
	lockFile := fs.String("lock-file", "", "Path to checks lock file (default ./.governor/checks.lock.yaml)")
	strict := fs.Bool("strict", false, "Fail when trust warnings or errors are present")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("checks trust validate does not accept positional args")
	}

	resolvedPath, trustPolicy, hasPolicy, err := resolveTrustPolicy(*trustPolicyPath)
	if err != nil {
		return err
	}
	if !hasPolicy {
		fmt.Println("no trust policy found")
		return nil
	}

	lockPath := strings.TrimSpace(*lockFile)
	if lockPath == "" {
		lockPath = taps.DefaultLockPath()
	}
	lock, err := taps.LoadLock(lockPath)
	if err != nil {
		return err
	}
	cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
	if err != nil {
		return err
	}
	allPacks, err := taps.DiscoverPacks(cfg)
	if err != nil {
		return err
	}
	byName := make(map[string][]taps.LocatedPack, len(allPacks))
	for _, pack := range allPacks {
		byName[strings.ToLower(pack.Name)] = append(byName[strings.ToLower(pack.Name)], pack)
	}

	totalErrors := 0
	totalWarnings := 0
	for _, locked := range lock.Packs {
		candidates := byName[strings.ToLower(locked.Name)]
		if len(candidates) == 0 {
			totalWarnings++
			fmt.Fprintf(os.Stderr, "warning: locked pack %s missing from taps\n", locked.Name)
			continue
		}
		selected, err := taps.ResolveLockedPack(candidates, locked)
		if err != nil {
			totalErrors++
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			continue
		}
		result := tapstrust.ValidatePack(locked, true, selected, trustPolicy)
		totalErrors += len(result.Errors)
		totalWarnings += len(result.Warnings)
		emitTrustValidation(result)
	}

	fmt.Printf("trust policy: %s\n", resolvedPath)
	fmt.Printf("summary: errors=%d warnings=%d\n", totalErrors, totalWarnings)
	if totalErrors > 0 {
		return errors.New("trust validation failed")
	}
	if *strict && totalWarnings > 0 {
		return errors.New("trust validation failed in strict mode due to warnings")
	}
	return nil
}

func runChecksTrustPin(args []string) error {
	fs := flag.NewFlagSet("governor checks trust pin", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	source := fs.String("source", "", "Optional source tap name override")
	trustPolicyPath := fs.String("trust-policy", "", "Path to check trust policy (default ./.governor/check-trust.yaml)")
	lockFile := fs.String("lock-file", "", "Path to checks lock file (default ./.governor/checks.lock.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return errors.New("usage: governor checks trust pin <pack> [--source <tap>]")
	}
	packName := strings.TrimSpace(fs.Args()[0])

	lockPath := strings.TrimSpace(*lockFile)
	if lockPath == "" {
		lockPath = taps.DefaultLockPath()
	}
	lock, err := taps.LoadLock(lockPath)
	if err != nil {
		return err
	}
	locked, hasLocked := taps.FindLockedPack(lock, packName)

	cfg, err := taps.LoadConfig(taps.DefaultConfigPath())
	if err != nil {
		return err
	}
	allPacks, err := taps.DiscoverPacks(cfg)
	if err != nil {
		return err
	}
	candidates := taps.FindPackCandidates(allPacks, packName)
	if len(candidates) == 0 && !hasLocked {
		return fmt.Errorf("pack %q not found in taps and lockfile", packName)
	}

	var selected taps.LocatedPack
	if hasLocked && len(candidates) > 0 {
		selected, err = taps.ResolveLockedPack(candidates, locked)
		if err != nil {
			selected, err = taps.SelectLatestPack(candidates)
			if err != nil {
				return err
			}
		}
	} else if len(candidates) > 0 {
		selected, err = taps.SelectLatestPack(candidates)
		if err != nil {
			return err
		}
	} else {
		selected = taps.LocatedPack{
			Name:    locked.Name,
			TapName: locked.Source,
			Version: locked.Version,
			Digest:  locked.Digest,
			Commit:  locked.Commit,
		}
	}

	if strings.TrimSpace(*source) != "" {
		selected.TapName = strings.TrimSpace(*source)
	}

	resolvedPath := strings.TrimSpace(*trustPolicyPath)
	if resolvedPath == "" {
		resolvedPath = tapstrust.DefaultPath()
	}
	trustPolicy, err := loadOrInitTrustPolicy(resolvedPath)
	if err != nil {
		return err
	}
	tapstrust.UpsertPinnedPack(&trustPolicy, tapstrust.PinnedPack{
		Pack:    selected.Name,
		Source:  selected.TapName,
		Version: selected.Version,
		Digest:  selected.Digest,
		Commit:  selected.Commit,
	})
	if err := tapstrust.Save(resolvedPath, trustPolicy); err != nil {
		return err
	}
	fmt.Printf("pinned pack %s in %s\n", selected.Name, resolvedPath)
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

func runChecksTest(args []string) error {
	fs := flag.NewFlagSet("checks test", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	checksDir := fs.String("checks-dir", "", "Checks directory (default ./.governor/checks + ~/.governor/checks, repo first)")
	format := fs.String("format", "text", "Output format: text|json")
	aiProfile := fs.String("ai-profile", "codex", "AI profile name (default codex)")
	aiProvider := fs.String("ai-provider", "", "AI provider override: codex-cli|openai-compatible")
	aiModel := fs.String("ai-model", "", "AI model override")
	aiAuthMode := fs.String("ai-auth-mode", "", "AI auth override: auto|account|api-key")
	aiBaseURL := fs.String("ai-base-url", "", "AI base URL override for openai-compatible providers")
	aiAPIKeyEnv := fs.String("ai-api-key-env", "", "AI API key environment variable override")

	var aiBin string
	fs.StringVar(&aiBin, "ai-bin", "codex", "AI CLI executable path (used by codex-cli provider)")

	var allowCustomAIBin bool
	fs.BoolVar(&allowCustomAIBin, "allow-custom-ai-bin", false, "Allow non-default AI binary path (for testing only)")

	executionMode := fs.String("execution-mode", "sandboxed", "AI execution mode: sandboxed|host")

	var aiSandbox string
	fs.StringVar(&aiSandbox, "ai-sandbox", "read-only", "AI sandbox mode: read-only|workspace-write|danger-full-access")

	timeout := fs.Duration("timeout", 4*time.Minute, "Per-worker timeout (0 disables timeout)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	positional := fs.Args()
	if len(positional) != 2 {
		return errors.New("usage: governor checks test <check-id> <path> [flags]")
	}
	checkID := strings.TrimSpace(positional[0])
	targetPath := strings.TrimSpace(positional[1])

	outFormat := strings.ToLower(strings.TrimSpace(*format))
	if outFormat != "text" && outFormat != "json" {
		return errors.New("--format must be text or json")
	}

	selection, err := checks.ResolveAuditSelection(checks.AuditSelectionOptions{
		ChecksDir: *checksDir,
		OnlyIDs:   []string{checkID},
	})
	if err != nil {
		return err
	}
	if len(selection.Checks) == 0 {
		return fmt.Errorf("check %q not found or not enabled", checkID)
	}

	modeValue, err := normalizeExecutionModeFlag(*executionMode)
	if err != nil {
		return err
	}
	sandboxValue, err := normalizeSandboxModeFlag(aiSandbox)
	if err != nil {
		return err
	}
	if modeValue == "host" {
		sandboxValue = ""
	}

	aiRequired := checks.SelectionRequiresAI(selection.Checks)
	aiRuntime, err := ai.ResolveRuntime(ai.ResolveOptions{
		Profile:       strings.TrimSpace(*aiProfile),
		Provider:      strings.TrimSpace(*aiProvider),
		Model:         strings.TrimSpace(*aiModel),
		AuthMode:      strings.TrimSpace(*aiAuthMode),
		Bin:           strings.TrimSpace(aiBin),
		BaseURL:       strings.TrimSpace(*aiBaseURL),
		APIKeyEnv:     strings.TrimSpace(*aiAPIKeyEnv),
		ExecutionMode: modeValue,
		SandboxMode:   sandboxValue,
	})
	if err != nil {
		return err
	}

	if aiRequired && aiRuntime.UsesCLI() {
		aiInfo, err := trust.ResolveAIBinary(context.Background(), aiRuntime.Bin, allowCustomAIBin)
		if err != nil {
			return err
		}
		aiRuntime.Bin = aiInfo.ResolvedPath
	}

	outDir := filepath.Join(os.TempDir(), fmt.Sprintf("governor-check-test-%d", time.Now().UnixNano()))
	stage, err := intake.Stage(intake.StageOptions{
		InputPath: targetPath,
		OutDir:    outDir,
		MaxFiles:  20000,
		MaxBytes:  250 * 1024 * 1024,
	})
	if err != nil {
		return err
	}
	defer func() { _ = stage.Cleanup() }()

	results := worker.RunAll(context.Background(), stage.WorkspacePath, stage.Manifest, selection.Checks, worker.RunOptions{
		AIRuntime:   aiRuntime,
		CodexBin:    aiRuntime.Bin,
		OutDir:      outDir,
		MaxParallel: 1,
		Timeout:     *timeout,
		Verbose:     false,
		Sink:        progress.NewPlainSink(os.Stderr),
		Mode:        modeValue,
		SandboxMode: sandboxValue,
	})

	var allFindings []model.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	if outFormat == "json" {
		b, marshalErr := json.MarshalIndent(allFindings, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal findings: %w", marshalErr)
		}
		fmt.Println(string(b))
	} else {
		if len(allFindings) == 0 {
			fmt.Println("no findings")
		}
		for _, f := range allFindings {
			fmt.Printf("[%s] %s\n", strings.ToUpper(f.Severity), f.Title)
			fmt.Printf("  category:   %s\n", f.Category)
			if len(f.FileRefs) > 0 {
				fmt.Printf("  file refs:  %s\n", strings.Join(f.FileRefs, ", "))
			}
			if f.Evidence != "" {
				fmt.Printf("  evidence:   %s\n", f.Evidence)
			}
			if f.Impact != "" {
				fmt.Printf("  impact:     %s\n", f.Impact)
			}
			if f.Remediation != "" {
				fmt.Printf("  remediation: %s\n", f.Remediation)
			}
			fmt.Println()
		}
	}

	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(os.Stderr, "warning: %s: %s\n", r.Track, r.Error)
		}
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
	templateEngine := template.Engine
	if templateEngine == "" {
		templateEngine = checks.EngineAI
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

		if templateEngine == checks.EngineAI {
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
	if templateEngine == checks.EngineAI && instructions == "" {
		return "", "", errors.New("instructions are required for ai checks")
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
		Engine:         templateEngine,
		Description:    description,
		Instructions:   instructions,
		Rule:           template.Rule,
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
	case "account":
		return isolation.AuthAccount, nil
	case "subscription":
		return isolation.AuthAccount, nil
	case "api-key":
		return isolation.AuthAPIKey, nil
	default:
		return "", errors.New("--auth-mode must be auto, account, or api-key")
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
		return "", errors.New("--ai-sandbox must be read-only, workspace-write, or danger-full-access")
	}
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	force := fs.Bool("force", false, "Overwrite existing files")
	aiProfile := fs.String("ai-profile", "", "Set default AI profile in config")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("init does not accept positional args")
	}

	repoRoot, err := checks.FindRepoRootFromCWD()
	if err != nil {
		return err
	}
	root := repoRoot
	if root == "" {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return fmt.Errorf("resolve cwd: %w", cwdErr)
		}
		root = cwd
		fmt.Fprintf(os.Stderr, "warning: not inside a git repository, initializing in %s\n", root)
	}

	govDir := filepath.Join(root, ".governor")
	checksDir := filepath.Join(govDir, "checks")
	gitignorePath := filepath.Join(govDir, ".gitignore")
	configPath := filepath.Join(govDir, "config.yaml")

	if !*force {
		if _, err := os.Stat(gitignorePath); err == nil {
			if _, err := os.Stat(configPath); err == nil {
				fmt.Println("already initialized:", govDir)
				return nil
			}
		}
	}

	if err := os.MkdirAll(checksDir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", checksDir, err)
	}

	gitignoreContent := `# Keep this file and repo-local checks.
*
!.gitignore
!checks/
!checks/**
!suppressions.yaml
!baseline.json
!config.yaml

# Always ignore generated run artifacts.
runs/
`

	configContent := `# Governor configuration
# Docs: https://github.com/anthropics/governor
#
# Values here override global (~/.governor/config.yaml) settings.
# CLI flags override both.

# ai_profile: codex
# ai_provider: codex-cli
# ai_model:
# workers: 3
# execution_mode: sandboxed
# ai_sandbox: read-only
# fail_on:
# timeout: 4m
# verbose: false
`

	if strings.TrimSpace(*aiProfile) != "" {
		configContent = strings.Replace(configContent, "# ai_profile: codex", "ai_profile: "+strings.TrimSpace(*aiProfile), 1)
	}

	created := []string{}

	if err := writeIfNeeded(gitignorePath, gitignoreContent, *force); err != nil {
		return err
	}
	created = append(created, gitignorePath)

	if err := writeIfNeeded(configPath, configContent, *force); err != nil {
		return err
	}
	created = append(created, configPath)

	fmt.Println("initialized:", govDir)
	for _, path := range created {
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		fmt.Println("  created:", rel)
	}
	fmt.Println("")
	fmt.Println("next steps:")
	fmt.Println("  governor checks init    — scaffold a custom check")
	fmt.Println("  governor audit <path>   — run a security audit")
	return nil
}

func writeIfNeeded(path, content string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

func usageError(msg string) error {
	printUsage()
	return errors.New(msg)
}

func isInteractiveTerminal() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) &&
		isatty.IsTerminal(os.Stderr.Fd()) &&
		isatty.IsTerminal(os.Stdin.Fd())
}

// shouldAutoQuick returns true when no AI configuration exists, meaning the
// user has neither set any AI-related CLI flags nor provided AI settings in a
// config file. When true the audit should automatically fall back to quick
// (rule-engine only) mode.
func shouldAutoQuick(explicitQuick bool, cfg config.Config, setFlags map[string]struct{}) bool {
	if explicitQuick {
		return false
	}

	// AI-related CLI flag names.
	aiFlags := []string{
		"ai-profile",
		"ai-provider",
		"ai-model",
		"ai-auth-mode",
		"ai-base-url",
		"ai-api-key-env",
		"ai-bin",
	}
	for _, name := range aiFlags {
		if _, ok := setFlags[name]; ok {
			return false
		}
	}

	// AI-related config fields.
	if cfg.AIProfile != "" ||
		cfg.AIProvider != "" ||
		cfg.AIModel != "" ||
		cfg.AIAuthMode != "" ||
		cfg.AIBaseURL != "" ||
		cfg.AIAPIKeyEnv != "" ||
		cfg.AIBin != "" {
		return false
	}

	return true
}

func runClear(args []string) error {
	keep := 0
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--without-last" || arg == "-without-last" {
			keep = 1
			if i+1 < len(args) {
				n := 0
				valid := true
				for _, c := range args[i+1] {
					if c < '0' || c > '9' {
						valid = false
						break
					}
					n = n*10 + int(c-'0')
				}
				if valid && len(args[i+1]) > 0 {
					keep = n
					i++
				}
			}
		} else {
			return fmt.Errorf("unknown flag: %s", arg)
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	runsDir := filepath.Join(wd, ".governor", "runs")

	removed, err := clearRuns(runsDir, keep)
	if err != nil {
		return err
	}

	if len(removed) == 0 {
		fmt.Println("No runs to clear.")
		return nil
	}

	for _, name := range removed {
		fmt.Printf("  removed %s\n", name)
	}
	fmt.Printf("Removed %d run(s).\n", len(removed))
	return nil
}

func clearRuns(runsDir string, keep int) ([]string, error) {
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read runs directory: %w", err)
	}

	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) == 0 {
		return nil, nil
	}

	sort.Strings(dirs)

	if keep >= len(dirs) {
		return nil, nil
	}

	toRemove := dirs
	if keep > 0 {
		toRemove = dirs[:len(dirs)-keep]
	}

	var removed []string
	for _, name := range toRemove {
		if err := os.RemoveAll(filepath.Join(runsDir, name)); err != nil {
			return removed, fmt.Errorf("remove run %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	return removed, nil
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	jsonOut := fs.Bool("json", false, "Output doctor report as JSON")
	strict := fs.Bool("strict", false, "Treat warnings as failures")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("doctor does not accept positional args")
	}

	report := doctor.BuildReport(context.Background(), doctor.Options{})
	if *jsonOut {
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal doctor report: %w", err)
		}
		fmt.Println(string(b))
	} else {
		fmt.Println("doctor checks:")
		for _, check := range report.Checks {
			fmt.Printf("- %-20s %-7s %s\n", check.ID, string(check.Status), check.Message)
		}
		fmt.Println("")
		fmt.Printf("summary: pass=%d warning=%d fail=%d\n", report.Summary.Pass, report.Summary.Warning, report.Summary.Fail)
	}

	if report.Failed(*strict) {
		if *strict && report.Summary.Fail == 0 {
			return errors.New("doctor strict mode failed: warnings found")
		}
		return errors.New("doctor failed: one or more checks failed")
	}
	return nil
}

func runPolicy(args []string) error {
	if len(args) == 0 {
		return usageError("usage: governor policy <validate|explain> [flags]")
	}
	switch args[0] {
	case "validate":
		return runPolicyValidate(args[1:])
	case "explain":
		return runPolicyExplain(args[1:])
	default:
		return usageError(fmt.Sprintf("unknown policy subcommand %q", args[0]))
	}
}

func runPolicyValidate(args []string) error {
	fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	file := fs.String("file", policy.DefaultPath("."), "Path to policy file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("policy validate does not accept positional args")
	}
	p, err := policy.Load(*file)
	if err != nil {
		return err
	}
	fmt.Printf("policy valid: %s (%s)\n", *file, p.APIVersion)
	return nil
}

func runPolicyExplain(args []string) error {
	fs := flag.NewFlagSet("policy explain", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	file := fs.String("file", policy.DefaultPath("."), "Path to policy file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("policy explain does not accept positional args")
	}

	p, err := policy.Load(*file)
	if err != nil {
		return err
	}
	fmt.Printf("policy: %s\n", *file)
	fmt.Printf("api_version: %s\n", p.APIVersion)
	fmt.Printf("defaults:\n")
	fmt.Printf("  fail_on_severity: %s\n", fallback(p.Defaults.FailOnSeverity, "none"))
	fmt.Printf("  fail_on_exploitability: %s\n", fallback(p.Defaults.FailOnExploitability, "none"))
	if p.Defaults.MaxSuppressionRatio != nil {
		fmt.Printf("  max_suppression_ratio: %.2f\n", *p.Defaults.MaxSuppressionRatio)
	}
	if p.Defaults.MaxNewFindings != nil {
		fmt.Printf("  max_new_findings: %d\n", *p.Defaults.MaxNewFindings)
	}
	if p.Defaults.MaxNewReachableFindings != nil {
		fmt.Printf("  max_new_reachable_findings: %d\n", *p.Defaults.MaxNewReachableFindings)
	}
	if p.Defaults.MinConfidenceForBlock != nil {
		fmt.Printf("  min_confidence_for_block: %.2f\n", *p.Defaults.MinConfidenceForBlock)
	}
	if p.Defaults.RequireAttackPathForBlocking != nil {
		fmt.Printf("  require_attack_path_for_blocking: %t\n", *p.Defaults.RequireAttackPathForBlocking)
	}
	fmt.Printf("  require_checks: %s\n", strings.Join(p.Defaults.RequireChecks, ", "))
	fmt.Printf("  forbid_checks: %s\n", strings.Join(p.Defaults.ForbidChecks, ", "))
	fmt.Printf("rules: %d\n", len(p.Rules))
	fmt.Printf("waivers: %d\n", len(p.Waivers))
	return nil
}

func runMatrix(args []string) error {
	if len(args) == 0 {
		return usageError("usage: governor matrix <run> [flags]")
	}
	switch args[0] {
	case "run":
		return runMatrixRun(args[1:])
	default:
		return usageError(fmt.Sprintf("unknown matrix subcommand %q", args[0]))
	}
}

func runMatrixRun(args []string) error {
	fs := flag.NewFlagSet("matrix run", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	configPath := fs.String("config", matrix.DefaultPath(), "Path to matrix config")
	outDir := fs.String("out", "", "Output directory for matrix summary artifacts")
	jsonOut := fs.Bool("json", false, "Print matrix summary as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("matrix run does not accept positional args")
	}

	cfg, err := matrix.Load(*configPath)
	if err != nil {
		return err
	}

	runStarted := time.Now().UTC()
	matrixOutDir, err := resolveMatrixOutDir(*outDir, runStarted)
	if err != nil {
		return err
	}
	matrixOutDir, err = safefile.EnsureFreshDir(matrixOutDir, 0o700)
	if err != nil {
		return fmt.Errorf("create matrix output dir: %w", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	targets := make([]matrix.TargetSummary, 0, len(cfg.Targets))
	failedTargets := 0
	passedTargets := 0
	totalFindings := 0
	aggregateSeverity := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

	for _, target := range cfg.Targets {
		effective := matrix.MergeOptions(cfg.Defaults, target.TargetOptions)
		targetStarted := time.Now().UTC()
		targetRunDir := filepath.Join(matrixOutDir, sanitizeTargetName(target.Name))
		cmdArgs := buildMatrixAuditArgs(target, effective, targetRunDir)
		cmd := exec.Command(exePath, cmdArgs...)
		cmd.Env = os.Environ()
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		runErr := cmd.Run()

		exitCode := 0
		status := "passed"
		if runErr != nil {
			status = "failed"
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				return fmt.Errorf("run target %s: %w", target.Name, runErr)
			}
		}

		targetSummary := matrix.TargetSummary{
			Name:         target.Name,
			Path:         target.Path,
			Status:       status,
			RunDir:       targetRunDir,
			JSONPath:     filepath.Join(targetRunDir, "audit.json"),
			MarkdownPath: filepath.Join(targetRunDir, "audit.md"),
			HTMLPath:     filepath.Join(targetRunDir, "audit.html"),
			ExitCode:     exitCode,
			DurationMS:   time.Since(targetStarted).Milliseconds(),
		}
		if rawReport, readErr := os.ReadFile(targetSummary.JSONPath); readErr == nil {
			var report model.AuditReport
			if err := json.Unmarshal(rawReport, &report); err == nil {
				targetSummary.Findings = len(report.Findings)
				targetSummary.Errors = len(report.Errors)
				totalFindings += len(report.Findings)
				for sev, count := range report.CountsBySeverity {
					aggregateSeverity[strings.ToLower(strings.TrimSpace(sev))] += count
				}
			}
		}
		targets = append(targets, targetSummary)

		if status == "failed" {
			failedTargets++
			if cfg.Aggregation.FailFast {
				break
			}
		} else {
			passedTargets++
		}
	}

	summary := matrix.Summary{
		APIVersion:    matrix.APIVersion,
		ConfigPath:    strings.TrimSpace(*configPath),
		StartedAt:     runStarted,
		CompletedAt:   time.Now().UTC(),
		Targets:       targets,
		FailedTargets: failedTargets,
		TotalFindings: totalFindings,
	}
	summary.DurationMS = summary.CompletedAt.Sub(summary.StartedAt).Milliseconds()
	requireAll := true
	if cfg.Aggregation.RequireAllTargets != nil {
		requireAll = *cfg.Aggregation.RequireAllTargets
	}
	if requireAll {
		summary.Passed = failedTargets == 0
	} else {
		summary.Passed = passedTargets > 0
	}
	if threshold := strings.ToLower(strings.TrimSpace(cfg.Aggregation.OverallFailOn)); threshold != "" && threshold != "none" {
		thresholdWeight, ok := severityWeightMap[threshold]
		if !ok {
			return fmt.Errorf("invalid aggregation overall_fail_on %q", threshold)
		}
		if countAtOrAboveCounts(aggregateSeverity, thresholdWeight) > 0 {
			summary.Passed = false
		}
	}

	jsonPath, mdPath, err := matrix.WriteSummary(matrixOutDir, summary)
	if err != nil {
		return err
	}

	if *jsonOut {
		payload, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal matrix summary: %w", err)
		}
		fmt.Println(string(payload))
	} else {
		fmt.Printf("matrix summary json: %s\n", jsonPath)
		fmt.Printf("matrix summary md:   %s\n", mdPath)
		fmt.Printf("targets: %d passed=%t failed=%d findings=%d\n", len(summary.Targets), summary.Passed, summary.FailedTargets, summary.TotalFindings)
	}

	if !summary.Passed {
		return errors.New("matrix run failed")
	}
	return nil
}

func buildMatrixAuditArgs(target matrix.Target, opts matrix.TargetOptions, outDir string) []string {
	args := []string{"audit", target.Path, "--out", outDir, "--no-tui"}
	if strings.TrimSpace(opts.FailOn) != "" && strings.TrimSpace(opts.FailOn) != "none" {
		args = append(args, "--fail-on", strings.TrimSpace(opts.FailOn))
	}
	if strings.TrimSpace(opts.Policy) != "" {
		args = append(args, "--policy", strings.TrimSpace(opts.Policy))
	}
	if opts.RequirePolicy != nil && *opts.RequirePolicy {
		args = append(args, "--require-policy")
	}
	if strings.TrimSpace(opts.Baseline) != "" {
		args = append(args, "--baseline", strings.TrimSpace(opts.Baseline))
	}
	if strings.TrimSpace(opts.ChecksDir) != "" {
		args = append(args, "--checks-dir", strings.TrimSpace(opts.ChecksDir))
	}
	if opts.NoCustomChecks != nil && *opts.NoCustomChecks {
		args = append(args, "--no-custom-checks")
	}
	if opts.Quick != nil && *opts.Quick {
		args = append(args, "--quick")
	}
	for _, check := range opts.OnlyChecks {
		args = append(args, "--only-check", check)
	}
	for _, check := range opts.SkipChecks {
		args = append(args, "--skip-check", check)
	}
	if strings.TrimSpace(opts.Suppressions) != "" {
		args = append(args, "--suppressions", strings.TrimSpace(opts.Suppressions))
	}
	if opts.Workers != nil {
		args = append(args, "--workers", fmt.Sprintf("%d", *opts.Workers))
	}
	if strings.TrimSpace(opts.AIProfile) != "" {
		args = append(args, "--ai-profile", strings.TrimSpace(opts.AIProfile))
	}
	if opts.IncludeTestFiles != nil && *opts.IncludeTestFiles {
		args = append(args, "--include-test-files")
	}
	return args
}

func resolveMatrixOutDir(raw string, now time.Time) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return filepath.Abs(raw)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	return filepath.Join(cwd, ".governor", "runs", "matrix-"+now.Format("20060102-150405")), nil
}

func sanitizeTargetName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "target"
	}
	var b strings.Builder
	for _, ch := range name {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			b.WriteRune(ch + ('a' - 'A'))
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '-' || ch == '_':
			b.WriteRune(ch)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-_")
}

func resolvePolicyInput(rawPath string, require bool) (string, policy.Policy, bool, error) {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		defaultPath := policy.DefaultPath(".")
		if _, err := os.Stat(defaultPath); err == nil {
			path = defaultPath
		} else if require {
			return "", policy.Policy{}, false, fmt.Errorf("policy file is required but not found at %s", defaultPath)
		} else {
			return "", policy.Policy{}, false, nil
		}
	}
	p, err := policy.Load(path)
	if err != nil {
		return "", policy.Policy{}, false, err
	}
	return path, p, true, nil
}

func loadDiffReport(path string) (*diff.DiffReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read diff report: %w", err)
	}
	var dr diff.DiffReport
	if err := json.Unmarshal(raw, &dr); err != nil {
		return nil, fmt.Errorf("parse diff report: %w", err)
	}
	return &dr, nil
}

func persistAuditArtifacts(paths app.ArtifactPaths, report model.AuditReport) error {
	if err := reportpkg.WriteJSON(paths.JSONPath, report); err != nil {
		return err
	}
	if err := reportpkg.WriteMarkdown(paths.MarkdownPath, report); err != nil {
		return err
	}
	if err := reportpkg.WriteHTML(paths.HTMLPath, report); err != nil {
		return err
	}
	if strings.TrimSpace(paths.SARIFPath) != "" {
		if err := reportpkg.WriteSARIF(paths.SARIFPath, report); err != nil {
			return err
		}
	}
	return nil
}

func checkPolicyDecision(decision *model.PolicyDecision) error {
	if decision == nil || decision.Passed {
		return nil
	}
	unwaived := 0
	for _, violation := range decision.Violations {
		if !violation.Waived {
			unwaived++
		}
	}
	if unwaived == 0 {
		return nil
	}
	return fmt.Errorf("policy check failed: %d unwaived violation(s)", unwaived)
}

func fallback(value string, defaultValue string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue
	}
	return value
}

func resolveTrustPolicy(rawPath string) (string, tapstrust.Policy, bool, error) {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		defaultPath := tapstrust.DefaultPath()
		if _, err := os.Stat(defaultPath); err == nil {
			path = defaultPath
		} else {
			return "", tapstrust.Policy{}, false, nil
		}
	}
	p, err := tapstrust.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", tapstrust.Policy{}, false, nil
		}
		return "", tapstrust.Policy{}, false, err
	}
	return path, p, true, nil
}

func loadOrInitTrustPolicy(path string) (tapstrust.Policy, error) {
	p, err := tapstrust.Load(path)
	if err == nil {
		return p, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return tapstrust.Normalize(tapstrust.Policy{APIVersion: tapstrust.APIVersion, Mode: tapstrust.ModeWarn}), nil
	}
	return tapstrust.Policy{}, err
}

func emitTrustValidation(result tapstrust.ValidationResult) {
	for _, warning := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
	for _, trustErr := range result.Errors {
		fmt.Fprintf(os.Stderr, "error: %s\n", trustErr)
	}
}

func runCI(args []string) error {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	failOn := fs.String("fail-on", "high", "Exit non-zero if any new finding meets or exceeds severity: critical|high|medium|low|info")
	failOnExploitability := fs.String("fail-on-exploitability", "", "Exit non-zero if any finding meets or exceeds exploitability: confirmed-path|reachable|theoretical")
	maxNewReachable := fs.Int("max-new-reachable", -1, "Exit non-zero if reachable/confirmed-path new findings exceed this count (-1 disables)")
	minConfidenceForBlock := fs.Float64("min-confidence-for-block", -1, "Only block on findings with confidence >= threshold (0.0-1.0, default -1 disables)")
	requireAttackPathForBlocking := fs.Bool("require-attack-path-for-blocking", false, "Only block findings that include non-empty attack_path")
	commentFile := fs.String("comment-file", "", "Write PR comment markdown to file")
	updateBaseline := fs.Bool("update-baseline", false, "Write findings as baseline after audit")
	baselineFile := fs.String("baseline-file", ".governor/baseline.json", "Baseline file path")
	out := fs.String("out", "", "Output directory for run artifacts")
	workers := fs.Int("workers", 3, "Max concurrent worker processes (1-3)")
	aiProfile := fs.String("ai-profile", "codex", "AI profile name")
	aiProvider := fs.String("ai-provider", "", "AI provider override")
	aiModel := fs.String("ai-model", "", "AI model override")
	aiAuthMode := fs.String("ai-auth-mode", "", "AI auth override")
	aiBaseURL := fs.String("ai-base-url", "", "AI base URL override")
	aiAPIKeyEnv := fs.String("ai-api-key-env", "", "AI API key env override")
	var aiBin string
	fs.StringVar(&aiBin, "ai-bin", "codex", "AI CLI executable path")
	var allowCustomAIBin bool
	fs.BoolVar(&allowCustomAIBin, "allow-custom-ai-bin", false, "Allow non-default AI binary path")
	executionMode := fs.String("execution-mode", "sandboxed", "AI execution mode: sandboxed|host")
	var aiSandbox string
	fs.StringVar(&aiSandbox, "ai-sandbox", "read-only", "AI sandbox mode")
	maxFiles := fs.Int("max-files", 20000, "Maximum included file count")
	maxBytes := fs.Int64("max-bytes", 250*1024*1024, "Maximum included file bytes")
	timeout := fs.Duration("timeout", 4*time.Minute, "Per-worker timeout")
	verbose := fs.Bool("verbose", false, "Enable verbose logs")
	checksDir := fs.String("checks-dir", "", "Checks directory")
	noCustomChecks := fs.Bool("no-custom-checks", false, "Run built-in checks only")
	suppressionsPath := fs.String("suppressions", "", "Path to suppressions YAML file")
	showSuppressed := fs.Bool("show-suppressed", false, "Include suppressed findings in reports")
	includeTestFiles := fs.Bool("include-test-files", false, "Include test files in security scanning")
	quick := fs.Bool("quick", false, "Run only rule-engine checks (no AI, no network)")
	policyPath := fs.String("policy", "", "Path to policy file (default ./.governor/policy.yaml if present)")
	requirePolicy := fs.Bool("require-policy", false, "Fail if no policy file is found")
	maxRuleFileBytes := fs.Int("max-rule-file-bytes", 0, "Max file size for rule-engine scanning (default 2MB, max 20MB)")
	maxSuppressionRatio := fs.Float64("max-suppression-ratio", 1.0, "Fail if suppression ratio exceeds threshold (0.0-1.0, default 1.0=disabled)")

	var onlyChecks listFlag
	var skipChecks listFlag
	fs.Var(&onlyChecks, "only-check", "Only run specific check ID(s)")
	fs.Var(&skipChecks, "skip-check", "Skip specific check ID(s)")

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
	case positionalInput == "" && len(remaining) == 0:
		positionalInput = "."
	default:
		return usageError("usage: governor ci [<path>] [flags]")
	}

	if *workers < 1 || *workers > 3 {
		return errors.New("--workers must be between 1 and 3")
	}
	if *maxRuleFileBytes < 0 || (*maxRuleFileBytes > 0 && *maxRuleFileBytes > worker.MaxAllowedRuleFileBytes) {
		return fmt.Errorf("--max-rule-file-bytes must be between 0 and %d", worker.MaxAllowedRuleFileBytes)
	}
	if *maxNewReachable < -1 {
		return errors.New("--max-new-reachable must be >= -1")
	}
	if *minConfidenceForBlock != -1 && (*minConfidenceForBlock < 0 || *minConfidenceForBlock > 1) {
		return errors.New("--min-confidence-for-block must be between 0.0 and 1.0 (or -1 to disable)")
	}

	modeValue, err := normalizeExecutionModeFlag(*executionMode)
	if err != nil {
		return err
	}
	sandboxValue, err := normalizeSandboxModeFlag(aiSandbox)
	if err != nil {
		return err
	}
	if modeValue == "host" {
		sandboxValue = ""
	}

	ciSelOpts := checks.AuditSelectionOptions{
		ChecksDir:      *checksDir,
		NoCustomChecks: *noCustomChecks,
		OnlyIDs:        onlyChecks.Values(),
		SkipIDs:        skipChecks.Values(),
	}
	if *quick {
		ciSelOpts.EngineFilter = checks.EngineRule
	}
	selection, err := checks.ResolveAuditSelection(ciSelOpts)
	if err != nil {
		return err
	}

	var aiRuntime ai.Runtime
	aiInfo := trust.AIBinary{}
	if *quick {
		// Quick mode: skip AI resolution entirely.
	} else {
		aiRequired := checks.SelectionRequiresAI(selection.Checks)
		aiRuntime, err = ai.ResolveRuntime(ai.ResolveOptions{
			Profile:       strings.TrimSpace(*aiProfile),
			Provider:      strings.TrimSpace(*aiProvider),
			Model:         strings.TrimSpace(*aiModel),
			AuthMode:      strings.TrimSpace(*aiAuthMode),
			Bin:           strings.TrimSpace(aiBin),
			BaseURL:       strings.TrimSpace(*aiBaseURL),
			APIKeyEnv:     strings.TrimSpace(*aiAPIKeyEnv),
			ExecutionMode: modeValue,
			SandboxMode:   sandboxValue,
		})
		if err != nil {
			return err
		}

		if aiRequired && aiRuntime.UsesCLI() {
			aiInfo, err = trust.ResolveAIBinary(context.Background(), aiRuntime.Bin, allowCustomAIBin)
			if err != nil {
				return err
			}
			aiRuntime.Bin = aiInfo.ResolvedPath
		}
	}

	// Resolve suppressions path.
	if strings.TrimSpace(*suppressionsPath) == "" {
		defaultSuppPath := suppress.DefaultPath(".")
		if _, statErr := os.Stat(defaultSuppPath); statErr == nil {
			*suppressionsPath = defaultSuppPath
		}
	}

	// Detect baseline.
	baselinePath := strings.TrimSpace(*baselineFile)
	if _, statErr := os.Stat(baselinePath); statErr != nil {
		baselinePath = "" // no baseline available
	}

	resolvedPolicyPath, loadedPolicy, hasPolicy, err := resolvePolicyInput(*policyPath, *requirePolicy)
	if err != nil {
		return err
	}

	auditOpts := app.AuditOptions{
		InputPath:     positionalInput,
		OutDir:        *out,
		AIRuntime:     aiRuntime,
		AIBin:         aiInfo.ResolvedPath,
		AIVersion:     aiInfo.Version,
		AISHA256:      aiInfo.SHA256,
		AIRequest:     aiInfo.RequestedPath,
		Workers:       *workers,
		MaxFiles:      *maxFiles,
		MaxBytes:      *maxBytes,
		Timeout:       *timeout,
		Verbose:       *verbose,
		ExecutionMode: modeValue,
		SandboxMode:   sandboxValue,

		ChecksDir:        *checksDir,
		NoCustomChecks:   *noCustomChecks,
		OnlyChecks:       onlyChecks.Values(),
		SkipChecks:       skipChecks.Values(),
		BaselinePath:     baselinePath,
		SuppressionsPath: strings.TrimSpace(*suppressionsPath),
		ShowSuppressed:   *showSuppressed,
		IncludeTestFiles: *includeTestFiles,
		Quick:            *quick,
		MaxRuleFileBytes: *maxRuleFileBytes,
	}

	auditOpts.Progress = progress.NewPlainSink(os.Stderr)
	report, paths, err := app.RunAudit(context.Background(), auditOpts)
	if err != nil {
		os.Exit(2)
	}
	var diffReport *diff.DiffReport
	if paths.DiffPath != "" {
		diffReport, err = loadDiffReport(paths.DiffPath)
		if err != nil {
			return err
		}
	}
	if hasPolicy {
		decision := policy.Evaluate(resolvedPolicyPath, loadedPolicy, report, diffReport)
		report.PolicyDecision = &decision
		report.RunMetadata.PolicyPath = resolvedPolicyPath
		report.RunMetadata.PolicyVersion = loadedPolicy.APIVersion
		if err := persistAuditArtifacts(paths, report); err != nil {
			return err
		}
	}
	printAuditSummary(report, paths)

	// Generate PR comment if requested.
	if strings.TrimSpace(*commentFile) != "" {
		var diffReport *diff.DiffReport
		if baselinePath != "" && paths.DiffPath != "" {
			raw, readErr := os.ReadFile(paths.DiffPath)
			if readErr == nil {
				var dr diff.DiffReport
				if jsonErr := json.Unmarshal(raw, &dr); jsonErr == nil {
					diffReport = &dr
				}
			}
		}
		commentMD := comment.Generate(report, diffReport, comment.Options{ShowSuppressed: *showSuppressed})
		if writeErr := safefile.WriteFileAtomic(*commentFile, []byte(commentMD), 0o600); writeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: write comment file: %v\n", writeErr)
		}
	}

	// Update baseline if requested.
	if *updateBaseline {
		baselineData, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr != nil {
			fmt.Fprintf(os.Stderr, "warning: marshal baseline: %v\n", marshalErr)
		} else {
			baselineDir := filepath.Dir(*baselineFile)
			if mkdirErr := os.MkdirAll(baselineDir, 0o700); mkdirErr != nil {
				fmt.Fprintf(os.Stderr, "warning: create baseline dir: %v\n", mkdirErr)
			} else if writeErr := safefile.WriteFileAtomic(*baselineFile, baselineData, 0o600); writeErr != nil {
				fmt.Fprintf(os.Stderr, "warning: write baseline: %v\n", writeErr)
			} else {
				fmt.Printf("baseline:       %s\n", *baselineFile)
			}
		}
	}

	// CI exit codes: 0=pass, 1=findings exceed threshold, 2=audit error (handled above).
	riskErr := checkRiskGates(report, diffReport, riskGateOptions{
		FailOnSeverity:               *failOn,
		FailOnExploitability:         *failOnExploitability,
		MaxNewReachable:              *maxNewReachable,
		MinConfidenceForBlock:        *minConfidenceForBlock,
		RequireAttackPathForBlocking: *requireAttackPathForBlocking,
	})
	if riskErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", riskErr)
		os.Exit(1)
	}
	if ratioErr := checkSuppressionRatioCI(*maxSuppressionRatio, report); ratioErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", ratioErr)
		os.Exit(1)
	}
	if policyErr := checkPolicyDecision(report.PolicyDecision); policyErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", policyErr)
		os.Exit(1)
	}
	return nil
}

func runFindings(args []string) error {
	if len(args) == 0 {
		return usageError("usage: governor findings <suppress|unsuppress|prune|list|expired>")
	}
	switch args[0] {
	case "suppress":
		return runFindingsSuppress(args[1:])
	case "unsuppress":
		return runFindingsUnsuppress(args[1:])
	case "prune":
		return runFindingsPrune(args[1:])
	case "list":
		return runFindingsList(args[1:])
	case "expired":
		return runFindingsExpired(args[1:])
	default:
		return usageError(fmt.Sprintf("unknown findings subcommand %q", args[0]))
	}
}

func runFindingsSuppress(args []string) error {
	fs := flag.NewFlagSet("findings suppress", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	reason := fs.String("reason", "", "Reason for suppression (required)")
	check := fs.String("check", "", "Check ID to suppress")
	category := fs.String("category", "", "Category to suppress")
	files := fs.String("files", "", "File glob pattern to suppress")
	severity := fs.String("severity", "", "Severity to suppress")
	author := fs.String("author", "", "Author of suppression")
	expires := fs.String("expires", "", "Expiration date (YYYY-MM-DD)")
	suppressionsPath := fs.String("suppressions", "", "Path to suppressions file (default ./.governor/suppressions.yaml)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Positional arg is the title pattern.
	var titlePattern string
	if len(fs.Args()) > 0 {
		titlePattern = strings.Join(fs.Args(), " ")
	}

	if strings.TrimSpace(*reason) == "" {
		return errors.New("--reason is required")
	}
	if titlePattern == "" && *check == "" && *category == "" && *files == "" && *severity == "" {
		return errors.New("at least one matching criterion is required (title pattern, --check, --category, --files, or --severity)")
	}

	path := strings.TrimSpace(*suppressionsPath)
	if path == "" {
		path = suppress.DefaultPath(".")
	}

	// Load existing suppressions.
	rules, loadErr := suppress.Load(path)
	if loadErr != nil && !os.IsNotExist(loadErr) {
		return fmt.Errorf("load suppressions: %w", loadErr)
	}
	rules = suppress.EnsureRuleIDs(rules)

	// Add new rule.
	newRule := suppress.Rule{
		Check:    strings.TrimSpace(*check),
		Title:    strings.TrimSpace(titlePattern),
		Category: strings.TrimSpace(*category),
		Files:    strings.TrimSpace(*files),
		Severity: strings.TrimSpace(*severity),
		Reason:   strings.TrimSpace(*reason),
		Author:   strings.TrimSpace(*author),
		Expires:  strings.TrimSpace(*expires),
	}
	rules = append(rules, newRule)
	rules = suppress.EnsureRuleIDs(rules)
	added := rules[len(rules)-1]

	if err := suppress.Save(path, rules); err != nil {
		return fmt.Errorf("save suppressions: %w", err)
	}

	fmt.Printf("added suppression %s to %s\n", added.ID, path)
	return nil
}

func runFindingsUnsuppress(args []string) error {
	fs := flag.NewFlagSet("findings unsuppress", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	check := fs.String("check", "", "Check ID glob to match")
	title := fs.String("title", "", "Title glob to match")
	category := fs.String("category", "", "Category to match")
	files := fs.String("files", "", "File glob to match")
	severity := fs.String("severity", "", "Severity to match")
	suppressionsPath := fs.String("suppressions", "", "Path to suppressions file (default ./.governor/suppressions.yaml)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	idPattern := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if idPattern == "" && *check == "" && *title == "" && *category == "" && *files == "" && *severity == "" {
		return errors.New("at least one matching criterion is required (id/pattern, --check, --title, --category, --files, or --severity)")
	}

	path := strings.TrimSpace(*suppressionsPath)
	if path == "" {
		path = suppress.DefaultPath(".")
	}

	rules, err := suppress.Load(path)
	if err != nil {
		return fmt.Errorf("load suppressions: %w", err)
	}
	kept, removed := suppress.RemoveMatching(rules, suppress.MatchOptions{
		IDPattern: idPattern,
		Check:     strings.TrimSpace(*check),
		Title:     strings.TrimSpace(*title),
		Category:  strings.TrimSpace(*category),
		Files:     strings.TrimSpace(*files),
		Severity:  strings.TrimSpace(*severity),
	})
	if len(removed) == 0 {
		fmt.Println("no matching suppressions found")
		return nil
	}
	if err := suppress.Save(path, kept); err != nil {
		return fmt.Errorf("save suppressions: %w", err)
	}
	fmt.Printf("removed %d suppression(s)\n", len(removed))
	for _, rule := range removed {
		fmt.Printf("- %s\n", rule.ID)
	}
	return nil
}

func runFindingsPrune(args []string) error {
	fs := flag.NewFlagSet("findings prune", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	expiredOnly := fs.Bool("expired-only", false, "Only prune expired suppressions")
	yes := fs.Bool("yes", false, "Apply prune without confirmation prompt")
	suppressionsPath := fs.String("suppressions", "", "Path to suppressions file (default ./.governor/suppressions.yaml)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("findings prune does not accept positional args")
	}

	path := strings.TrimSpace(*suppressionsPath)
	if path == "" {
		path = suppress.DefaultPath(".")
	}

	rules, err := suppress.Load(path)
	if err != nil {
		return fmt.Errorf("load suppressions: %w", err)
	}

	now := time.Now().UTC()
	kept := make([]suppress.Rule, 0, len(rules))
	removed := make([]suppress.Rule, 0)
	for _, rule := range suppress.EnsureRuleIDs(rules) {
		if rule.IsExpired(now) {
			removed = append(removed, rule)
			continue
		}
		if !*expiredOnly && rule.HasInvalidExpiry() {
			removed = append(removed, rule)
			continue
		}
		kept = append(kept, rule)
	}
	if len(removed) == 0 {
		fmt.Println("no suppressions to prune")
		return nil
	}

	if !*yes {
		fmt.Printf("would prune %d suppression(s). Re-run with --yes to apply.\n", len(removed))
		for _, rule := range removed {
			fmt.Printf("- %s\n", rule.ID)
		}
		return errors.New("prune preview only")
	}

	if err := suppress.Save(path, kept); err != nil {
		return fmt.Errorf("save suppressions: %w", err)
	}
	fmt.Printf("pruned %d suppression(s)\n", len(removed))
	return nil
}

func runFindingsList(args []string) error {
	fs := flag.NewFlagSet("findings list", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	suppressionsPath := fs.String("suppressions", "", "Path to suppressions file (default ./.governor/suppressions.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := strings.TrimSpace(*suppressionsPath)
	if path == "" {
		path = suppress.DefaultPath(".")
	}

	rules, err := suppress.Load(path)
	if err != nil {
		return fmt.Errorf("load suppressions: %w", err)
	}
	rules = suppress.EnsureRuleIDs(rules)
	if len(rules) == 0 {
		fmt.Println("no active suppressions")
		return nil
	}

	fmt.Printf("suppressions from %s:\n\n", path)
	for i, r := range rules {
		fmt.Printf("[%d] id=%s ", i+1, r.ID)
		if r.Check != "" {
			fmt.Printf("check=%s ", r.Check)
		}
		if r.Title != "" {
			fmt.Printf("title=%q ", r.Title)
		}
		if r.Category != "" {
			fmt.Printf("category=%s ", r.Category)
		}
		if r.Files != "" {
			fmt.Printf("files=%s ", r.Files)
		}
		if r.Severity != "" {
			fmt.Printf("severity=%s ", r.Severity)
		}
		fmt.Println()
		fmt.Printf("    reason: %s\n", r.Reason)
		if r.Author != "" {
			fmt.Printf("    author: %s\n", r.Author)
		}
		if r.Expires != "" {
			fmt.Printf("    expires: %s\n", r.Expires)
		}
	}
	return nil
}

func runFindingsExpired(args []string) error {
	fs := flag.NewFlagSet("findings expired", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	suppressionsPath := fs.String("suppressions", "", "Path to suppressions file (default ./.governor/suppressions.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := strings.TrimSpace(*suppressionsPath)
	if path == "" {
		path = suppress.DefaultPath(".")
	}

	rules, err := suppress.Load(path)
	if err != nil {
		return fmt.Errorf("load suppressions: %w", err)
	}
	rules = suppress.EnsureRuleIDs(rules)

	now := time.Now().UTC()
	expired := make([]suppress.Rule, 0)
	for _, r := range rules {
		if r.IsExpired(now) {
			expired = append(expired, r)
		}
	}

	if len(expired) == 0 {
		fmt.Println("no expired suppressions")
		return nil
	}

	fmt.Printf("%d expired suppression(s):\n\n", len(expired))
	for _, r := range expired {
		fmt.Printf("- id=%s", r.ID)
		if r.Title != "" {
			fmt.Printf(" title=%q", r.Title)
		}
		if r.Check != "" {
			fmt.Printf(" check=%s", r.Check)
		}
		fmt.Printf(" expires=%s reason=%q\n", r.Expires, r.Reason)
	}
	return nil
}

func printUsage() {
	fmt.Println("Governor CLI")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  governor version")
	fmt.Println("  governor init [flags]")
	fmt.Println("  governor quickstart              — guided setup wizard")
	fmt.Println("  governor audit <path-or-zip> [flags]")
	fmt.Println("  governor doctor [flags]")
	fmt.Println("  governor matrix run [flags]")
	fmt.Println("  governor policy <validate|explain> [flags]")
	fmt.Println("  governor ci [<path>] [flags]")
	fmt.Println("  governor findings <suppress|unsuppress|prune|list|expired> [flags]")
	fmt.Println("  governor isolate audit <path-or-zip> [flags]")
	fmt.Println("  governor checks [<tui|init|add|extract|list|validate|doctor|explain|test|enable|disable|lock|update-packs|trust>] [flags]")
	fmt.Println("  governor checks tap <source>           Register a check pack source")
	fmt.Println("  governor checks untap <name>           Remove a registered source")
	fmt.Println("  governor checks install-pack <pack>    Install a check pack")
	fmt.Println("  governor checks list-packs             List available check packs")
	fmt.Println("  governor checks lock                   Write checks lock file")
	fmt.Println("  governor checks update-packs           Update locked pack versions")
	fmt.Println("  governor checks trust <validate|pin>   Validate/pin check-pack trust policy")
	fmt.Println("  governor hooks <install|remove|status>")
	fmt.Println("  governor diff <old.json> <new.json> [flags]")
	fmt.Println("  governor scan <file...> [flags]")
	fmt.Println("  governor fix <audit.json> [flags]")
	fmt.Println("  governor badge <audit.json> [flags]")
	fmt.Println("  governor clear [--without-last [N]]")
	fmt.Println("")
	fmt.Println("Flags (hooks install):")
	fmt.Println("  --force             Overwrite existing pre-commit hook")
	fmt.Println("")
	fmt.Println("Flags (clear):")
	fmt.Println("  --without-last [N]  Preserve the N most recent runs (default 1 if N omitted)")
	fmt.Println("")
	fmt.Println("Flags (doctor):")
	fmt.Println("  --json              Output doctor report as JSON")
	fmt.Println("  --strict            Treat warnings as failures")
	fmt.Println("")
	fmt.Println("Flags (matrix run):")
	fmt.Println("  --config <path>     Matrix config path (default ./.governor/matrix.yaml)")
	fmt.Println("  --out <dir>         Matrix summary output directory")
	fmt.Println("  --json              Print matrix summary JSON to stdout")
	fmt.Println("")
	fmt.Println("Flags (audit):")
	fmt.Println("  --out <dir>         Output directory (default ./.governor/runs/<timestamp>)")
	fmt.Println("  --workers <1-3>     Max concurrent worker processes (default 3)")
	fmt.Println("  --ai-profile <name> AI profile (default codex)")
	fmt.Println("  --ai-provider <name>  AI provider override: codex-cli|openai-compatible")
	fmt.Println("  --ai-model <id>    AI model override")
	fmt.Println("  --ai-auth-mode <mode> AI auth override: auto|account|api-key")
	fmt.Println("  --ai-base-url <url>  AI base URL override for openai-compatible providers")
	fmt.Println("  --ai-api-key-env <name>  AI API key env override")
	fmt.Println("  --ai-bin <path>    AI executable for codex-cli provider (default codex)")
	fmt.Println("  --allow-custom-ai-bin  Allow non-default ai binary (for testing)")
	fmt.Println("  --execution-mode <sandboxed|host>  Worker execution mode (default sandboxed)")
	fmt.Println("  --ai-sandbox <read-only|workspace-write|danger-full-access>  Sandbox mode for sandboxed execution")
	fmt.Println("  --max-files <n>     Included file count cap (default 20000)")
	fmt.Println("  --max-bytes <n>     Included file bytes cap (default 262144000)")
	fmt.Println("  --timeout <dur>     Per-worker timeout (default 4m, 0 disables timeout)")
	fmt.Println("  --verbose           Verbose execution logs")
	fmt.Println("  --checks-dir <dir>  Custom checks dir (default ./.governor/checks + ~/.governor/checks, repo first)")
	fmt.Println("  --only-check <id>   Run only specified check ID (repeatable)")
	fmt.Println("  --skip-check <id>   Skip specified check ID (repeatable)")
	fmt.Println("  --no-custom-checks  Disable custom check loading")
	fmt.Println("  --keep-workspace-error  Retain staged workspace on warning/failed runs (default deletes)")
	fmt.Println("  --tui               Enable interactive terminal UI")
	fmt.Println("  --fail-on <sev>     Exit non-zero if findings meet/exceed severity (critical|high|medium|low|info)")
	fmt.Println("  --fail-on-exploitability <mode>  Exit non-zero if findings meet/exceed exploitability (confirmed-path|reachable|theoretical)")
	fmt.Println("  --max-new-reachable <n>  Exit non-zero if reachable/confirmed-path new findings exceed n (-1 disables)")
	fmt.Println("  --min-confidence-for-block <0..1>  Only block findings at/above confidence threshold (-1 disables)")
	fmt.Println("  --require-attack-path-for-blocking  Only block findings with non-empty attack_path")
	fmt.Println("  --baseline <path>   Compare against a previous audit.json for diff report")
	fmt.Println("  --suppressions <path>  Suppressions YAML file (default ./.governor/suppressions.yaml)")
	fmt.Println("  --show-suppressed   Include suppressed findings in reports")
	fmt.Println("  --include-test-files  Include test files in security scanning (excluded by default)")
	fmt.Println("  --no-tui            Disable interactive terminal UI")
	fmt.Println("  --quick             Run only rule-engine checks (no AI, no network)")
	fmt.Println("  --policy <path>     Apply policy file (default ./.governor/policy.yaml if present)")
	fmt.Println("  --require-policy    Fail if no policy file is found")
	fmt.Println("  --changed-only      Scan only files with uncommitted changes (vs HEAD)")
	fmt.Println("  --changed-since <ref>  Scan only files changed since a git ref")
	fmt.Println("  --staged            Scan only staged files (for pre-commit use)")
	fmt.Println("  --ignore-file <path>  Path to .governorignore file (default .governorignore if present)")
	fmt.Println("")
	fmt.Println("Flags (fix):")
	fmt.Println("  --out <dir>          Output directory (default directory containing audit.json)")
	fmt.Println("  --json               Output fix report JSON to stdout")
	fmt.Println("  --max-suggestions <n>  Maximum findings to include (default 50)")
	fmt.Println("  --only-finding <id>  Only include finding ID(s) (repeatable)")
	fmt.Println("  --only-severity <sev>  Only include severity level(s) (repeatable)")
	fmt.Println("  --only-check <id>    Only include check/track ID(s) (repeatable)")
	fmt.Println("  --ai-profile <name>  AI profile (default codex)")
	fmt.Println("  --ai-provider <name> AI provider override: codex-cli|openai-compatible")
	fmt.Println("  --ai-model <id>      AI model override")
	fmt.Println("  --ai-auth-mode <mode>  AI auth override: auto|account|api-key")
	fmt.Println("  --ai-base-url <url>  AI base URL override for openai-compatible providers")
	fmt.Println("  --ai-api-key-env <name>  AI API key env override")
	fmt.Println("  --ai-bin <path>      AI executable for codex-cli provider (default codex)")
	fmt.Println("  --allow-custom-ai-bin  Allow non-default ai binary (for testing)")
	fmt.Println("  --execution-mode <sandboxed|host>  AI execution mode (default sandboxed)")
	fmt.Println("  --ai-sandbox <read-only|workspace-write|danger-full-access>  Sandbox mode for sandboxed execution")
	fmt.Println("")
	fmt.Println("Flags (ci):")
	fmt.Println("  --fail-on <sev>     Exit non-zero threshold (default high)")
	fmt.Println("  --comment-file <path>  Write PR comment markdown to file")
	fmt.Println("  --update-baseline   Write findings as .governor/baseline.json after audit")
	fmt.Println("  --baseline-file <path>  Baseline file path (default .governor/baseline.json)")
	fmt.Println("  --policy <path>     Apply policy file (default ./.governor/policy.yaml if present)")
	fmt.Println("  --require-policy    Fail if no policy file is found")
	fmt.Println("  --fail-on-exploitability <mode>  Exit non-zero if findings meet/exceed exploitability (confirmed-path|reachable|theoretical)")
	fmt.Println("  --max-new-reachable <n>  Exit non-zero if reachable/confirmed-path new findings exceed n (-1 disables)")
	fmt.Println("  --min-confidence-for-block <0..1>  Only block findings at/above confidence threshold (-1 disables)")
	fmt.Println("  --require-attack-path-for-blocking  Only block findings with non-empty attack_path")
	fmt.Println("  (also accepts most audit flags: --workers, --ai-*, --checks-dir, etc.)")
	fmt.Println("")
	fmt.Println("Flags (policy):")
	fmt.Println("  --file <path>       Policy file path (default ./.governor/policy.yaml)")
	fmt.Println("")
	fmt.Println("Flags (checks trust):")
	fmt.Println("  --trust-policy <path>  Trust policy path (default ./.governor/check-trust.yaml)")
	fmt.Println("  --strict               Fail on trust warnings/errors (validate)")
	fmt.Println("  --source <tap>         Override source when pinning a pack")
	fmt.Println("")
	fmt.Println("Flags (findings suppress):")
	fmt.Println("  <title-pattern>     Title glob pattern (positional)")
	fmt.Println("  --reason <text>     Reason for suppression (required)")
	fmt.Println("  --check <id>        Check ID to suppress")
	fmt.Println("  --category <cat>    Category to suppress")
	fmt.Println("  --files <glob>      File glob pattern")
	fmt.Println("  --severity <sev>    Severity to suppress")
	fmt.Println("  --author <email>    Author of suppression")
	fmt.Println("  --expires <date>    Expiration date (YYYY-MM-DD)")
	fmt.Println("")
	fmt.Println("Flags (findings unsuppress):")
	fmt.Println("  <id|pattern>        Suppression ID or glob pattern (positional)")
	fmt.Println("  --check <glob>      Match by check ID glob")
	fmt.Println("  --title <glob>      Match by title glob")
	fmt.Println("  --category <cat>    Match by category")
	fmt.Println("  --files <glob>      Match by file glob")
	fmt.Println("  --severity <sev>    Match by severity")
	fmt.Println("")
	fmt.Println("Flags (findings prune):")
	fmt.Println("  --expired-only      Prune only expired suppressions")
	fmt.Println("  --yes               Apply prune (without this flag, prune is preview-only)")
	fmt.Println("")
	fmt.Println("Flags (isolate audit):")
	fmt.Println("  --out <dir>         Output directory for artifacts (default ./.governor/runs/<timestamp>)")
	fmt.Println("  --runtime <name>    Container runtime: auto|docker|podman (default auto)")
	fmt.Println("  --image <ref>       Runner image (default governor-runner:local)")
	fmt.Println("  --network <mode>    Network policy: unrestricted|none (default none)")
	fmt.Println("  --pull <policy>     Image pull policy: always|if-missing|never (default never)")
	fmt.Println("  --clean-image       Remove runner image after run")
	fmt.Println("  --auth-mode <mode>  Auth mode: auto|account|api-key (default account)")
	fmt.Println("  --ai-home <dir>     Host AI account home for account auth bundle (default ~/.codex)")
	fmt.Println("  --ai-profile <name> AI profile (default codex)")
	fmt.Println("  --ai-provider <name>  AI provider override: codex-cli|openai-compatible")
	fmt.Println("  --ai-model <id>     AI model override")
	fmt.Println("  --ai-auth-mode <mode> AI auth override: auto|account|api-key")
	fmt.Println("  --ai-base-url <url> AI base URL override for openai-compatible providers")
	fmt.Println("  --ai-api-key-env <name>  AI API key env override")
	fmt.Println("  --ai-bin <path>     AI executable for codex-cli provider (default codex)")
	fmt.Println("  --execution-mode <sandboxed|host>  Inner worker execution mode (default host)")
	fmt.Println("  --ai-sandbox <read-only|workspace-write|danger-full-access>  Inner sandbox mode (used when execution is sandboxed)")
	fmt.Println("  --workers <1-3>     Max worker processes inside isolated run (default 3)")
	fmt.Println("  --timeout <dur>     Per-worker timeout inside isolated run (default 4m, 0 disables timeout)")
	fmt.Println("  --checks-dir <dir>  Mount custom checks read-only into isolated run")
	fmt.Println("  --only-check <id>   Run only specified check ID (repeatable)")
	fmt.Println("  --skip-check <id>   Skip specified check ID (repeatable)")
	fmt.Println("  --no-custom-checks  Disable custom check loading")
	fmt.Println("  --keep-workspace-error  Retain staged workspace on warning/failed runs (default deletes)")
	fmt.Println("  --include-test-files  Include test files in security scanning (excluded by default)")
	fmt.Println("  --fail-on <sev>     Exit non-zero if findings meet/exceed severity (critical|high|medium|low|info)")
	fmt.Println("")
	fmt.Println("Flags (diff):")
	fmt.Println("  --json              Output diff report as JSON")
	fmt.Println("  --fail-on <sev>     Exit non-zero if new findings meet/exceed severity")
	fmt.Println("  --out <file>        Write diff JSON to file")
	fmt.Println("")
	fmt.Println("Flags (scan):")
	fmt.Println("  --json              Output findings as JSON array")
	fmt.Println("  --only-check <id>   Only run specific check ID(s)")
	fmt.Println("  --skip-check <id>   Skip specific check ID(s)")
	fmt.Println("  --no-custom-checks  Run built-in rule checks only")
	fmt.Println("  --fail-on <sev>     Exit non-zero if findings meet/exceed severity")
	fmt.Println("  --ignore-file <path>  Path to .governorignore file")
}

func flagsExplicitlySet(fs *flag.FlagSet) map[string]struct{} {
	set := map[string]struct{}{}
	fs.Visit(func(f *flag.Flag) {
		set[f.Name] = struct{}{}
	})
	return set
}

func applyConfig(cfg config.Config, setFlags map[string]struct{},
	strFlags map[string]*string,
	intFlags map[string]*int,
	boolFlags map[string]*bool,
) {
	cfgStrMap := map[string]string{
		"ai-profile":     cfg.AIProfile,
		"ai-provider":    cfg.AIProvider,
		"ai-model":       cfg.AIModel,
		"ai-auth-mode":   cfg.AIAuthMode,
		"ai-base-url":    cfg.AIBaseURL,
		"ai-api-key-env": cfg.AIAPIKeyEnv,
		"execution-mode": cfg.ExecutionMode,
		"checks-dir":     cfg.ChecksDir,
		"fail-on":        cfg.FailOn,
		"baseline":       cfg.Baseline,
	}
	for name, ptr := range strFlags {
		if _, explicit := setFlags[name]; explicit {
			continue
		}
		if val, ok := cfgStrMap[name]; ok && val != "" {
			*ptr = val
		}
	}

	cfgIntMap := map[string]*int{
		"workers":   cfg.Workers,
		"max-files": cfg.MaxFiles,
	}
	for name, ptr := range intFlags {
		if _, explicit := setFlags[name]; explicit {
			continue
		}
		if cfgVal, ok := cfgIntMap[name]; ok && cfgVal != nil {
			*ptr = *cfgVal
		}
	}

	cfgBoolMap := map[string]*bool{
		"verbose":          cfg.Verbose,
		"no-custom-checks": cfg.NoCustom,
	}
	for name, ptr := range boolFlags {
		if _, explicit := setFlags[name]; explicit {
			continue
		}
		if cfgVal, ok := cfgBoolMap[name]; ok && cfgVal != nil {
			*ptr = *cfgVal
		}
	}
}

const (
	hookMarkerStart = "# >>> governor pre-commit hook >>>"
	hookMarkerEnd   = "# <<< governor pre-commit hook <<<"
	hookScript      = `#!/bin/sh
# >>> governor pre-commit hook >>>
governor audit --staged --quick --fail-on high
# <<< governor pre-commit hook <<<
`
)

func runHooks(args []string) error {
	if len(args) == 0 {
		return usageError("usage: governor hooks <install|remove|status>")
	}
	switch args[0] {
	case "install":
		return runHooksInstall(args[1:])
	case "remove":
		return runHooksRemove(args[1:])
	case "status":
		return runHooksStatus(args[1:])
	default:
		return usageError(fmt.Sprintf("unknown hooks subcommand %q", args[0]))
	}
}

func runHooksInstall(args []string) error {
	fs := flag.NewFlagSet("hooks install", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())
	force := fs.Bool("force", false, "Overwrite existing pre-commit hook")
	if err := fs.Parse(args); err != nil {
		return err
	}

	hookPath, err := resolvePreCommitHookPath()
	if err != nil {
		return err
	}

	if existing, statErr := os.ReadFile(hookPath); statErr == nil {
		if strings.Contains(string(existing), hookMarkerStart) {
			fmt.Println("governor pre-commit hook is already installed")
			return nil
		}
		if !*force {
			return fmt.Errorf("pre-commit hook already exists at %s (use --force to overwrite)", hookPath)
		}
	}

	hooksDir := filepath.Dir(hookPath)
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}

	if err := os.WriteFile(hookPath, []byte(hookScript), 0o755); err != nil {
		return fmt.Errorf("write pre-commit hook: %w", err)
	}
	fmt.Printf("installed governor pre-commit hook at %s\n", hookPath)
	return nil
}

func runHooksRemove(_ []string) error {
	hookPath, err := resolvePreCommitHookPath()
	if err != nil {
		return err
	}

	content, readErr := os.ReadFile(hookPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			fmt.Println("no pre-commit hook found")
			return nil
		}
		return fmt.Errorf("read pre-commit hook: %w", readErr)
	}

	if !strings.Contains(string(content), hookMarkerStart) {
		return fmt.Errorf("pre-commit hook at %s was not installed by governor (missing marker)", hookPath)
	}

	if err := os.Remove(hookPath); err != nil {
		return fmt.Errorf("remove pre-commit hook: %w", err)
	}
	fmt.Printf("removed governor pre-commit hook from %s\n", hookPath)
	return nil
}

func runHooksStatus(_ []string) error {
	hookPath, err := resolvePreCommitHookPath()
	if err != nil {
		return err
	}

	content, readErr := os.ReadFile(hookPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			fmt.Println("status: not installed")
			return nil
		}
		return fmt.Errorf("read pre-commit hook: %w", readErr)
	}

	if strings.Contains(string(content), hookMarkerStart) {
		fmt.Println("status: installed")
		fmt.Printf("path:   %s\n", hookPath)
	} else {
		fmt.Println("status: not installed (hook exists but not managed by governor)")
		fmt.Printf("path:   %s\n", hookPath)
	}
	return nil
}

func resolveIgnoreFile(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	defaultPath := ".governorignore"
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	return ""
}

func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	jsonOut := fs.Bool("json", false, "Output diff report as JSON")
	failOn := fs.String("fail-on", "", "Exit non-zero if new findings meet or exceed severity: critical|high|medium|low|info")
	outFile := fs.String("out", "", "Write diff JSON to file")

	if err := fs.Parse(args); err != nil {
		return err
	}
	remaining := fs.Args()
	if len(remaining) < 2 {
		return usageError("usage: governor diff <old.json> <new.json> [flags]")
	}
	if len(remaining) > 2 {
		return usageError("usage: governor diff <old.json> <new.json> [flags]")
	}

	oldReport, err := loadAuditJSON(remaining[0])
	if err != nil {
		return fmt.Errorf("load old report: %w", err)
	}
	newReport, err := loadAuditJSON(remaining[1])
	if err != nil {
		return fmt.Errorf("load new report: %w", err)
	}

	dr := diff.Compare(oldReport, newReport)

	if strings.TrimSpace(*outFile) != "" {
		b, marshalErr := json.MarshalIndent(dr, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal diff report: %w", marshalErr)
		}
		if writeErr := safefile.WriteFileAtomic(*outFile, b, 0o600); writeErr != nil {
			return fmt.Errorf("write diff file: %w", writeErr)
		}
		fmt.Printf("diff report written to %s\n", *outFile)
	}

	if *jsonOut {
		b, marshalErr := json.MarshalIndent(dr, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal diff report: %w", marshalErr)
		}
		fmt.Println(string(b))
	} else {
		printDiffSummary(dr)
	}

	return checkDiffFailOn(*failOn, dr)
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	jsonOut := fs.Bool("json", false, "Output findings as JSON array")
	failOn := fs.String("fail-on", "", "Exit non-zero if findings meet or exceed severity: critical|high|medium|low|info")
	checksDir := fs.String("checks-dir", "", "Checks directory")
	noCustomChecks := fs.Bool("no-custom-checks", false, "Run built-in rule checks only")

	var onlyChecks listFlag
	var skipChecks listFlag
	fs.Var(&onlyChecks, "only-check", "Only run specific check ID(s) (repeatable or comma-separated)")
	fs.Var(&skipChecks, "skip-check", "Skip specific check ID(s) (repeatable or comma-separated)")

	// Collect file args before flags.
	var files []string
	parseArgs := args
	for len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
		files = append(files, parseArgs[0])
		parseArgs = parseArgs[1:]
	}

	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	files = append(files, fs.Args()...)

	if len(files) == 0 {
		return usageError("usage: governor scan <file...> [flags]")
	}

	result, err := scan.Run(context.Background(), scan.Options{
		Files:          files,
		ChecksDir:      *checksDir,
		NoCustomChecks: *noCustomChecks,
		OnlyIDs:        onlyChecks.Values(),
		SkipIDs:        skipChecks.Values(),
	})
	if err != nil {
		return err
	}

	if *jsonOut {
		out, marshalErr := scan.FormatJSON(result.Findings)
		if marshalErr != nil {
			return marshalErr
		}
		fmt.Println(out)
	} else if isInteractiveTerminal() {
		fmt.Print(scan.FormatHumanColorized(result.Findings, false))
	} else {
		fmt.Print(scan.FormatHuman(result.Findings))
	}

	if strings.TrimSpace(*failOn) != "" {
		return checkFailOn(*failOn, model.AuditReport{Findings: result.Findings})
	}

	if len(result.Findings) > 0 {
		return fmt.Errorf("%d finding(s) detected", len(result.Findings))
	}
	return nil
}

func runFix(args []string) error {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	out := fs.String("out", "", "Output directory for fix artifacts (default directory containing audit.json)")
	jsonOut := fs.Bool("json", false, "Output fix report as JSON")
	maxSuggestions := fs.Int("max-suggestions", 50, "Maximum findings to include in fix suggestion generation")

	aiProfile := fs.String("ai-profile", "codex", "AI profile name (default codex)")
	aiProvider := fs.String("ai-provider", "", "AI provider override: codex-cli|openai-compatible")
	aiModel := fs.String("ai-model", "", "AI model override")
	aiAuthMode := fs.String("ai-auth-mode", "", "AI auth override: auto|account|api-key")
	aiBaseURL := fs.String("ai-base-url", "", "AI base URL override for openai-compatible providers")
	aiAPIKeyEnv := fs.String("ai-api-key-env", "", "AI API key environment variable override")

	var aiBin string
	fs.StringVar(&aiBin, "ai-bin", "codex", "AI CLI executable path (used by codex-cli provider)")
	fs.StringVar(&aiBin, "codex-bin", "codex", "Deprecated alias for --ai-bin")

	var allowCustomAIBin bool
	fs.BoolVar(&allowCustomAIBin, "allow-custom-ai-bin", false, "Allow non-default AI binary path (for testing only)")
	fs.BoolVar(&allowCustomAIBin, "allow-custom-codex-bin", false, "Deprecated alias for --allow-custom-ai-bin")

	executionMode := fs.String("execution-mode", "sandboxed", "AI execution mode: sandboxed|host")

	var aiSandbox string
	fs.StringVar(&aiSandbox, "ai-sandbox", "read-only", "AI sandbox mode for sandboxed execution: read-only|workspace-write|danger-full-access")
	fs.StringVar(&aiSandbox, "codex-sandbox", "read-only", "Deprecated alias for --ai-sandbox")

	var onlyFindingIDs listFlag
	var onlySeverities listFlag
	var onlyChecks listFlag
	fs.Var(&onlyFindingIDs, "only-finding", "Only suggest fixes for finding ID(s) (repeatable or comma-separated)")
	fs.Var(&onlySeverities, "only-severity", "Only suggest fixes for severity level(s) (repeatable or comma-separated)")
	fs.Var(&onlyChecks, "only-check", "Only suggest fixes for check/track ID(s) (repeatable or comma-separated)")

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
		return usageError("usage: governor fix <audit.json> [flags]")
	}

	if *maxSuggestions <= 0 {
		return errors.New("--max-suggestions must be > 0")
	}

	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", cfgErr)
	}
	setFlags := flagsExplicitlySet(fs)
	applyConfig(cfg, setFlags, map[string]*string{
		"ai-profile":     aiProfile,
		"ai-provider":    aiProvider,
		"ai-model":       aiModel,
		"ai-auth-mode":   aiAuthMode,
		"ai-base-url":    aiBaseURL,
		"ai-api-key-env": aiAPIKeyEnv,
		"execution-mode": executionMode,
	}, nil, nil)
	if _, ok := setFlags["ai-bin"]; !ok && cfg.AIBin != "" {
		aiBin = cfg.AIBin
	}
	if _, ok := setFlags["ai-sandbox"]; !ok && cfg.AISandbox != "" {
		aiSandbox = cfg.AISandbox
	}
	if strings.TrimSpace(aiBin) == "" {
		return errors.New("--ai-bin cannot be empty")
	}

	modeValue, err := normalizeExecutionModeFlag(*executionMode)
	if err != nil {
		return err
	}
	sandboxValue, err := normalizeSandboxModeFlag(aiSandbox)
	if err != nil {
		return err
	}
	if modeValue == "host" {
		sandboxValue = ""
	}

	aiRuntime, err := ai.ResolveRuntime(ai.ResolveOptions{
		Profile:       strings.TrimSpace(*aiProfile),
		Provider:      strings.TrimSpace(*aiProvider),
		Model:         strings.TrimSpace(*aiModel),
		AuthMode:      strings.TrimSpace(*aiAuthMode),
		Bin:           strings.TrimSpace(aiBin),
		BaseURL:       strings.TrimSpace(*aiBaseURL),
		APIKeyEnv:     strings.TrimSpace(*aiAPIKeyEnv),
		ExecutionMode: modeValue,
		SandboxMode:   sandboxValue,
	})
	if err != nil {
		return err
	}

	aiInfo := trust.AIBinary{}
	if aiRuntime.UsesCLI() {
		aiInfo, err = trust.ResolveAIBinary(context.Background(), aiRuntime.Bin, allowCustomAIBin)
		if err != nil {
			return err
		}
		aiRuntime.Bin = aiInfo.ResolvedPath
	}

	fixReport, paths, err := fix.Run(context.Background(), fix.Options{
		AuditPath:      positionalInput,
		OutDir:         strings.TrimSpace(*out),
		AIRuntime:      aiRuntime,
		AIRequestedBin: aiInfo.RequestedPath,
		AIBin:          aiInfo.ResolvedPath,
		AIVersion:      aiInfo.Version,
		AISHA256:       aiInfo.SHA256,
		Filters: model.FixFilters{
			OnlyFindingIDs: onlyFindingIDs.Values(),
			OnlySeverities: onlySeverities.Values(),
			OnlyChecks:     onlyChecks.Values(),
			MaxSuggestions: *maxSuggestions,
		},
	})
	if err != nil {
		return err
	}

	fmt.Println("fix suggestion run complete")
	fmt.Printf("source audit:   %s\n", fixReport.SourceAudit)
	fmt.Printf("fix artifacts:  %s\n", paths.FixDir)
	fmt.Printf("fix json:       %s\n", paths.JSONPath)
	fmt.Printf("fix markdown:   %s\n", paths.MarkdownPath)
	fmt.Printf("fix worker log: %s\n", paths.LogPath)
	fmt.Printf("findings:       %d selected / %d total\n", fixReport.Selected, fixReport.TotalFindings)
	fmt.Printf("suggestions:    %d\n", len(fixReport.Suggestions))
	if len(fixReport.Warnings) > 0 {
		for _, warning := range fixReport.Warnings {
			fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
		}
	}

	if *jsonOut {
		b, marshalErr := json.MarshalIndent(fixReport, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal fix report: %w", marshalErr)
		}
		fmt.Println(string(b))
	}
	return nil
}

func loadAuditJSON(path string) (model.AuditReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.AuditReport{}, fmt.Errorf("read %s: %w", path, err)
	}
	var report model.AuditReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return model.AuditReport{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return report, nil
}

func printDiffSummary(dr diff.DiffReport) {
	fmt.Println("diff summary:")
	fmt.Printf("  new findings:       %d\n", dr.Summary.NewCount)
	fmt.Printf("  resolved findings:  %d\n", dr.Summary.FixedCount)
	fmt.Printf("  unchanged:          %d\n", dr.Summary.UnchangedCount)

	if len(dr.New) > 0 {
		fmt.Println("")
		fmt.Println("new findings:")
		for _, f := range dr.New {
			cats := strings.TrimSpace(f.Category)
			track := strings.TrimSpace(f.SourceTrack)
			label := ""
			if cats != "" || track != "" {
				parts := []string{}
				if cats != "" {
					parts = append(parts, cats)
				}
				if track != "" {
					parts = append(parts, track)
				}
				label = " (" + strings.Join(parts, ", ") + ")"
			}
			fmt.Printf("  [%-8s] %s%s\n", strings.ToUpper(f.Severity), f.Title, label)
		}
	}

	if len(dr.Fixed) > 0 {
		fmt.Println("")
		fmt.Println("resolved findings:")
		for _, f := range dr.Fixed {
			cats := strings.TrimSpace(f.Category)
			track := strings.TrimSpace(f.SourceTrack)
			label := ""
			if cats != "" || track != "" {
				parts := []string{}
				if cats != "" {
					parts = append(parts, cats)
				}
				if track != "" {
					parts = append(parts, track)
				}
				label = " (" + strings.Join(parts, ", ") + ")"
			}
			fmt.Printf("  [%-8s] %s%s\n", strings.ToUpper(f.Severity), f.Title, label)
		}
	}
}

func checkDiffFailOn(threshold string, dr diff.DiffReport) error {
	threshold = strings.ToLower(strings.TrimSpace(threshold))
	if threshold == "" {
		return nil
	}
	thresholdWeight, ok := severityWeightMap[threshold]
	if !ok {
		return fmt.Errorf("invalid --fail-on severity %q (expected critical, high, medium, low, or info)", threshold)
	}
	count := 0
	for _, f := range dr.New {
		w, exists := severityWeightMap[strings.ToLower(strings.TrimSpace(f.Severity))]
		if !exists {
			w = severityWeightMap["info"]
		}
		if w <= thresholdWeight {
			count++
		}
	}
	if count > 0 {
		return fmt.Errorf("new findings exceed --fail-on threshold %q (%d new finding(s) at or above %s severity)",
			threshold, count, threshold)
	}
	return nil
}

func resolvePreCommitHookPath() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--git-dir").Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository (or git not installed): %w", err)
	}
	gitDir := strings.TrimSpace(string(out))
	return filepath.Join(gitDir, "hooks", "pre-commit"), nil
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

func runBadge(args []string) error {
	fs := flag.NewFlagSet("badge", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())

	out := fs.String("out", "", "Output file path (default governor-badge.svg or governor-badge.json)")
	format := fs.String("format", "svg", "Output format: svg|shields-json")
	style := fs.String("style", "flat", "Badge style: flat|flat-square")
	label := fs.String("label", "governor", "Badge label text")

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
		return usageError("usage: governor badge <audit.json> [flags]")
	}

	data, err := os.ReadFile(positionalInput)
	if err != nil {
		return fmt.Errorf("read audit file: %w", err)
	}

	var report model.AuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("parse audit file: %w", err)
	}

	grade, color := badge.Grade(report.CountsBySeverity)

	outputFormat := strings.ToLower(strings.TrimSpace(*format))
	outputPath := strings.TrimSpace(*out)

	var content string
	switch outputFormat {
	case "shields-json":
		content = badge.ShieldsJSON(*label, grade, color)
		if outputPath == "" {
			outputPath = "governor-badge.json"
		}
	case "svg":
		content = badge.RenderSVG(*label, grade, color, badge.ParseStyle(*style))
		if outputPath == "" {
			outputPath = "governor-badge.svg"
		}
	default:
		return fmt.Errorf("unknown badge format %q (use svg or shields-json)", outputFormat)
	}

	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write badge: %w", err)
	}

	fmt.Printf("badge: %s (grade %s) -> %s\n", *label, grade, outputPath)
	return nil
}

// ---------------------------------------------------------------------------
// quickstart — interactive guided setup wizard
// ---------------------------------------------------------------------------

func runQuickstart(args []string) error {
	fs := flag.NewFlagSet("quickstart", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runQuickstartWithIO(".", os.Stdin, os.Stderr)
}

func runQuickstartWithIO(root string, in io.Reader, out io.Writer) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve root path: %w", err)
	}

	scanner := bufio.NewScanner(in)

	w := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format, a...) }
	wln := func(s string) { _, _ = fmt.Fprintln(out, s) }

	wln("")
	wln("Welcome to Governor — security auditing for AI-generated code.")
	wln("")

	// Detect project type.
	proj := detect.Project(absRoot)
	if proj.Type != "" {
		w("Detected project type: %s\n", proj.Label)
	} else {
		wln("Project type: unknown")
	}
	wln("")

	// Prompt 1: Initialize .governor directory.
	initDir := promptYN(scanner, out, "Initialize .governor directory?", true)
	if initDir {
		if err := initGovDir(absRoot, ""); err != nil {
			return fmt.Errorf("initialize .governor: %w", err)
		}
		wln("  created .governor/config.yaml")
		wln("  created .governor/.gitignore")
		wln("  created .governor/checks/")
		wln("")
	}

	// Prompt 2: Install pre-commit hook (only if .git exists).
	gitDir := filepath.Join(absRoot, ".git")
	if _, statErr := os.Stat(gitDir); statErr == nil {
		installHook := promptYN(scanner, out, "Install pre-commit hook?", true)
		if installHook {
			hooksDir := filepath.Join(gitDir, "hooks")
			if err := os.MkdirAll(hooksDir, 0o755); err != nil {
				return fmt.Errorf("create hooks directory: %w", err)
			}
			hookPath := filepath.Join(hooksDir, "pre-commit")
			if err := os.WriteFile(hookPath, []byte(hookScript), 0o755); err != nil {
				return fmt.Errorf("write pre-commit hook: %w", err)
			}
			w("  installed pre-commit hook at %s\n", hookPath)
			wln("")
		}
	}

	// Prompt 3: Set up AI-powered checks.
	setupAI := promptYN(scanner, out, "Set up AI-powered checks?", false)
	if setupAI {
		wln("")
		wln("To use AI-powered checks, configure an AI provider:")
		wln("")
		wln("  Option 1 — Codex CLI (default):")
		wln("    Install: npm install -g @openai/codex")
		wln("    Set:     export OPENAI_API_KEY=<your-key>")
		wln("")
		wln("  Option 2 — OpenAI-compatible API:")
		wln("    governor init --ai-profile openai")
		wln("    Set:     export OPENAI_API_KEY=<your-key>")
		wln("")
		wln("  Option 3 — Claude:")
		wln("    governor init --ai-profile claude")
		wln("    Set:     export ANTHROPIC_API_KEY=<your-key>")
		wln("")
	}

	// Prompt 4: Run first audit.
	runNow := promptYN(scanner, out, "Run your first audit now?", true)
	if runNow {
		wln("")
		wln("Running: governor audit --quick ...")
		wln("")
		if auditErr := runAudit([]string{absRoot, "--quick"}); auditErr != nil {
			w("Audit completed with findings: %v\n", auditErr)
		}
	}

	// Next steps.
	wln("")
	wln("Next steps:")
	wln("  governor audit <path>       — run a full security audit")
	wln("  governor checks init        — scaffold a custom check")
	wln("  governor checks list        — list available checks")
	wln("  governor doctor             — verify installation health")
	wln("")

	return nil
}

// promptYN displays a yes/no prompt and returns the user's choice.
// defaultYes controls the default when the user presses enter without typing.
func promptYN(scanner *bufio.Scanner, out io.Writer, prompt string, defaultYes bool) bool {
	hint := "[y/N]"
	if defaultYes {
		hint = "[Y/n]"
	}
	_, _ = fmt.Fprintf(out, "%s %s ", prompt, hint)

	if !scanner.Scan() {
		return defaultYes
	}
	answer := strings.TrimSpace(scanner.Text())
	if answer == "" {
		return defaultYes
	}

	switch strings.ToLower(answer) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return false
	}
}

// initGovDir creates the .governor directory structure with config.yaml,
// .gitignore, and an empty checks/ subdirectory. If aiProfile is non-empty
// the ai_profile line in config.yaml is uncommented and set.
func initGovDir(root string, aiProfile string) error {
	govDir := filepath.Join(root, ".governor")
	checksDir := filepath.Join(govDir, "checks")
	gitignorePath := filepath.Join(govDir, ".gitignore")
	configPath := filepath.Join(govDir, "config.yaml")

	if err := os.MkdirAll(checksDir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", checksDir, err)
	}

	gitignoreContent := `# Keep this file and repo-local checks.
*
!.gitignore
!checks/
!checks/**
!suppressions.yaml
!baseline.json
!config.yaml

# Always ignore generated run artifacts.
runs/
`

	configContent := `# Governor configuration
# Docs: https://github.com/anthropics/governor
#
# Values here override global (~/.governor/config.yaml) settings.
# CLI flags override both.

# ai_profile: codex
# ai_provider: codex-cli
# ai_model:
# workers: 3
# execution_mode: sandboxed
# ai_sandbox: read-only
# fail_on:
# timeout: 4m
# verbose: false
`

	if strings.TrimSpace(aiProfile) != "" {
		configContent = strings.Replace(configContent, "# ai_profile: codex", "ai_profile: "+strings.TrimSpace(aiProfile), 1)
	}

	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0o600); err != nil {
		return fmt.Errorf("write .gitignore: %w", err)
	}

	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		return fmt.Errorf("write config.yaml: %w", err)
	}

	return nil
}
