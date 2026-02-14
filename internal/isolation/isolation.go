package isolation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"governor/internal/ai"
	"governor/internal/checks"
	"governor/internal/model"
	reportpkg "governor/internal/report"
	"governor/internal/safefile"
)

const (
	DefaultImage       = "governor-runner:local"
	defaultAIHome      = "~/.codex"
	defaultWorkers     = 3
	defaultMaxFiles    = 20000
	defaultMaxBytes    = 250 * 1024 * 1024
	defaultTimeout     = 4 * time.Minute
	preflightAITO      = 20 * time.Second
	defaultPathInImage = "/usr/bin:/bin:/usr/sbin:/sbin"
	defaultExecMode    = "host"
	defaultSandboxMode = "read-only"
)

type Runtime string

const (
	RuntimeAuto   Runtime = "auto"
	RuntimeDocker Runtime = "docker"
	RuntimePodman Runtime = "podman"
)

type NetworkPolicy string

const (
	NetworkUnrestricted NetworkPolicy = "unrestricted"
	NetworkNone         NetworkPolicy = "none"
)

type PullPolicy string

const (
	PullAlways    PullPolicy = "always"
	PullIfMissing PullPolicy = "if-missing"
	PullNever     PullPolicy = "never"
)

type AuthMode string

const (
	AuthAuto         AuthMode = "auto"
	AuthAccount      AuthMode = "account"
	AuthSubscription AuthMode = AuthAccount
	AuthAPIKey       AuthMode = "api-key"
)

type AuditOptions struct {
	InputPath string
	OutDir    string
	ChecksDir string

	Runtime       Runtime
	Image         string
	NetworkPolicy NetworkPolicy
	PullPolicy    PullPolicy
	CleanImage    bool

	AuthMode  AuthMode
	AIRuntime ai.Runtime
	AIHome    string
	CodexHome string

	Workers  int
	MaxFiles int
	MaxBytes int64
	Timeout  time.Duration
	Verbose  bool

	ExecutionMode string
	SandboxMode   string

	NoCustomChecks       bool
	OnlyChecks           []string
	SkipChecks           []string
	KeepWorkspaceOnError bool
	IncludeTestFiles     bool
}

func RunAudit(ctx context.Context, opts AuditOptions) error {
	opts = normalizeOptions(opts)
	if err := validateOptions(opts); err != nil {
		return err
	}

	inputAbs, err := filepath.Abs(strings.TrimSpace(opts.InputPath))
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}
	inStat, err := os.Stat(inputAbs)
	if err != nil {
		return fmt.Errorf("stat input path: %w", err)
	}
	if !inStat.IsDir() && !strings.EqualFold(filepath.Ext(inputAbs), ".zip") {
		return fmt.Errorf("input must be a folder or .zip file")
	}

	outAbs, err := resolveOutDir(opts.OutDir, time.Now().UTC())
	if err != nil {
		return err
	}
	outAbs, err = safefile.EnsureFreshDir(outAbs, 0o700)
	if err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	var checksAbs string
	if strings.TrimSpace(opts.ChecksDir) != "" {
		checksAbs, err = filepath.Abs(strings.TrimSpace(opts.ChecksDir))
		if err != nil {
			return fmt.Errorf("resolve checks dir: %w", err)
		}
		info, err := os.Stat(checksAbs)
		if err != nil {
			return fmt.Errorf("stat checks dir: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("checks dir must be a directory")
		}
	}

	runtimeBin, err := resolveRuntime(opts.Runtime)
	if err != nil {
		return err
	}

	if err := ensureImage(ctx, runtimeBin, opts.Image, opts.PullPolicy); err != nil {
		return err
	}
	defer func() {
		if opts.CleanImage {
			_ = removeImage(context.Background(), runtimeBin, opts.Image)
		}
	}()

	hostEnv := envToMap(os.Environ())
	aiRequired, selectionWarnings, err := isolateSelectionRequiresAI(opts)
	if err != nil {
		return err
	}
	runtimeCfg := opts.AIRuntime
	if strings.TrimSpace(runtimeCfg.Provider) == "" {
		runtimeCfg, err = ai.ResolveRuntime(ai.ResolveOptions{
			Profile:       "codex",
			ExecutionMode: opts.ExecutionMode,
			SandboxMode:   opts.SandboxMode,
			AccountHome:   opts.AIHome,
		})
		if err != nil {
			return err
		}
	}

	authMode := AuthAuto
	if aiRequired {
		authMode, err = resolveAuthMode(opts.AuthMode, runtimeCfg, opts.AIHome, hostEnv)
		if err != nil {
			return err
		}
	}

	tmpRoot, err := os.MkdirTemp("", "governor-isolate-*")
	if err != nil {
		return fmt.Errorf("create isolate temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpRoot) }()

	var seedDir string
	if aiRequired && authMode == AuthAccount && runtimeCfg.UsesCLI() {
		aiHome, err := resolveAIHome(opts.AIHome)
		if err != nil {
			return err
		}
		seedDir, err = stageAccountBundle(aiHome, filepath.Join(tmpRoot, "ai-seed"))
		if err != nil {
			return err
		}
	}

	containerEnv := buildContainerEnv(hostEnv, runtimeCfg, authMode, aiRequired)
	preflight := runPreflight(ctx, runtimeBin, opts, runtimeCfg, authMode, seedDir, containerEnv, aiRequired)
	preflight.Warnings = append(preflight.Warnings, selectionWarnings...)
	emitPreflight(preflight)
	opts.AIRuntime = runtimeCfg
	govArgs := buildInnerGovernorArgs(opts, checksAbs != "")
	runArgs := buildContainerRunArgs(opts, inputAbs, outAbs, checksAbs, seedDir, envNames(containerEnv), govArgs)

	cmd := exec.CommandContext(ctx, runtimeBin, runArgs...)
	cmd.Env = mergeEnv(os.Environ(), containerEnv)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("isolated audit failed: %w", err)
	}

	if len(preflight.Warnings) > 0 {
		if err := appendWarningsToAuditArtifacts(outAbs, preflight.Warnings); err != nil {
			fmt.Fprintf(os.Stderr, "[governor] warning: failed to append preflight warnings to report: %v\n", err)
		}
	}
	return nil
}

type preflightResult struct {
	Notes    []string
	Warnings []string
}

type endpointProbeResult struct {
	DNSOK   bool   `json:"dns_ok"`
	HTTPSOK bool   `json:"https_ok"`
	Status  int    `json:"status"`
	Error   string `json:"error"`
}

type codexProbeResult struct {
	OK          bool   `json:"ok"`
	ExitCode    int    `json:"exit_code"`
	HasCABundle bool   `json:"has_ca_bundle"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
}

func runPreflight(
	ctx context.Context,
	runtimeBin string,
	opts AuditOptions,
	runtimeCfg ai.Runtime,
	authMode AuthMode,
	seedDir string,
	containerEnv []string,
	aiRequired bool,
) preflightResult {
	result := preflightResult{
		Notes: []string{
			fmt.Sprintf("isolate preflight: ai-required=%t network=%s provider=%s", aiRequired, opts.NetworkPolicy, runtimeCfg.Provider),
		},
		Warnings: []string{},
	}
	if !aiRequired {
		result.Notes = append(result.Notes, "isolate preflight: selected checks are deterministic only; skipping AI auth/probe")
		return result
	}
	result.Notes = append(result.Notes, fmt.Sprintf("isolate preflight: auth-mode=%s", authMode))

	switch authMode {
	case AuthAccount:
		if seedDir == "" {
			result.Warnings = append(result.Warnings, "isolate preflight: account auth selected but no staged auth bundle was mounted")
		} else if _, err := os.Stat(filepath.Join(seedDir, "auth.json")); err != nil {
			result.Warnings = append(result.Warnings, "isolate preflight: staged account auth.json is unavailable")
		}
	case AuthAPIKey:
		result.Notes = append(result.Notes, "isolate preflight: using API key environment forwarding")
	default:
		result.Notes = append(result.Notes, "isolate preflight: using auto auth selection")
	}

	if opts.NetworkPolicy == NetworkNone {
		result.Warnings = append(result.Warnings, "isolate preflight: network policy is none; AI egress is disabled by policy")
		return result
	}

	if !runtimeCfg.UsesCLI() {
		result.Notes = append(result.Notes, "isolate preflight: non-CLI AI provider selected; skipping CLI exec probe")
		return result
	}

	endpointProbe, err := probeCodexEndpoint(ctx, runtimeBin, opts, seedDir, containerEnv)
	if err != nil {
		result.Warnings = append(result.Warnings, "[infra.network] isolate preflight: AI endpoint probe failed: "+sanitizeErr(err))
	} else if endpointProbe.HTTPSOK {
		result.Notes = append(result.Notes, fmt.Sprintf("isolate preflight: AI endpoint reachable (status=%d)", endpointProbe.Status))
	} else {
		msg := "[infra.network] isolate preflight: AI endpoint probe could not establish HTTPS"
		if strings.TrimSpace(endpointProbe.Error) != "" {
			msg += ": " + sanitizeErr(errors.New(endpointProbe.Error))
		}
		result.Warnings = append(result.Warnings, msg)
	}

	probeCtx, cancel := context.WithTimeout(ctx, preflightAITO)
	defer cancel()
	codexProbe, err := probeCodexExec(probeCtx, runtimeBin, opts, seedDir, containerEnv)
	if err != nil {
		result.Warnings = append(result.Warnings, "[infra.unknown] isolate preflight: AI exec probe failed: "+sanitizeErr(err))
		return result
	}
	if !codexProbe.HasCABundle {
		result.Warnings = append(result.Warnings, "[infra.tls_trust] isolate preflight: runner image does not expose a CA trust bundle")
	}
	if codexProbe.OK {
		result.Notes = append(result.Notes, "isolate preflight: AI exec probe succeeded")
	} else {
		label, reason := classifyCodexProbeFailure(codexProbe)
		msg := fmt.Sprintf("[%s] isolate preflight: AI exec probe failed (exit=%d): %s", label, codexProbe.ExitCode, reason)
		if tail := summarizeProbeTail(codexProbe.Stderr, codexProbe.Stdout); tail != "" {
			msg += ": " + tail
		}
		result.Warnings = append(result.Warnings, msg)
	}
	return result
}

func emitPreflight(result preflightResult) {
	for _, note := range result.Notes {
		note = strings.TrimSpace(note)
		if note == "" {
			continue
		}
		fmt.Fprintf(os.Stderr, "[governor] %s\n", note)
	}
	for _, warning := range result.Warnings {
		warning = strings.TrimSpace(warning)
		if warning == "" {
			continue
		}
		fmt.Fprintf(os.Stderr, "[governor] warning: %s\n", warning)
	}
}

func sanitizeErr(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "unknown error"
	}
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.ReplaceAll(msg, "\r", " ")
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return msg
}

func summarizeProbeTail(parts ...string) string {
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		part = sanitizeErr(errors.New(part))
		if part != "" {
			return part
		}
	}
	return ""
}

func hasAnyPattern(text string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}

func classifyCodexProbeFailure(probe codexProbeResult) (label string, reason string) {
	text := strings.ToLower(strings.TrimSpace(probe.Stderr + "\n" + probe.Stdout))
	if hasAnyPattern(text,
		"unable to get local issuer certificate",
		"certificate verify failed",
		"x509:",
		"unknown certificate",
		"self signed certificate",
		"tls handshake failure",
	) {
		return "infra.tls_trust", "TLS trust validation failed while AI provider attempted HTTPS"
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
		return "auth.account", "authentication is unavailable for AI provider in isolated mode"
	}
	if hasAnyPattern(text,
		"temporary failure in name resolution",
		"network is unreachable",
		"no route to host",
		"connection refused",
		"connection reset by peer",
		"timed out",
		"context deadline exceeded",
	) {
		return "infra.network", "network connectivity to AI endpoints failed"
	}
	if hasAnyPattern(text,
		"stream disconnected before completion",
		"error sending request for url",
	) {
		return "stream.transient", "AI stream disconnected before a response completed"
	}
	return "infra.unknown", "AI probe failed with an unclassified error"
}

func probeCodexEndpoint(
	ctx context.Context,
	runtimeBin string,
	opts AuditOptions,
	seedDir string,
	containerEnv []string,
) (endpointProbeResult, error) {
	script := `set -eu
if [ -d /ai-seed ]; then cp -R /ai-seed/. /ai-home/; chmod -R go-rwx /ai-home || true; fi
node -e '
const dns = require("dns").promises;
const https = require("https");
async function main() {
  const out = { dns_ok: false, https_ok: false, status: 0, error: "" };
  try {
    await dns.lookup("chatgpt.com");
    out.dns_ok = true;
  } catch (e) {
    out.error = "dns:" + (e && e.message ? e.message : String(e));
  }
  try {
    await new Promise((resolve, reject) => {
      const req = https.request("https://chatgpt.com/backend-api/codex/models?client_version=0.101.0", { method: "GET", timeout: 8000 }, (res) => {
        out.status = res.statusCode || 0;
        out.https_ok = true;
        res.resume();
        res.on("end", resolve);
      });
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", reject);
      req.end();
    });
  } catch (e) {
    const msg = "https:" + (e && e.message ? e.message : String(e));
    out.error = out.error ? out.error + "; " + msg : msg;
  }
  process.stdout.write(JSON.stringify(out));
  process.exit(out.https_ok ? 0 : 2);
}
main().catch((e) => {
  process.stdout.write(JSON.stringify({ dns_ok: false, https_ok: false, status: 0, error: String(e) }));
  process.exit(2);
});
'`
	args := buildProbeContainerRunArgs(opts, seedDir, envNames(containerEnv), script)

	cmd := exec.CommandContext(ctx, runtimeBin, args...)
	cmd.Env = mergeEnv(os.Environ(), containerEnv)
	out, err := cmd.CombinedOutput()

	probe, parseErr := parseEndpointProbeOutput(out)
	if parseErr != nil {
		if err != nil {
			return endpointProbeResult{}, fmt.Errorf("%v; parse probe output: %w", err, parseErr)
		}
		return endpointProbeResult{}, fmt.Errorf("parse probe output: %w", parseErr)
	}
	if err != nil {
		return probe, err
	}
	return probe, nil
}

func parseEndpointProbeOutput(raw []byte) (endpointProbeResult, error) {
	out, err := extractTrailingJSON(raw)
	if err != nil {
		return endpointProbeResult{}, err
	}
	result := endpointProbeResult{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return endpointProbeResult{}, err
	}
	return result, nil
}

func probeCodexExec(
	ctx context.Context,
	runtimeBin string,
	opts AuditOptions,
	seedDir string,
	containerEnv []string,
) (codexProbeResult, error) {
	script := `set -eu
if [ -d /ai-seed ]; then cp -R /ai-seed/. /ai-home/; chmod -R go-rwx /ai-home || true; fi
ca_bundle=0
if [ -f /etc/ssl/certs/ca-certificates.crt ] || [ -f /etc/ssl/cert.pem ]; then
  ca_bundle=1
fi
set +e
printf '%s\n' 'Reply exactly OK.' | timeout 20s codex exec --skip-git-repo-check -C /work --color never - >/tmp/codex-probe.out 2>/tmp/codex-probe.err
exit_code=$?
set -e
PROBE_EXIT="$exit_code" PROBE_CA_BUNDLE="$ca_bundle" node -e '
const fs = require("fs");
const exitCode = Number(process.env.PROBE_EXIT || "1");
const hasCABundle = process.env.PROBE_CA_BUNDLE === "1";
function readTail(path, maxChars) {
  try {
    const data = fs.readFileSync(path, "utf8");
    if (data.length <= maxChars) return data;
    return data.slice(data.length - maxChars);
  } catch (e) {
    return "";
  }
}
const payload = {
  ok: exitCode === 0,
  exit_code: exitCode,
  has_ca_bundle: hasCABundle,
  stdout: readTail("/tmp/codex-probe.out", 600),
  stderr: readTail("/tmp/codex-probe.err", 2500),
};
process.stdout.write(JSON.stringify(payload));
process.exit(payload.ok ? 0 : 2);
'`
	args := buildProbeContainerRunArgs(opts, seedDir, envNames(containerEnv), script)

	cmd := exec.CommandContext(ctx, runtimeBin, args...)
	cmd.Env = mergeEnv(os.Environ(), containerEnv)
	out, err := cmd.CombinedOutput()

	probe, parseErr := parseCodexProbeOutput(out)
	if parseErr != nil {
		if err != nil {
			return codexProbeResult{}, fmt.Errorf("%v; parse probe output: %w", err, parseErr)
		}
		return codexProbeResult{}, fmt.Errorf("parse probe output: %w", parseErr)
	}
	if err != nil {
		return probe, err
	}
	return probe, nil
}

func parseCodexProbeOutput(raw []byte) (codexProbeResult, error) {
	out, err := extractTrailingJSON(raw)
	if err != nil {
		return codexProbeResult{}, err
	}
	result := codexProbeResult{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return codexProbeResult{}, err
	}
	return result, nil
}

func extractTrailingJSON(raw []byte) (string, error) {
	out := strings.TrimSpace(string(raw))
	if out == "" {
		return "", fmt.Errorf("empty probe output")
	}
	start := strings.LastIndex(out, "{")
	if start < 0 {
		return "", fmt.Errorf("probe output missing json payload")
	}
	return out[start:], nil
}

func buildProbeContainerRunArgs(opts AuditOptions, seedDir string, envVars []string, script string) []string {
	args := []string{"run", "--rm"}
	args = append(args,
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--pids-limit", "64",
		"--memory", "256m",
		"--cpus", "0.5",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
		"--tmpfs", "/home/governor:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=700",
		"--tmpfs", "/work:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=700",
		"--tmpfs", "/ai-home:rw,nosuid,nodev,size=32m,uid=65532,gid=65532,mode=700",
		"--entrypoint", "sh",
		"-w", "/work",
	)
	if seedDir != "" {
		args = append(args, "-v", fmt.Sprintf("%s:/ai-seed:ro", seedDir))
	}
	if opts.NetworkPolicy == NetworkNone {
		args = append(args, "--network", "none")
	}
	for _, key := range envVars {
		args = append(args, "-e", key)
	}
	args = append(args, opts.Image, "-lc", script)
	return args
}

func appendWarningsToAuditArtifacts(outDir string, warnings []string) error {
	if len(warnings) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(warnings))
	seen := map[string]struct{}{}
	for _, warning := range warnings {
		warning = strings.TrimSpace(warning)
		if warning == "" {
			continue
		}
		if _, ok := seen[warning]; ok {
			continue
		}
		seen[warning] = struct{}{}
		sanitized = append(sanitized, warning)
	}
	if len(sanitized) == 0 {
		return nil
	}

	jsonPath := filepath.Join(outDir, "audit.json")
	mdPath := filepath.Join(outDir, "audit.md")
	htmlPath := filepath.Join(outDir, "audit.html")

	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return err
	}
	var report model.AuditReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}
	existing := make(map[string]struct{}, len(report.Errors))
	for _, existingErr := range report.Errors {
		existing[strings.TrimSpace(existingErr)] = struct{}{}
	}
	for _, warning := range sanitized {
		if _, ok := existing[warning]; ok {
			continue
		}
		report.Errors = append(report.Errors, warning)
		existing[warning] = struct{}{}
	}
	if err := reportpkg.WriteJSON(jsonPath, report); err != nil {
		return err
	}
	if err := reportpkg.WriteMarkdown(mdPath, report); err != nil {
		return err
	}
	if err := reportpkg.WriteHTML(htmlPath, report); err != nil {
		return err
	}
	return nil
}

func normalizeOptions(opts AuditOptions) AuditOptions {
	if strings.TrimSpace(opts.Image) == "" {
		opts.Image = DefaultImage
	}
	if opts.Runtime == "" {
		opts.Runtime = RuntimeAuto
	}
	if opts.NetworkPolicy == "" {
		opts.NetworkPolicy = NetworkNone
	}
	if opts.PullPolicy == "" {
		opts.PullPolicy = PullNever
	}
	if opts.AuthMode == "" {
		opts.AuthMode = AuthAccount
	}
	if strings.TrimSpace(opts.AIHome) == "" {
		opts.AIHome = strings.TrimSpace(opts.CodexHome)
	}
	if strings.TrimSpace(opts.AIHome) == "" {
		opts.AIHome = defaultAIHome
	}
	if opts.Workers < 1 {
		opts.Workers = defaultWorkers
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = defaultMaxFiles
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxBytes
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if strings.TrimSpace(opts.ExecutionMode) == "" {
		opts.ExecutionMode = defaultExecMode
	}
	if strings.TrimSpace(opts.SandboxMode) == "" && normalizeExecutionMode(opts.ExecutionMode) == "sandboxed" {
		opts.SandboxMode = defaultSandboxMode
	}
	return opts
}

func validateOptions(opts AuditOptions) error {
	if strings.TrimSpace(opts.InputPath) == "" {
		return errors.New("input path is required")
	}
	if opts.Workers < 1 || opts.Workers > 3 {
		return errors.New("--workers must be between 1 and 3")
	}
	if opts.MaxFiles <= 0 {
		return errors.New("--max-files must be > 0")
	}
	if opts.MaxBytes <= 0 {
		return errors.New("--max-bytes must be > 0")
	}
	if opts.Timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}
	switch opts.Runtime {
	case RuntimeAuto, RuntimeDocker, RuntimePodman:
	default:
		return errors.New("--runtime must be auto, docker, or podman")
	}
	switch opts.NetworkPolicy {
	case NetworkUnrestricted, NetworkNone:
	default:
		return errors.New("--network must be unrestricted or none")
	}
	switch opts.PullPolicy {
	case PullAlways, PullIfMissing, PullNever:
	default:
		return errors.New("--pull must be always, if-missing, or never")
	}
	switch opts.AuthMode {
	case AuthAuto, AuthAccount, AuthAPIKey:
	default:
		return errors.New("--auth-mode must be auto, account, or api-key")
	}
	switch normalizeExecutionMode(opts.ExecutionMode) {
	case "sandboxed", "host":
	default:
		return errors.New("--execution-mode must be sandboxed or host")
	}
	if normalizeExecutionMode(opts.ExecutionMode) == "sandboxed" {
		switch normalizeSandboxMode(opts.SandboxMode) {
		case "read-only", "workspace-write", "danger-full-access":
		default:
			return errors.New("--ai-sandbox must be read-only, workspace-write, or danger-full-access")
		}
	}
	if err := validateImagePolicy(opts.Image, opts.PullPolicy); err != nil {
		return err
	}
	return nil
}

var digestRefRE = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)

func validateImagePolicy(image string, pullPolicy PullPolicy) error {
	image = strings.TrimSpace(image)
	if image == "" {
		return errors.New("--image cannot be empty")
	}
	if pullPolicy == PullNever {
		return nil
	}
	if !digestRefRE.MatchString(strings.ToLower(image)) {
		return fmt.Errorf("--image must be digest pinned (name@sha256:...) when --pull is %q", pullPolicy)
	}
	return nil
}

func resolveOutDir(raw string, now time.Time) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		outAbs, err := filepath.Abs(raw)
		if err != nil {
			return "", fmt.Errorf("resolve output path: %w", err)
		}
		return outAbs, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	return filepath.Join(cwd, ".governor", "runs", now.UTC().Format("20060102-150405")), nil
}

func resolveRuntime(pref Runtime) (string, error) {
	return resolveRuntimeWithLookPath(pref, exec.LookPath)
}

func resolveRuntimeWithLookPath(pref Runtime, lookPath func(string) (string, error)) (string, error) {
	switch pref {
	case RuntimeDocker:
		_, err := lookPath("docker")
		if err != nil {
			return "", fmt.Errorf("docker runtime not found in PATH")
		}
		return "docker", nil
	case RuntimePodman:
		_, err := lookPath("podman")
		if err != nil {
			return "", fmt.Errorf("podman runtime not found in PATH")
		}
		return "podman", nil
	case RuntimeAuto:
		if _, err := lookPath("docker"); err == nil {
			return "docker", nil
		}
		if _, err := lookPath("podman"); err == nil {
			return "podman", nil
		}
		return "", fmt.Errorf("no container runtime found; install docker or podman")
	default:
		return "", fmt.Errorf("unsupported runtime %q", pref)
	}
}

func ensureImage(ctx context.Context, runtimeBin string, image string, policy PullPolicy) error {
	switch policy {
	case PullNever:
		if !hasImage(ctx, runtimeBin, image) {
			return fmt.Errorf("runner image %s not found locally and --pull=never is set", image)
		}
		return nil
	case PullAlways:
		return pullImage(ctx, runtimeBin, image)
	case PullIfMissing:
		if hasImage(ctx, runtimeBin, image) {
			return nil
		}
		return pullImage(ctx, runtimeBin, image)
	default:
		return fmt.Errorf("unsupported pull policy %q", policy)
	}
}

func hasImage(ctx context.Context, runtimeBin string, image string) bool {
	cmd := exec.CommandContext(ctx, runtimeBin, "image", "inspect", image)
	return cmd.Run() == nil
}

func pullImage(ctx context.Context, runtimeBin string, image string) error {
	cmd := exec.CommandContext(ctx, runtimeBin, "pull", image)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pull image %s: %w", image, err)
	}
	return nil
}

func removeImage(ctx context.Context, runtimeBin string, image string) error {
	cmd := exec.CommandContext(ctx, runtimeBin, "image", "rm", image)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func resolveAuthMode(mode AuthMode, runtimeCfg ai.Runtime, aiHomeRaw string, env map[string]string) (AuthMode, error) {
	switch mode {
	case AuthAccount:
		if !runtimeCfg.UsesCLI() {
			return "", fmt.Errorf("account auth is only supported for provider %q", ai.ProviderCodexCLI)
		}
		aiHome, err := resolveAIHome(aiHomeRaw)
		if err != nil {
			return "", err
		}
		if !hasAccountAuth(aiHome) {
			return "", fmt.Errorf("account auth selected but %s/auth.json not found", aiHome)
		}
		return AuthAccount, nil
	case AuthAPIKey:
		if !hasAPIKeyAuth(runtimeCfg, env) {
			return "", fmt.Errorf("api-key auth selected but %s is not set", strings.TrimSpace(runtimeCfg.APIKeyEnv))
		}
		return AuthAPIKey, nil
	case AuthAuto:
		if runtimeCfg.UsesCLI() {
			aiHome, err := resolveAIHome(aiHomeRaw)
			if err != nil {
				return "", err
			}
			if hasAccountAuth(aiHome) {
				return AuthAccount, nil
			}
		}
		if hasAPIKeyAuth(runtimeCfg, env) {
			return AuthAPIKey, nil
		}
		if runtimeCfg.UsesOpenAICompatibleAPI() && isLikelyLocalBaseURL(runtimeCfg.BaseURL) {
			return AuthAuto, nil
		}
		if runtimeCfg.UsesCLI() {
			return "", fmt.Errorf("no auth available for isolated run; run codex login or set API key env")
		}
		return "", fmt.Errorf("no auth available for isolated run; set %s or configure local openai-compatible endpoint", runtimeCfg.APIKeyEnv)
	default:
		return "", fmt.Errorf("unsupported auth mode %q", mode)
	}
}

func hasAccountAuth(aiHome string) bool {
	path := filepath.Join(aiHome, "auth.json")
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() && info.Size() > 0
}

func hasAPIKeyAuth(runtimeCfg ai.Runtime, env map[string]string) bool {
	if key := strings.TrimSpace(runtimeCfg.APIKeyEnv); key != "" {
		if strings.TrimSpace(env[key]) != "" {
			return true
		}
	}
	for _, key := range []string{"AI_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "CODEX_API_KEY"} {
		if strings.TrimSpace(env[key]) != "" {
			return true
		}
	}
	return false
}

func resolveAIHome(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultAIHome
	}
	if strings.HasPrefix(raw, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		switch raw {
		case "~":
			raw = home
		case "~/":
			raw = home + string(os.PathSeparator)
		default:
			raw = filepath.Join(home, strings.TrimPrefix(raw, "~/"))
		}
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("resolve ai home: %w", err)
	}
	return abs, nil
}

func stageAccountBundle(aiHome string, seedDir string) (string, error) {
	if err := os.MkdirAll(seedDir, 0o700); err != nil {
		return "", fmt.Errorf("create ai seed dir: %w", err)
	}

	required := []string{"auth.json"}
	for _, name := range required {
		src := filepath.Join(aiHome, name)
		if err := copyRegularFileNoSymlink(src, filepath.Join(seedDir, name)); err != nil {
			return "", fmt.Errorf("stage ai auth file %s: %w", name, err)
		}
	}
	return seedDir, nil
}

func isLikelyLocalBaseURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	return strings.Contains(raw, "127.0.0.1") || strings.Contains(raw, "localhost")
}

// Backward compatibility wrappers.
func resolveCodexHome(raw string) (string, error) { return resolveAIHome(raw) }
func stageSubscriptionBundle(codexHome string, seedDir string) (string, error) {
	return stageAccountBundle(codexHome, seedDir)
}
func hasSubscriptionAuth(codexHome string) bool { return hasAccountAuth(codexHome) }

func copyRegularFileNoSymlink(src string, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink source not allowed")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source must be a regular file")
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func buildContainerEnv(hostEnv map[string]string, runtimeCfg ai.Runtime, authMode AuthMode, aiRequired bool) []string {
	keys := []string{
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "no_proxy",
	}
	if aiRequired && authMode == AuthAPIKey {
		if strings.TrimSpace(runtimeCfg.APIKeyEnv) != "" {
			keys = append(keys, strings.TrimSpace(runtimeCfg.APIKeyEnv))
		}
		keys = append(keys,
			"AI_API_KEY",
			"AI_BASE_URL",
			"AI_MODEL",
			"AI_PROVIDER",
			"AI_PROFILE",
			"OPENAI_API_KEY",
			"OPENAI_BASE_URL",
			"OPENAI_ORG_ID",
			"OPENAI_PROJECT",
			"AZURE_OPENAI_API_KEY",
			"AZURE_OPENAI_ENDPOINT",
			"AZURE_OPENAI_API_VERSION",
			"ANTHROPIC_API_KEY",
			"OPENROUTER_API_KEY",
			"MISTRAL_API_KEY",
			"DEEPSEEK_API_KEY",
			"MINIMAX_API_KEY",
			"XAI_API_KEY",
			"PERPLEXITY_API_KEY",
			"CHATGLM_API_KEY",
			"HUGGINGFACEHUB_API_TOKEN",
			"HF_TOKEN",
			"CODEX_API_KEY",
			"CODEX_BASE_URL",
			"CODEX_PROFILE",
		)
	}

	out := make([]string, 0, len(keys)+10)
	added := map[string]struct{}{}
	for _, key := range keys {
		val := strings.TrimSpace(hostEnv[key])
		if val == "" {
			continue
		}
		if _, ok := added[key]; ok {
			continue
		}
		added[key] = struct{}{}
		out = append(out, key+"="+val)
	}

	// Force fixed in-container paths to avoid host PATH poisoning.
	out = append(out,
		"PATH="+defaultPathInImage,
		"HOME=/home/governor",
	)
	if strings.TrimSpace(runtimeCfg.Profile) != "" {
		out = append(out, "AI_PROFILE="+strings.TrimSpace(runtimeCfg.Profile))
	}
	if strings.TrimSpace(runtimeCfg.Provider) != "" {
		out = append(out, "AI_PROVIDER="+strings.TrimSpace(runtimeCfg.Provider))
	}
	if strings.TrimSpace(runtimeCfg.Model) != "" {
		out = append(out, "AI_MODEL="+strings.TrimSpace(runtimeCfg.Model))
	}
	if strings.TrimSpace(runtimeCfg.BaseURL) != "" {
		out = append(out, "AI_BASE_URL="+strings.TrimSpace(runtimeCfg.BaseURL))
	}
	if runtimeCfg.UsesCLI() {
		out = append(out, "AI_HOME=/ai-home", "CODEX_HOME=/ai-home")
	}
	sort.Strings(out)
	return out
}

func envNames(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, kv := range in {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		key := kv[:idx]
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func mergeEnv(base []string, overrides []string) []string {
	m := envToMap(base)
	for _, kv := range overrides {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		m[kv[:idx]] = kv[idx+1:]
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

func buildInnerGovernorArgs(opts AuditOptions, hasChecksMount bool) []string {
	executionMode := normalizeExecutionMode(opts.ExecutionMode)
	if executionMode == "" {
		executionMode = defaultExecMode
	}
	args := []string{
		"audit",
		"/input",
		"--out", "/output",
		"--no-tui",
		"--allow-existing-out-dir",
		"--execution-mode", executionMode,
		"--workers", fmt.Sprintf("%d", opts.Workers),
		"--max-files", fmt.Sprintf("%d", opts.MaxFiles),
		"--max-bytes", fmt.Sprintf("%d", opts.MaxBytes),
		"--timeout", opts.Timeout.String(),
	}
	if strings.TrimSpace(opts.AIRuntime.Profile) != "" {
		args = append(args, "--ai-profile", strings.TrimSpace(opts.AIRuntime.Profile))
	}
	if strings.TrimSpace(opts.AIRuntime.Provider) != "" {
		args = append(args, "--ai-provider", strings.TrimSpace(opts.AIRuntime.Provider))
	}
	if strings.TrimSpace(opts.AIRuntime.Model) != "" {
		args = append(args, "--ai-model", strings.TrimSpace(opts.AIRuntime.Model))
	}
	if strings.TrimSpace(opts.AIRuntime.AuthMode) != "" {
		args = append(args, "--ai-auth-mode", strings.TrimSpace(opts.AIRuntime.AuthMode))
	}
	if strings.TrimSpace(opts.AIRuntime.BaseURL) != "" {
		args = append(args, "--ai-base-url", strings.TrimSpace(opts.AIRuntime.BaseURL))
	}
	if strings.TrimSpace(opts.AIRuntime.APIKeyEnv) != "" {
		args = append(args, "--ai-api-key-env", strings.TrimSpace(opts.AIRuntime.APIKeyEnv))
	}
	if opts.AIRuntime.UsesCLI() {
		bin := strings.TrimSpace(opts.AIRuntime.Bin)
		if bin == "" {
			bin = "codex"
		} else {
			bin = filepath.Base(bin)
		}
		args = append(args, "--ai-bin", bin)
	}
	if executionMode == "sandboxed" {
		sandboxMode := normalizeSandboxMode(opts.SandboxMode)
		if sandboxMode == "" {
			sandboxMode = defaultSandboxMode
		}
		args = append(args, "--ai-sandbox", sandboxMode, "--sandbox-deny-host-fallback")
	}
	if opts.Verbose {
		args = append(args, "--verbose")
	}
	if opts.NoCustomChecks {
		args = append(args, "--no-custom-checks")
	}
	if opts.KeepWorkspaceOnError {
		args = append(args, "--keep-workspace-error")
	}
	if opts.IncludeTestFiles {
		args = append(args, "--include-test-files")
	}
	if hasChecksMount {
		args = append(args, "--checks-dir", "/checks")
	}
	for _, id := range opts.OnlyChecks {
		id = strings.TrimSpace(id)
		if id != "" {
			args = append(args, "--only-check", id)
		}
	}
	for _, id := range opts.SkipChecks {
		id = strings.TrimSpace(id)
		if id != "" {
			args = append(args, "--skip-check", id)
		}
	}
	return args
}

func buildContainerRunArgs(opts AuditOptions, inputAbs string, outAbs string, checksAbs string, seedDir string, envVars []string, governorArgs []string) []string {
	args := []string{"run", "--rm"}
	args = append(args,
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--pids-limit", "256",
		"--memory", "2g",
		"--cpus", "1",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
		"--tmpfs", "/home/governor:rw,noexec,nosuid,nodev,size=256m,uid=65532,gid=65532,mode=700",
		"--tmpfs", "/work:rw,noexec,nosuid,nodev,size=128m,uid=65532,gid=65532,mode=700",
		"--tmpfs", "/ai-home:rw,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=700",
		"--entrypoint", "sh",
		"-w", "/work",
		"-v", fmt.Sprintf("%s:/input:ro", inputAbs),
		"-v", fmt.Sprintf("%s:/output:rw", outAbs),
	)
	if checksAbs != "" {
		args = append(args, "-v", fmt.Sprintf("%s:/checks:ro", checksAbs))
	}
	if seedDir != "" {
		args = append(args, "-v", fmt.Sprintf("%s:/ai-seed:ro", seedDir))
	}
	if opts.NetworkPolicy == NetworkNone {
		args = append(args, "--network", "none")
	}
	for _, key := range envVars {
		args = append(args, "-e", key)
	}

	args = append(args, opts.Image, "-lc", buildEntrypointScript(governorArgs, seedDir != ""))
	return args
}

func buildEntrypointScript(governorArgs []string, hasSeed bool) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	if hasSeed {
		b.WriteString("if [ -d /ai-seed ]; then cp -R /ai-seed/. /ai-home/; chmod -R go-rwx /ai-home || true; fi\n")
	}
	b.WriteString("exec ")
	b.WriteString(shellJoin(append([]string{"governor"}, governorArgs...)))
	b.WriteString("\n")
	return b.String()
}

func shellJoin(parts []string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, shellQuote(p))
	}
	return strings.Join(out, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func envToMap(in []string) map[string]string {
	out := make(map[string]string, len(in))
	for _, kv := range in {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		out[kv[:idx]] = kv[idx+1:]
	}
	return out
}

func normalizeExecutionMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "sandboxed":
		return "sandboxed"
	case "host":
		return "host"
	default:
		return ""
	}
}

func normalizeSandboxMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
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

func isolateSelectionRequiresAI(opts AuditOptions) (bool, []string, error) {
	builtinDefs := checks.Builtins()
	customDefs := []checks.Definition{}
	warnings := make([]string, 0, 4)

	if !opts.NoCustomChecks && strings.TrimSpace(opts.ChecksDir) != "" {
		dirs, err := checks.ResolveReadDirs(opts.ChecksDir)
		if err != nil {
			return false, nil, err
		}
		loaded, loadWarnings, err := checks.LoadCustomDirs(dirs)
		if err != nil {
			return false, nil, err
		}
		customDefs = loaded
		warnings = append(warnings, loadWarnings...)
	}

	selection, err := checks.BuildSelection(builtinDefs, customDefs, checks.SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   !opts.NoCustomChecks && strings.TrimSpace(opts.ChecksDir) != "",
		OnlyIDs:         opts.OnlyChecks,
		SkipIDs:         opts.SkipChecks,
	})
	if err != nil {
		return false, nil, err
	}
	warnings = append(warnings, selection.Warnings...)
	return checks.SelectionRequiresAI(selection.Checks), warnings, nil
}
