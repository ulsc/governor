package isolation

import (
	"context"
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

	"governor/internal/safefile"
)

const (
	DefaultImage       = "governor-runner:local"
	defaultCodexHome   = "~/.codex"
	defaultWorkers     = 3
	defaultMaxFiles    = 20000
	defaultMaxBytes    = 250 * 1024 * 1024
	defaultTimeout     = 4 * time.Minute
	defaultPathInImage = "/usr/bin:/bin:/usr/sbin:/sbin"
	defaultExecMode    = "sandboxed"
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
	AuthSubscription AuthMode = "subscription"
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
	authMode, err := resolveAuthMode(opts.AuthMode, opts.CodexHome, hostEnv)
	if err != nil {
		return err
	}

	tmpRoot, err := os.MkdirTemp("", "governor-isolate-*")
	if err != nil {
		return fmt.Errorf("create isolate temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpRoot) }()

	var seedDir string
	if authMode == AuthSubscription {
		codexHome, err := resolveCodexHome(opts.CodexHome)
		if err != nil {
			return err
		}
		seedDir, err = stageSubscriptionBundle(codexHome, filepath.Join(tmpRoot, "codex-seed"))
		if err != nil {
			return err
		}
	}

	containerEnv := buildContainerEnv(hostEnv, authMode)
	govArgs := buildInnerGovernorArgs(opts, checksAbs != "")
	runArgs := buildContainerRunArgs(opts, inputAbs, outAbs, checksAbs, seedDir, envNames(containerEnv), govArgs)

	cmd := exec.CommandContext(ctx, runtimeBin, runArgs...)
	cmd.Env = mergeEnv(os.Environ(), containerEnv)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("isolated audit failed: %w", err)
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
		opts.AuthMode = AuthSubscription
	}
	if strings.TrimSpace(opts.CodexHome) == "" {
		opts.CodexHome = defaultCodexHome
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
	if strings.TrimSpace(opts.SandboxMode) == "" && normalizeExecutionMode(opts.ExecutionMode) == defaultExecMode {
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
	case AuthAuto, AuthSubscription, AuthAPIKey:
	default:
		return errors.New("--auth-mode must be auto, subscription, or api-key")
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
			return errors.New("--codex-sandbox must be read-only, workspace-write, or danger-full-access")
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

func resolveAuthMode(mode AuthMode, codexHomeRaw string, env map[string]string) (AuthMode, error) {
	switch mode {
	case AuthSubscription:
		codexHome, err := resolveCodexHome(codexHomeRaw)
		if err != nil {
			return "", err
		}
		if !hasSubscriptionAuth(codexHome) {
			return "", fmt.Errorf("subscription auth selected but %s/auth.json not found", codexHome)
		}
		return AuthSubscription, nil
	case AuthAPIKey:
		if !hasAPIKeyAuth(env) {
			return "", fmt.Errorf("api-key auth selected but no API key env found")
		}
		return AuthAPIKey, nil
	case AuthAuto:
		codexHome, err := resolveCodexHome(codexHomeRaw)
		if err != nil {
			return "", err
		}
		if hasSubscriptionAuth(codexHome) {
			return AuthSubscription, nil
		}
		if hasAPIKeyAuth(env) {
			return AuthAPIKey, nil
		}
		return "", fmt.Errorf("no auth available for isolated run; run codex login or set API key env")
	default:
		return "", fmt.Errorf("unsupported auth mode %q", mode)
	}
}

func hasSubscriptionAuth(codexHome string) bool {
	path := filepath.Join(codexHome, "auth.json")
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() && info.Size() > 0
}

func hasAPIKeyAuth(env map[string]string) bool {
	for _, key := range []string{"OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "CODEX_API_KEY"} {
		if strings.TrimSpace(env[key]) != "" {
			return true
		}
	}
	return false
}

func resolveCodexHome(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultCodexHome
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
		return "", fmt.Errorf("resolve codex home: %w", err)
	}
	return abs, nil
}

func stageSubscriptionBundle(codexHome string, seedDir string) (string, error) {
	if err := os.MkdirAll(seedDir, 0o700); err != nil {
		return "", fmt.Errorf("create codex seed dir: %w", err)
	}

	required := []string{"auth.json"}
	for _, name := range required {
		src := filepath.Join(codexHome, name)
		if err := copyRegularFileNoSymlink(src, filepath.Join(seedDir, name)); err != nil {
			return "", fmt.Errorf("stage codex auth file %s: %w", name, err)
		}
	}
	return seedDir, nil
}

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

func buildContainerEnv(hostEnv map[string]string, authMode AuthMode) []string {
	keys := []string{
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "no_proxy",
	}
	if authMode == AuthAPIKey {
		keys = append(keys,
			"OPENAI_API_KEY",
			"OPENAI_BASE_URL",
			"OPENAI_ORG_ID",
			"OPENAI_PROJECT",
			"AZURE_OPENAI_API_KEY",
			"AZURE_OPENAI_ENDPOINT",
			"AZURE_OPENAI_API_VERSION",
			"CODEX_API_KEY",
			"CODEX_BASE_URL",
			"CODEX_PROFILE",
		)
	}

	out := make([]string, 0, len(keys)+4)
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
		"CODEX_HOME=/codex-home",
	)
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
	if executionMode == "sandboxed" {
		sandboxMode := normalizeSandboxMode(opts.SandboxMode)
		if sandboxMode == "" {
			sandboxMode = defaultSandboxMode
		}
		args = append(args, "--codex-sandbox", sandboxMode)
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
		"--tmpfs", "/codex-home:rw,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=700",
		"--entrypoint", "sh",
		"-w", "/work",
		"-v", fmt.Sprintf("%s:/input:ro", inputAbs),
		"-v", fmt.Sprintf("%s:/output:rw", outAbs),
	)
	if checksAbs != "" {
		args = append(args, "-v", fmt.Sprintf("%s:/checks:ro", checksAbs))
	}
	if seedDir != "" {
		args = append(args, "-v", fmt.Sprintf("%s:/codex-seed:ro", seedDir))
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
		b.WriteString("if [ -d /codex-seed ]; then cp -R /codex-seed/. /codex-home/; chmod -R go-rwx /codex-home || true; fi\n")
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
