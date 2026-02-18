package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"governor/internal/ai"
	"governor/internal/checks"
	"governor/internal/config"
	"governor/internal/trust"
)

type Options struct {
	CWD string
}

func BuildReport(ctx context.Context, opts Options) Report {
	report := Report{Checks: make([]CheckResult, 0, 8)}
	add := func(res CheckResult) {
		report.Checks = append(report.Checks, res)
		switch res.Status {
		case StatusFail:
			report.Summary.Fail++
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %s", res.ID, res.Message))
		case StatusWarn:
			report.Summary.Warning++
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s: %s", res.ID, res.Message))
		default:
			report.Summary.Pass++
		}
	}

	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		add(CheckResult{
			ID:      "config.load",
			Status:  StatusFail,
			Message: fmt.Sprintf("failed to load config: %v", cfgErr),
		})
	} else {
		meta := map[string]string{}
		if cwd, err := resolveCWD(opts.CWD); err == nil {
			home, _ := os.UserHomeDir()
			globalPath := filepath.Join(home, ".governor", "config.yaml")
			localPath := filepath.Join(cwd, ".governor", "config.yaml")
			meta["global_config"] = fileState(globalPath)
			meta["local_config"] = fileState(localPath)
		}
		add(CheckResult{
			ID:       "config.load",
			Status:   StatusPass,
			Message:  "configuration loaded",
			Metadata: meta,
		})
	}

	profileName := strings.TrimSpace(cfg.AIProfile)
	if profileName == "" {
		profileName = "codex"
	}
	runtimeOpts := ai.ResolveOptions{
		Profile:       profileName,
		Provider:      strings.TrimSpace(cfg.AIProvider),
		Model:         strings.TrimSpace(cfg.AIModel),
		AuthMode:      strings.TrimSpace(cfg.AIAuthMode),
		Bin:           strings.TrimSpace(cfg.AIBin),
		BaseURL:       strings.TrimSpace(cfg.AIBaseURL),
		APIKeyEnv:     strings.TrimSpace(cfg.AIAPIKeyEnv),
		ExecutionMode: strings.TrimSpace(cfg.ExecutionMode),
		SandboxMode:   strings.TrimSpace(cfg.AISandbox),
	}
	rt, rtErr := ai.ResolveRuntime(runtimeOpts)
	if rtErr != nil {
		add(CheckResult{
			ID:      "ai.runtime",
			Status:  StatusFail,
			Message: fmt.Sprintf("failed to resolve ai runtime: %v", rtErr),
			Metadata: map[string]string{
				"profile": profileName,
			},
		})
	} else {
		add(CheckResult{
			ID:      "ai.runtime",
			Status:  StatusPass,
			Message: "ai runtime resolved",
			Metadata: map[string]string{
				"profile":   rt.Profile,
				"provider":  rt.Provider,
				"auth_mode": rt.AuthMode,
			},
		})

		add(aiAuthCheck(rt))
		add(aiBinaryCheck(ctx, rt))
	}

	add(checksDoctorCheck(strings.TrimSpace(cfg.ChecksDir)))
	add(containerRuntimeCheck())
	add(governorDirWritableCheck(opts.CWD))

	return report
}

func aiAuthCheck(rt ai.Runtime) CheckResult {
	if rt.AuthMode == ai.AuthAPIKey {
		keyName := strings.TrimSpace(rt.APIKeyEnv)
		if keyName == "" {
			return CheckResult{ID: "ai.auth", Status: StatusFail, Message: "api-key auth selected but api key env is empty"}
		}
		if strings.TrimSpace(os.Getenv(keyName)) == "" {
			return CheckResult{
				ID:      "ai.auth",
				Status:  StatusFail,
				Message: fmt.Sprintf("api-key auth selected but %s is not set", keyName),
				Metadata: map[string]string{
					"api_key_env": keyName,
				},
			}
		}
		return CheckResult{
			ID:      "ai.auth",
			Status:  StatusPass,
			Message: fmt.Sprintf("api-key auth configured via %s", keyName),
			Metadata: map[string]string{
				"api_key_env": keyName,
			},
		}
	}

	if rt.UsesCLI() {
		homePath, err := expandHome(strings.TrimSpace(rt.AccountHome))
		if err != nil {
			return CheckResult{ID: "ai.auth", Status: StatusWarn, Message: fmt.Sprintf("unable to resolve account home: %v", err)}
		}
		authFile := filepath.Join(homePath, "auth.json")
		if _, err := os.Stat(authFile); err == nil {
			return CheckResult{
				ID:      "ai.auth",
				Status:  StatusPass,
				Message: "account auth file found",
				Metadata: map[string]string{
					"auth_file": authFile,
				},
			}
		}
		keyName := strings.TrimSpace(rt.APIKeyEnv)
		if keyName != "" && strings.TrimSpace(os.Getenv(keyName)) != "" {
			return CheckResult{
				ID:      "ai.auth",
				Status:  StatusPass,
				Message: fmt.Sprintf("api key env %s is set", keyName),
				Metadata: map[string]string{
					"api_key_env": keyName,
				},
			}
		}
		return CheckResult{
			ID:      "ai.auth",
			Status:  StatusWarn,
			Message: "no account auth file or API key found for codex-cli",
		}
	}

	if rt.UsesOpenAICompatibleAPI() {
		if strings.TrimSpace(rt.AuthMode) == ai.AuthAuto {
			keyName := strings.TrimSpace(rt.APIKeyEnv)
			if keyName != "" && strings.TrimSpace(os.Getenv(keyName)) == "" {
				return CheckResult{ID: "ai.auth", Status: StatusWarn, Message: fmt.Sprintf("openai-compatible auth is auto and %s is not set", keyName)}
			}
		}
		return CheckResult{ID: "ai.auth", Status: StatusPass, Message: "openai-compatible auth settings look valid"}
	}

	return CheckResult{ID: "ai.auth", Status: StatusWarn, Message: "unable to validate auth for unknown provider"}
}

func aiBinaryCheck(ctx context.Context, rt ai.Runtime) CheckResult {
	if !rt.UsesCLI() {
		return CheckResult{ID: "ai.binary", Status: StatusPass, Message: "ai binary attestation not required for openai-compatible provider"}
	}

	bin := strings.TrimSpace(rt.Bin)
	if bin == "" {
		bin = "codex"
	}
	resolved, err := trust.ResolveAIBinary(ctx, bin, true)
	if err != nil {
		return CheckResult{
			ID:      "ai.binary",
			Status:  StatusFail,
			Message: fmt.Sprintf("ai binary attestation failed: %v", err),
			Metadata: map[string]string{
				"bin": bin,
			},
		}
	}
	sha := resolved.SHA256
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return CheckResult{
		ID:      "ai.binary",
		Status:  StatusPass,
		Message: "ai binary attested",
		Metadata: map[string]string{
			"requested": resolved.RequestedPath,
			"resolved":  resolved.ResolvedPath,
			"version":   resolved.Version,
			"sha256":    sha,
		},
	}
}

func checksDoctorCheck(checksDir string) CheckResult {
	dirs, err := checks.ResolveReadDirs(checksDir)
	if err != nil {
		return CheckResult{ID: "checks.health", Status: StatusFail, Message: fmt.Sprintf("resolve checks dirs: %v", err)}
	}
	report, err := checks.BuildDoctorReport(dirs)
	if err != nil {
		return CheckResult{ID: "checks.health", Status: StatusFail, Message: fmt.Sprintf("checks doctor failed: %v", err)}
	}
	status := StatusPass
	message := "checks are healthy"
	if report.Summary.Error > 0 {
		status = StatusWarn
		message = fmt.Sprintf("checks include %d errors and %d warnings", report.Summary.Error, report.Summary.Warning)
	} else if report.Summary.Warning > 0 {
		status = StatusWarn
		message = fmt.Sprintf("checks include %d warnings", report.Summary.Warning)
	}
	return CheckResult{
		ID:      "checks.health",
		Status:  status,
		Message: message,
		Metadata: map[string]string{
			"searched_dirs": fmt.Sprintf("%d", len(report.SearchedDirs)),
			"effective":     fmt.Sprintf("%d", len(report.Effective)),
			"shadowed":      fmt.Sprintf("%d", len(report.Shadowed)),
		},
	}
}

func containerRuntimeCheck() CheckResult {
	_, dockerErr := exec.LookPath("docker")
	_, podmanErr := exec.LookPath("podman")

	if dockerErr == nil {
		return CheckResult{ID: "isolation.runtime", Status: StatusPass, Message: "docker runtime found", Metadata: map[string]string{"runtime": "docker"}}
	}
	if podmanErr == nil {
		return CheckResult{ID: "isolation.runtime", Status: StatusPass, Message: "podman runtime found", Metadata: map[string]string{"runtime": "podman"}}
	}
	return CheckResult{ID: "isolation.runtime", Status: StatusWarn, Message: "no container runtime found (docker/podman)"}
}

func governorDirWritableCheck(rawCWD string) CheckResult {
	cwd, err := resolveCWD(rawCWD)
	if err != nil {
		return CheckResult{ID: "workspace.permissions", Status: StatusFail, Message: fmt.Sprintf("resolve cwd: %v", err)}
	}
	govDir := filepath.Join(cwd, ".governor")
	if err := os.MkdirAll(govDir, 0o700); err != nil {
		return CheckResult{ID: "workspace.permissions", Status: StatusFail, Message: fmt.Sprintf("create .governor dir: %v", err)}
	}
	f, err := os.CreateTemp(govDir, ".doctor-write-*")
	if err != nil {
		return CheckResult{ID: "workspace.permissions", Status: StatusFail, Message: fmt.Sprintf("write test in .governor failed: %v", err)}
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return CheckResult{ID: "workspace.permissions", Status: StatusPass, Message: ".governor directory is writable", Metadata: map[string]string{"path": govDir}}
}

func expandHome(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

func resolveCWD(raw string) (string, error) {
	if strings.TrimSpace(raw) != "" {
		return filepath.Abs(raw)
	}
	return os.Getwd()
}

func fileState(path string) string {
	if _, err := os.Stat(path); err == nil {
		return "present"
	}
	return "missing"
}
