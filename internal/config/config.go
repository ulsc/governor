package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config mirrors the common audit/isolate flag names. Zero values mean "not set".
type Config struct {
	Workers       *int    `yaml:"workers,omitempty"`
	AIProfile     string  `yaml:"ai_profile,omitempty"`
	AIProvider    string  `yaml:"ai_provider,omitempty"`
	AIModel       string  `yaml:"ai_model,omitempty"`
	AIAuthMode    string  `yaml:"ai_auth_mode,omitempty"`
	AIBin         string  `yaml:"ai_bin,omitempty"`
	AIBaseURL     string  `yaml:"ai_base_url,omitempty"`
	AIAPIKeyEnv   string  `yaml:"ai_api_key_env,omitempty"`
	ExecutionMode string  `yaml:"execution_mode,omitempty"`
	AISandbox     string  `yaml:"ai_sandbox,omitempty"`
	MaxFiles      *int    `yaml:"max_files,omitempty"`
	MaxBytes      *int64  `yaml:"max_bytes,omitempty"`
	Timeout       string  `yaml:"timeout,omitempty"`
	Verbose       *bool   `yaml:"verbose,omitempty"`
	ChecksDir     string  `yaml:"checks_dir,omitempty"`
	NoCustom      *bool   `yaml:"no_custom_checks,omitempty"`
	FailOn        string  `yaml:"fail_on,omitempty"`
	Baseline      string  `yaml:"baseline,omitempty"`
}

// Load reads config from layered sources:
//  1. ~/.governor/config.yaml (global)
//  2. ./.governor/config.yaml (repo-local, takes precedence)
//
// Missing files are silently ignored. Returns zero Config if neither exists.
func Load() (Config, error) {
	home, _ := os.UserHomeDir()
	var globalPath, localPath string
	if home != "" {
		globalPath = filepath.Join(home, ".governor", "config.yaml")
	}

	cwd, _ := os.Getwd()
	if cwd != "" {
		localPath = filepath.Join(cwd, ".governor", "config.yaml")
	}

	var merged Config

	if globalPath != "" {
		global, err := loadFile(globalPath)
		if err != nil {
			return Config{}, fmt.Errorf("load global config %s: %w", globalPath, err)
		}
		merged = merge(merged, global)
	}

	if localPath != "" {
		local, err := loadFile(localPath)
		if err != nil {
			return Config{}, fmt.Errorf("load local config %s: %w", localPath, err)
		}
		merged = merge(merged, local)
	}

	return merged, nil
}

func loadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, err
	}
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return Config{}, nil
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// merge applies overrides from b onto a. Non-zero fields in b win.
func merge(a, b Config) Config {
	if b.Workers != nil {
		a.Workers = b.Workers
	}
	if b.AIProfile != "" {
		a.AIProfile = b.AIProfile
	}
	if b.AIProvider != "" {
		a.AIProvider = b.AIProvider
	}
	if b.AIModel != "" {
		a.AIModel = b.AIModel
	}
	if b.AIAuthMode != "" {
		a.AIAuthMode = b.AIAuthMode
	}
	if b.AIBin != "" {
		a.AIBin = b.AIBin
	}
	if b.AIBaseURL != "" {
		a.AIBaseURL = b.AIBaseURL
	}
	if b.AIAPIKeyEnv != "" {
		a.AIAPIKeyEnv = b.AIAPIKeyEnv
	}
	if b.ExecutionMode != "" {
		a.ExecutionMode = b.ExecutionMode
	}
	if b.AISandbox != "" {
		a.AISandbox = b.AISandbox
	}
	if b.MaxFiles != nil {
		a.MaxFiles = b.MaxFiles
	}
	if b.MaxBytes != nil {
		a.MaxBytes = b.MaxBytes
	}
	if b.Timeout != "" {
		a.Timeout = b.Timeout
	}
	if b.Verbose != nil {
		a.Verbose = b.Verbose
	}
	if b.ChecksDir != "" {
		a.ChecksDir = b.ChecksDir
	}
	if b.NoCustom != nil {
		a.NoCustom = b.NoCustom
	}
	if b.FailOn != "" {
		a.FailOn = b.FailOn
	}
	if b.Baseline != "" {
		a.Baseline = b.Baseline
	}
	return a
}
