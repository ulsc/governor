package matrix

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const APIVersion = "governor/matrix/v1"

type Config struct {
	APIVersion  string        `yaml:"api_version" json:"api_version"`
	Defaults    TargetOptions `yaml:"defaults" json:"defaults"`
	Targets     []Target      `yaml:"targets" json:"targets"`
	Aggregation Aggregation   `yaml:"aggregation" json:"aggregation"`
}

type TargetOptions struct {
	FailOn           string   `yaml:"fail_on,omitempty" json:"fail_on,omitempty"`
	Policy           string   `yaml:"policy,omitempty" json:"policy,omitempty"`
	RequirePolicy    *bool    `yaml:"require_policy,omitempty" json:"require_policy,omitempty"`
	Baseline         string   `yaml:"baseline,omitempty" json:"baseline,omitempty"`
	ChecksDir        string   `yaml:"checks_dir,omitempty" json:"checks_dir,omitempty"`
	NoCustomChecks   *bool    `yaml:"no_custom_checks,omitempty" json:"no_custom_checks,omitempty"`
	Quick            *bool    `yaml:"quick,omitempty" json:"quick,omitempty"`
	OnlyChecks       []string `yaml:"only_checks,omitempty" json:"only_checks,omitempty"`
	SkipChecks       []string `yaml:"skip_checks,omitempty" json:"skip_checks,omitempty"`
	Suppressions     string   `yaml:"suppressions,omitempty" json:"suppressions,omitempty"`
	Workers          *int     `yaml:"workers,omitempty" json:"workers,omitempty"`
	AIProfile        string   `yaml:"ai_profile,omitempty" json:"ai_profile,omitempty"`
	IncludeTestFiles *bool    `yaml:"include_test_files,omitempty" json:"include_test_files,omitempty"`
}

type Target struct {
	Name          string `yaml:"name" json:"name"`
	Path          string `yaml:"path" json:"path"`
	TargetOptions `yaml:",inline" json:",inline"`
}

type Aggregation struct {
	FailFast          bool   `yaml:"fail_fast" json:"fail_fast"`
	OverallFailOn     string `yaml:"overall_fail_on,omitempty" json:"overall_fail_on,omitempty"`
	RequireAllTargets *bool  `yaml:"require_all_targets,omitempty" json:"require_all_targets,omitempty"`
}

func DefaultPath() string {
	return filepath.Join(".governor", "matrix.yaml")
}

func Load(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultPath()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read matrix config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse matrix config: %w", err)
	}
	cfg = Normalize(cfg)
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Normalize(cfg Config) Config {
	cfg.APIVersion = strings.TrimSpace(cfg.APIVersion)
	if cfg.APIVersion == "" {
		cfg.APIVersion = APIVersion
	}
	cfg.Defaults = normalizeTargetOptions(cfg.Defaults)
	cfg.Aggregation.OverallFailOn = strings.ToLower(strings.TrimSpace(cfg.Aggregation.OverallFailOn))
	if cfg.Aggregation.OverallFailOn == "" {
		cfg.Aggregation.OverallFailOn = "none"
	}
	if cfg.Aggregation.RequireAllTargets == nil {
		value := true
		cfg.Aggregation.RequireAllTargets = &value
	}
	for i := range cfg.Targets {
		cfg.Targets[i].Name = strings.TrimSpace(cfg.Targets[i].Name)
		cfg.Targets[i].Path = strings.TrimSpace(cfg.Targets[i].Path)
		cfg.Targets[i].TargetOptions = normalizeTargetOptions(cfg.Targets[i].TargetOptions)
	}
	return cfg
}

func Validate(cfg Config) error {
	if cfg.APIVersion != APIVersion {
		return fmt.Errorf("unsupported matrix api_version %q", cfg.APIVersion)
	}
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("matrix targets are required")
	}
	seen := map[string]struct{}{}
	for i, target := range cfg.Targets {
		if target.Name == "" {
			return fmt.Errorf("targets[%d].name is required", i)
		}
		if target.Path == "" {
			return fmt.Errorf("targets[%d].path is required", i)
		}
		key := strings.ToLower(target.Name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate target name %q", target.Name)
		}
		seen[key] = struct{}{}
	}
	if !isSeverityOrNone(cfg.Aggregation.OverallFailOn) {
		return fmt.Errorf("aggregation.overall_fail_on must be critical|high|medium|low|info|none")
	}
	return nil
}

func MergeOptions(defaults TargetOptions, override TargetOptions) TargetOptions {
	out := defaults
	if strings.TrimSpace(override.FailOn) != "" {
		out.FailOn = override.FailOn
	}
	if strings.TrimSpace(override.Policy) != "" {
		out.Policy = override.Policy
	}
	if override.RequirePolicy != nil {
		out.RequirePolicy = override.RequirePolicy
	}
	if strings.TrimSpace(override.Baseline) != "" {
		out.Baseline = override.Baseline
	}
	if strings.TrimSpace(override.ChecksDir) != "" {
		out.ChecksDir = override.ChecksDir
	}
	if override.NoCustomChecks != nil {
		out.NoCustomChecks = override.NoCustomChecks
	}
	if override.Quick != nil {
		out.Quick = override.Quick
	}
	if len(override.OnlyChecks) > 0 {
		out.OnlyChecks = append([]string{}, override.OnlyChecks...)
	}
	if len(override.SkipChecks) > 0 {
		out.SkipChecks = append([]string{}, override.SkipChecks...)
	}
	if strings.TrimSpace(override.Suppressions) != "" {
		out.Suppressions = override.Suppressions
	}
	if override.Workers != nil {
		out.Workers = override.Workers
	}
	if strings.TrimSpace(override.AIProfile) != "" {
		out.AIProfile = override.AIProfile
	}
	if override.IncludeTestFiles != nil {
		out.IncludeTestFiles = override.IncludeTestFiles
	}
	return out
}

func normalizeTargetOptions(in TargetOptions) TargetOptions {
	in.FailOn = strings.ToLower(strings.TrimSpace(in.FailOn))
	if in.FailOn == "" {
		in.FailOn = "none"
	}
	in.Policy = strings.TrimSpace(in.Policy)
	in.Baseline = strings.TrimSpace(in.Baseline)
	in.ChecksDir = strings.TrimSpace(in.ChecksDir)
	in.OnlyChecks = unique(in.OnlyChecks)
	in.SkipChecks = unique(in.SkipChecks)
	in.Suppressions = strings.TrimSpace(in.Suppressions)
	in.AIProfile = strings.TrimSpace(in.AIProfile)
	return in
}

func unique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func isSeverityOrNone(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "none", "critical", "high", "medium", "low", "info":
		return true
	default:
		return false
	}
}
