package matrix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndMerge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "matrix.yaml")
	content := `api_version: governor/matrix/v1
defaults:
  fail_on: high
  ai_profile: openai
targets:
  - name: api
    path: ./services/api
  - name: web
    path: ./apps/web
    fail_on: medium
aggregation:
  fail_fast: true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write matrix: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load matrix: %v", err)
	}
	if len(cfg.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(cfg.Targets))
	}
	merged := MergeOptions(cfg.Defaults, cfg.Targets[1].TargetOptions)
	if merged.FailOn != "medium" {
		t.Fatalf("expected override fail_on medium, got %s", merged.FailOn)
	}
	if merged.AIProfile != "openai" {
		t.Fatalf("expected inherited ai_profile openai, got %s", merged.AIProfile)
	}
}

func TestValidateRejectsDuplicateTargetNames(t *testing.T) {
	cfg := Normalize(Config{
		APIVersion: APIVersion,
		Targets: []Target{
			{Name: "api", Path: "./api"},
			{Name: "API", Path: "./other"},
		},
	})
	if err := Validate(cfg); err == nil {
		t.Fatal("expected duplicate target validation error")
	}
}
