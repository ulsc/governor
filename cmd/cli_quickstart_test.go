package cmd

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuickstartCreatesGovDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0o700)

	// Y to init, N to hook, N to AI, N to audit
	input := "y\nn\nn\nn\n"
	var out bytes.Buffer

	err := runQuickstartWithIO(dir, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("quickstart failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".governor", "config.yaml")); err != nil {
		t.Error("expected .governor/config.yaml to be created")
	}
	if _, err := os.Stat(filepath.Join(dir, ".governor", ".gitignore")); err != nil {
		t.Error("expected .governor/.gitignore to be created")
	}
}

func TestQuickstartSkipsInitWhenDeclined(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0o700)

	// N to init, N to hook, N to AI, N to audit
	input := "n\nn\nn\nn\n"
	var out bytes.Buffer

	err := runQuickstartWithIO(dir, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("quickstart failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".governor")); err == nil {
		t.Error("expected .governor NOT to be created when init declined")
	}
}

func TestQuickstartInstallsHook(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git", "hooks"), 0o700)

	// Y to init, Y to hook, N to AI, N to audit
	input := "y\ny\nn\nn\n"
	var out bytes.Buffer

	err := runQuickstartWithIO(dir, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("quickstart failed: %v", err)
	}

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); err != nil {
		t.Error("expected pre-commit hook to be installed")
	}
}

func TestQuickstartNoHookPromptWithoutGit(t *testing.T) {
	dir := t.TempDir()
	// No .git directory

	// Y to init, N to AI, N to audit
	input := "y\nn\nn\n"
	var out bytes.Buffer

	err := runQuickstartWithIO(dir, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("quickstart failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".governor", "config.yaml")); err != nil {
		t.Error("expected .governor/config.yaml to be created")
	}
	// Hook prompt should not have been shown
	if strings.Contains(out.String(), "pre-commit hook") {
		t.Error("expected no hook prompt when .git dir is absent")
	}
}

func TestPromptYN(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		defaultYes bool
		want       bool
	}{
		{"empty defaults yes", "\n", true, true},
		{"empty defaults no", "\n", false, false},
		{"y", "y\n", false, true},
		{"yes", "yes\n", false, true},
		{"Y", "Y\n", false, true},
		{"n", "n\n", true, false},
		{"no", "no\n", true, false},
		{"random", "blah\n", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := bufio.NewScanner(strings.NewReader(tt.input))
			var out bytes.Buffer
			got := promptYN(scanner, &out, "test?", tt.defaultYes)
			if got != tt.want {
				t.Errorf("promptYN() = %v, want %v", got, tt.want)
			}
		})
	}
}
