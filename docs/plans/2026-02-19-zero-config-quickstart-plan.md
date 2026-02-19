# Zero-Config Quick Start — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `governor audit .` work immediately after install with zero configuration by auto-falling-back to rule-only mode, detecting project type, improving terminal output, and adding a quickstart wizard.

**Architecture:** Four independent features that layer together. Task 1 (detect) is a new package. Task 2 (auto-quick) modifies CLI flag resolution. Task 3 (terminal output) upgrades the scan formatter. Task 4 (quickstart) orchestrates existing commands. Each task is independently shippable.

**Tech Stack:** Go 1.22+, lipgloss (already a dependency), bufio (stdlib), go-isatty (already a dependency)

---

### Task 1: Project Auto-Detection Package

**Files:**
- Create: `internal/detect/detect.go`
- Create: `internal/detect/detect_test.go`

**Step 1: Write the failing test**

Create `internal/detect/detect_test.go`:

```go
package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetect_GoProject(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example"), 0o600)

	result := Project(dir)
	if result.Type != "go" {
		t.Errorf("expected go, got %s", result.Type)
	}
	if result.Label != "Go" {
		t.Errorf("expected Go, got %s", result.Label)
	}
}

func TestDetect_NextJS(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "next.config.js"), []byte("module.exports = {}"), 0o600)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{}}`), 0o600)

	result := Project(dir)
	if result.Type != "nextjs" {
		t.Errorf("expected nextjs, got %s", result.Type)
	}
}

func TestDetect_Express(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"express":"^4.0.0"}}`), 0o600)

	result := Project(dir)
	if result.Type != "express" {
		t.Errorf("expected express, got %s", result.Type)
	}
}

func TestDetect_FastAPI(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("fastapi==0.100.0\nuvicorn"), 0o600)

	result := Project(dir)
	if result.Type != "fastapi" {
		t.Errorf("expected fastapi, got %s", result.Type)
	}
}

func TestDetect_Supabase(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "supabase"), 0o700)
	os.WriteFile(filepath.Join(dir, "supabase", "config.toml"), []byte("[project]"), 0o600)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{}}`), 0o600)

	result := Project(dir)
	if result.Type != "supabase" {
		t.Errorf("expected supabase, got %s", result.Type)
	}
}

func TestDetect_Rust(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[package]"), 0o600)

	result := Project(dir)
	if result.Type != "rust" {
		t.Errorf("expected rust, got %s", result.Type)
	}
}

func TestDetect_NodeFallback(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"lodash":"^4"}}`), 0o600)

	result := Project(dir)
	if result.Type != "node" {
		t.Errorf("expected node, got %s", result.Type)
	}
}

func TestDetect_PythonFallback(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests\nbeautifulsoup4"), 0o600)

	result := Project(dir)
	if result.Type != "python" {
		t.Errorf("expected python, got %s", result.Type)
	}
}

func TestDetect_Unknown(t *testing.T) {
	dir := t.TempDir()

	result := Project(dir)
	if result.Type != "" {
		t.Errorf("expected empty, got %s", result.Type)
	}
	if result.Label != "" {
		t.Errorf("expected empty label, got %s", result.Label)
	}
}

func TestDetect_Flask(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==3.0.0\ngunicorn"), 0o600)

	result := Project(dir)
	if result.Type != "flask" {
		t.Errorf("expected flask, got %s", result.Type)
	}
}

func TestDetect_Fastify(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"fastify":"^4.0.0"}}`), 0o600)

	result := Project(dir)
	if result.Type != "fastify" {
		t.Errorf("expected fastify, got %s", result.Type)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/detect/ -v`
Expected: FAIL — package does not exist

**Step 3: Write implementation**

Create `internal/detect/detect.go`:

```go
package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Result holds the detected project type.
type Result struct {
	Type  string // machine-readable: "nextjs", "express", "go", etc. Empty if unknown.
	Label string // human-readable: "Next.js", "Express", "Go", etc. Empty if unknown.
}

// Project detects the project type at the given root directory.
// It checks marker files in priority order and returns the first match.
func Project(root string) Result {
	// High-specificity checks first.
	if fileExists(root, "next.config.js") || fileExists(root, "next.config.mjs") || fileExists(root, "next.config.ts") {
		return Result{Type: "nextjs", Label: "Next.js"}
	}
	if dirExists(root, "supabase") && fileExists(filepath.Join(root, "supabase"), "config.toml") {
		return Result{Type: "supabase", Label: "Supabase"}
	}

	// Check package.json dependencies.
	if deps := readPackageJSONDeps(root); deps != nil {
		if _, ok := deps["express"]; ok {
			return Result{Type: "express", Label: "Express"}
		}
		if _, ok := deps["fastify"]; ok {
			return Result{Type: "fastify", Label: "Fastify"}
		}
	}

	// Check Python dependency files.
	if reqs := readFileLines(root, "requirements.txt"); reqs != nil {
		for _, line := range reqs {
			pkg := strings.Split(strings.Split(line, "==")[0], ">=")[0]
			pkg = strings.TrimSpace(strings.Split(pkg, "[")[0])
			switch strings.ToLower(pkg) {
			case "fastapi":
				return Result{Type: "fastapi", Label: "FastAPI"}
			case "flask":
				return Result{Type: "flask", Label: "Flask"}
			case "django":
				return Result{Type: "django", Label: "Django"}
			}
		}
	}

	// Language-level fallbacks.
	if fileExists(root, "go.mod") {
		return Result{Type: "go", Label: "Go"}
	}
	if fileExists(root, "Cargo.toml") {
		return Result{Type: "rust", Label: "Rust"}
	}
	if fileExists(root, "package.json") {
		return Result{Type: "node", Label: "Node.js"}
	}
	if fileExists(root, "requirements.txt") || fileExists(root, "pyproject.toml") || fileExists(root, "setup.py") {
		return Result{Type: "python", Label: "Python"}
	}

	return Result{}
}

func fileExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func dirExists(dir, name string) bool {
	info, err := os.Stat(filepath.Join(dir, name))
	return err == nil && info.IsDir()
}

func readPackageJSONDeps(root string) map[string]string {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	merged := make(map[string]string)
	for k, v := range pkg.Dependencies {
		merged[k] = v
	}
	for k, v := range pkg.DevDependencies {
		merged[k] = v
	}
	return merged
}

func readFileLines(root, name string) []string {
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/detect/ -v`
Expected: PASS — all 11 tests pass

**Step 5: Verify build**

Run: `go build ./...`
Expected: Success

**Step 6: Commit**

```bash
git add internal/detect/detect.go internal/detect/detect_test.go
git commit -m "feat(detect): add project type auto-detection package"
```

---

### Task 2: Auto-Quick Fallback When No AI Configured

**Files:**
- Modify: `cmd/cli.go:278-314` (runAudit — quick/AI resolution block)
- Modify: `cmd/cli.go:610-680` (printAuditSummary)
- Create: `cmd/cli_quickfall_test.go`

**Step 1: Write the failing test**

Create `cmd/cli_quickfall_test.go`:

```go
package cmd

import (
	"testing"

	"governor/internal/config"
)

func TestShouldAutoQuick(t *testing.T) {
	tests := []struct {
		name          string
		explicitQuick bool
		aiProfile     string
		cfg           config.Config
		setFlags      map[string]struct{}
		wantAutoQuick bool
	}{
		{
			name:          "no config no flags",
			aiProfile:     "codex",
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{},
			wantAutoQuick: true,
		},
		{
			name:          "explicit quick flag",
			explicitQuick: true,
			aiProfile:     "codex",
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"quick": {}},
			wantAutoQuick: false, // already quick, not auto
		},
		{
			name:      "ai-profile set via flag",
			aiProfile: "openai",
			cfg:       config.Config{},
			setFlags:  map[string]struct{}{"ai-profile": {}},
			wantAutoQuick: false,
		},
		{
			name:      "ai-profile set via config",
			aiProfile: "codex",
			cfg:       config.Config{AIProfile: "openai"},
			setFlags:  map[string]struct{}{},
			wantAutoQuick: false,
		},
		{
			name:      "ai-provider set via flag",
			aiProfile: "codex",
			cfg:       config.Config{},
			setFlags:  map[string]struct{}{"ai-provider": {}},
			wantAutoQuick: false,
		},
		{
			name:      "ai-api-key-env set via config",
			aiProfile: "codex",
			cfg:       config.Config{AIAPIKeyEnv: "MY_KEY"},
			setFlags:  map[string]struct{}{},
			wantAutoQuick: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldAutoQuick(tt.explicitQuick, tt.cfg, tt.setFlags)
			if got != tt.wantAutoQuick {
				t.Errorf("shouldAutoQuick() = %v, want %v", got, tt.wantAutoQuick)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestShouldAutoQuick -v`
Expected: FAIL — `shouldAutoQuick` not defined

**Step 3: Write the shouldAutoQuick function**

Add to `cmd/cli.go` (after `isInteractiveTerminal` function, around line 2527):

```go
// shouldAutoQuick returns true when the user has not explicitly configured
// an AI profile via flags or config, meaning we should fall back to rule-only
// mode for a zero-setup first experience.
func shouldAutoQuick(explicitQuick bool, cfg config.Config, setFlags map[string]struct{}) bool {
	if explicitQuick {
		return false // already quick, not auto
	}
	// Any explicit AI configuration means the user has set up AI.
	aiFlags := []string{"ai-profile", "ai-provider", "ai-model", "ai-auth-mode", "ai-base-url", "ai-api-key-env", "ai-bin"}
	for _, f := range aiFlags {
		if _, ok := setFlags[f]; ok {
			return false
		}
	}
	// Config file has AI settings.
	if cfg.AIProfile != "" || cfg.AIProvider != "" || cfg.AIModel != "" ||
		cfg.AIAuthMode != "" || cfg.AIBaseURL != "" || cfg.AIAPIKeyEnv != "" || cfg.AIBin != "" {
		return false
	}
	return true
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/ -run TestShouldAutoQuick -v`
Expected: PASS

**Step 5: Wire auto-quick into runAudit**

In `cmd/cli.go`, in `runAudit`, after the config is loaded and flags are resolved (around line 278 where `if *quick {` begins), add the auto-quick logic:

```go
	autoQuick := false
	if shouldAutoQuick(*quick, cfg, setFlags) {
		autoQuick = true
		*quick = true
	}
```

This goes right before line 278 (`if *quick {`).

**Step 6: Print AI hint after auto-quick audit**

In `runAudit`, after `printAuditSummary` is called (find where it's called in the non-TUI path), add:

```go
	if autoQuick {
		fmt.Fprintf(os.Stderr, "\n%d rule-engine checks completed (no AI key needed)\n\n", report.RunMetadata.RuleChecks)
		fmt.Fprintf(os.Stderr, "Want deeper analysis? Add an AI profile:\n")
		fmt.Fprintf(os.Stderr, "  governor init --ai-profile openai\n")
		fmt.Fprintf(os.Stderr, "  export OPENAI_API_KEY=sk-...\n")
		fmt.Fprintf(os.Stderr, "  governor audit .\n\n")
	}
```

**Step 7: Run full test suite**

Run: `go test ./cmd/ -v -count=1`
Expected: PASS

**Step 8: Manual verification**

Run: `go run . audit . --quick` — should work as before
Run: `go build ./...` — should compile

**Step 9: Commit**

```bash
git add cmd/cli.go cmd/cli_quickfall_test.go
git commit -m "feat(cli): auto-fall-back to rule-only mode when no AI configured"
```

---

### Task 3: Improved Terminal Output

**Files:**
- Modify: `internal/scan/format.go`
- Modify: `internal/scan/format_test.go`

**Step 1: Write the failing test**

Add to `internal/scan/format_test.go`:

```go
func TestFormatHumanColorized_SortsBySeverity(t *testing.T) {
	findings := []model.Finding{
		{Title: "Low issue", Severity: "low", Remediation: "Fix low"},
		{Title: "Critical issue", Severity: "critical", Remediation: "Fix critical"},
		{Title: "High issue", Severity: "high", Remediation: "Fix high"},
	}

	out := FormatHumanColorized(findings, false)

	critIdx := strings.Index(out, "Critical issue")
	highIdx := strings.Index(out, "High issue")
	lowIdx := strings.Index(out, "Low issue")

	if critIdx == -1 || highIdx == -1 || lowIdx == -1 {
		t.Fatalf("missing finding in output:\n%s", out)
	}
	if critIdx > highIdx || highIdx > lowIdx {
		t.Errorf("findings not sorted by severity: crit=%d high=%d low=%d", critIdx, highIdx, lowIdx)
	}
}

func TestFormatHumanColorized_SummaryHeader(t *testing.T) {
	findings := []model.Finding{
		{Title: "A", Severity: "critical"},
		{Title: "B", Severity: "high"},
		{Title: "C", Severity: "medium"},
	}

	out := FormatHumanColorized(findings, false)

	if !strings.Contains(out, "3 findings") {
		t.Errorf("expected summary header with count, got:\n%s", out)
	}
	if !strings.Contains(out, "1 critical") {
		t.Errorf("expected critical count in summary, got:\n%s", out)
	}
}

func TestFormatHumanColorized_NoFindings(t *testing.T) {
	out := FormatHumanColorized(nil, false)
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected no findings message, got:\n%s", out)
	}
}

func TestFormatHumanColorized_VerboseIncludesEvidence(t *testing.T) {
	findings := []model.Finding{
		{Title: "Issue", Severity: "high", Evidence: "found bad thing", Remediation: "fix it"},
	}

	concise := FormatHumanColorized(findings, false)
	verbose := FormatHumanColorized(findings, true)

	if strings.Contains(concise, "found bad thing") {
		t.Error("concise output should not contain evidence")
	}
	if !strings.Contains(verbose, "found bad thing") {
		t.Error("verbose output should contain evidence")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/scan/ -run TestFormatHumanColorized -v`
Expected: FAIL — `FormatHumanColorized` not defined

**Step 3: Write implementation**

Add to `internal/scan/format.go`:

```go
import (
	"sort"
	"github.com/charmbracelet/lipgloss"
)
```

```go
var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

var (
	critStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("1"))
	highStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))
	medStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	lowStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	infoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	fileStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	remStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

// FormatHumanColorized formats findings with color, sorting, and a summary header.
// When verbose is false, evidence is omitted for a condensed view.
func FormatHumanColorized(findings []model.Finding, verbose bool) string {
	if len(findings) == 0 {
		return "No findings.\n"
	}

	// Sort by severity.
	sorted := make([]model.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityOrder[strings.ToLower(sorted[i].Severity)] < severityOrder[strings.ToLower(sorted[j].Severity)]
	})

	// Count by severity.
	counts := map[string]int{}
	for _, f := range sorted {
		counts[strings.ToLower(f.Severity)]++
	}

	var b strings.Builder

	// Summary header.
	b.WriteString(fmt.Sprintf("governor audit complete — %d findings", len(sorted)))
	parts := []string{}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c := counts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}
	if len(parts) > 0 {
		b.WriteString(" (")
		b.WriteString(strings.Join(parts, ", "))
		b.WriteString(")")
	}
	b.WriteString("\n\n")

	// Findings.
	for _, f := range sorted {
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "UNKNOWN"
		}
		label := styleSeverity(sev)
		b.WriteString(fmt.Sprintf("  %-10s %s\n", label, f.Title))

		if len(f.FileRefs) > 0 {
			b.WriteString(fmt.Sprintf("            %s\n", fileStyle.Render(strings.Join(f.FileRefs, ", "))))
		}

		if verbose {
			evidence := strings.TrimSpace(f.Evidence)
			if evidence != "" {
				evidence = strings.ReplaceAll(evidence, "\n", " ")
				if len(evidence) > 120 {
					evidence = evidence[:120] + "..."
				}
				b.WriteString(fmt.Sprintf("            evidence: %s\n", evidence))
			}
		}

		rem := strings.TrimSpace(f.Remediation)
		if rem != "" {
			rem = strings.ReplaceAll(rem, "\n", " ")
			if len(rem) > 200 {
				rem = rem[:200] + "..."
			}
			b.WriteString(fmt.Sprintf("            %s\n", remStyle.Render("→ "+rem)))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func styleSeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return critStyle.Render(fmt.Sprintf("%-8s", sev))
	case "HIGH":
		return highStyle.Render(fmt.Sprintf("%-8s", sev))
	case "MEDIUM":
		return medStyle.Render(fmt.Sprintf("%-8s", sev))
	case "LOW":
		return lowStyle.Render(fmt.Sprintf("%-8s", sev))
	default:
		return infoStyle.Render(fmt.Sprintf("%-8s", sev))
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/scan/ -v`
Expected: PASS — all tests pass including new ones

**Step 5: Wire FormatHumanColorized into audit output**

In `cmd/cli.go`, find where `FormatHuman` is called for the scan command output (around line 4066) and add a colorized variant call. Also update the audit non-TUI output path to use the new formatter for printing findings to stderr after the summary.

The scan command's `runScan` function (line 4065) should use `FormatHumanColorized` when outputting to a terminal:

```go
	if isInteractiveTerminal() {
		fmt.Print(scan.FormatHumanColorized(result.Findings, false))
	} else {
		fmt.Print(scan.FormatHuman(result.Findings))
	}
```

**Step 6: Build and test**

Run: `go build ./...`
Run: `go test ./internal/scan/ -v`
Expected: Both pass

**Step 7: Commit**

```bash
git add internal/scan/format.go internal/scan/format_test.go cmd/cli.go
git commit -m "feat(scan): add color-coded severity-sorted terminal output"
```

---

### Task 4: `governor quickstart` Wizard

**Files:**
- Modify: `cmd/cli.go` — add `quickstart` command routing and `runQuickstart` function
- Create: `cmd/cli_quickstart_test.go`

**Step 1: Write the failing test**

Create `cmd/cli_quickstart_test.go`:

```go
package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuickstartCreatesGovDir(t *testing.T) {
	dir := t.TempDir()

	// Create a fake git repo.
	os.MkdirAll(filepath.Join(dir, ".git"), 0o700)

	// Simulate Y to init, N to hook, N to AI, N to audit.
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestQuickstart -v`
Expected: FAIL — `runQuickstartWithIO` not defined

**Step 3: Write implementation**

Add the `quickstart` case to the command switch in `cmd/cli.go` `Execute` function (around line 76):

```go
	case "quickstart":
		return runQuickstart(args[1:])
```

Add the `quickstart` line to `printUsage` (after the `init` line):

```go
	fmt.Println("  governor quickstart              — guided setup wizard")
```

Add the implementation to `cmd/cli.go`:

```go
func runQuickstart(args []string) error {
	fs := flag.NewFlagSet("quickstart", flag.ContinueOnError)
	fs.SetOutput(flag.CommandLine.Output())
	if err := fs.Parse(args); err != nil {
		return err
	}

	return runQuickstartWithIO(".", os.Stdin, os.Stderr)
}

func runQuickstartWithIO(root string, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve root: %w", err)
	}

	// Step 1: Detect project.
	result := detect.Project(absRoot)
	if result.Label != "" {
		fmt.Fprintf(out, "\n  Scanning project...\n")
		fmt.Fprintf(out, "  Detected: %s project\n\n", result.Label)
	} else {
		fmt.Fprintf(out, "\n  Scanning project...\n\n")
	}

	// Step 2: Initialize .governor.
	govDir := filepath.Join(absRoot, ".governor")
	if promptYN(scanner, out, "1. Initialize .governor directory?", true) {
		if err := initGovDir(absRoot, ""); err != nil {
			return err
		}
		fmt.Fprintf(out, "     created %s\n\n", filepath.Join(".governor", "config.yaml"))
	}

	// Step 3: Install pre-commit hook.
	gitDir := filepath.Join(absRoot, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		if promptYN(scanner, out, "2. Install pre-commit hook?", true) {
			hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
			hooksDir := filepath.Dir(hookPath)
			os.MkdirAll(hooksDir, 0o755)
			if err := os.WriteFile(hookPath, []byte(hookScript), 0o755); err != nil {
				fmt.Fprintf(out, "     warning: could not install hook: %v\n\n", err)
			} else {
				fmt.Fprintf(out, "     installed pre-commit hook\n\n")
			}
		}
	}

	// Step 4: AI setup.
	if promptYN(scanner, out, "3. Set up AI-powered checks?", false) {
		fmt.Fprintf(out, "     To configure AI, run:\n")
		fmt.Fprintf(out, "       governor init --ai-profile openai\n")
		fmt.Fprintf(out, "       export OPENAI_API_KEY=sk-...\n\n")
	}

	// Step 5: First audit.
	if promptYN(scanner, out, "4. Run your first audit now?", true) {
		fmt.Fprintf(out, "     Running rule-engine audit...\n\n")
		auditErr := runAudit([]string{absRoot, "--quick"})
		if auditErr != nil {
			fmt.Fprintf(out, "     audit completed with findings\n")
		}
	}

	// Next steps.
	fmt.Fprintf(out, "\n  Next steps:\n")
	fmt.Fprintf(out, "    governor audit . --ai-profile openai   — deeper AI-powered analysis\n")
	fmt.Fprintf(out, "    governor checks list                    — see all available checks\n")
	fmt.Fprintf(out, "    governor badge <audit.json>             — add a security badge\n\n")

	return nil
}

func initGovDir(root, aiProfile string) error {
	govDir := filepath.Join(root, ".governor")
	checksDir := filepath.Join(govDir, "checks")
	gitignorePath := filepath.Join(govDir, ".gitignore")
	configPath := filepath.Join(govDir, "config.yaml")

	if err := os.MkdirAll(checksDir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", checksDir, err)
	}

	gitignoreContent := "# Keep this file and repo-local checks.\n*\n!.gitignore\n!checks/\n!checks/**\n!suppressions.yaml\n!baseline.json\n!config.yaml\n\n# Always ignore generated run artifacts.\nruns/\n"

	configContent := "# Governor configuration\n# ai_profile: codex\n# workers: 3\n"
	if strings.TrimSpace(aiProfile) != "" {
		configContent = "# Governor configuration\nai_profile: " + strings.TrimSpace(aiProfile) + "\n# workers: 3\n"
	}

	os.WriteFile(gitignorePath, []byte(gitignoreContent), 0o600)
	os.WriteFile(configPath, []byte(configContent), 0o600)
	return nil
}

func promptYN(scanner *bufio.Scanner, out io.Writer, prompt string, defaultYes bool) bool {
	hint := "[Y/n]"
	if !defaultYes {
		hint = "[y/N]"
	}
	fmt.Fprintf(out, "  %s %s ", prompt, hint)

	if !scanner.Scan() {
		return defaultYes
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer == "" {
		return defaultYes
	}
	return answer == "y" || answer == "yes"
}
```

Note: You'll need to add `"io"` and `"governor/internal/detect"` to the imports in `cmd/cli.go`.

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/ -run TestQuickstart -v`
Expected: PASS

**Step 5: Build and full test**

Run: `go build ./...`
Run: `go test ./cmd/ -v -count=1`
Expected: Both pass

**Step 6: Commit**

```bash
git add cmd/cli.go cmd/cli_quickstart_test.go
git commit -m "feat(cli): add governor quickstart interactive wizard"
```

---

### Task 5: Integration — Wire Detect Into Audit Output

**Files:**
- Modify: `cmd/cli.go` — add detect call in `runAudit`, show in output

**Step 1: Add detect import and call**

In `runAudit`, after resolving the input path but before running the audit (around line 265-270), add:

```go
	detected := detect.Project(positionalInput)
```

Then in `printAuditSummary`, pass and display the detection result:

```go
	if detected.Label != "" {
		fmt.Fprintf(os.Stderr, "detected:       %s\n", detected.Label)
	}
```

**Step 2: Build and test**

Run: `go build ./...`
Run: `go test ./... -count=1`
Expected: Both pass

**Step 3: Commit**

```bash
git add cmd/cli.go
git commit -m "feat(cli): show detected project type in audit output"
```

---

### Task 6: Final Verification

**Step 1: Run full test suite**

Run: `go test ./... -count=1`
Expected: All packages pass

**Step 2: Run linter**

Run: `golangci-lint run ./...`
Expected: Zero issues

**Step 3: Manual smoke test**

Run: `go run . quickstart` (in a test project directory)
Run: `go run . audit .` (with no AI config — should auto-quick)
Run: `go run . audit . --quick` (explicit quick — no hint)
Run: `go run . scan internal/detect/detect.go`

**Step 4: Final commit if any cleanup needed**

```bash
git add -A
git commit -m "chore: final cleanup for zero-config quickstart"
```
