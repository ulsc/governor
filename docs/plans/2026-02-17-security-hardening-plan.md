# Security Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden governor against mis-classification attacks (Finding 1) and governance evasion via suppressions (Finding 3).

**Architecture:** Seven targeted fixes across intake, model, suppress, worker, app, and CLI packages. Each fix is isolated to 1-2 files plus tests. Fixes 1a-1c address file mis-classification; fixes 3a-3d harden the suppression system.

**Tech Stack:** Go 1.22+, standard library only, table-driven tests, `go test ./...`

---

### Task 1: Fix 1a — Split security-relevant file skipping from binary skipping

**Files:**
- Modify: `internal/intake/intake.go:48-53` (skipFileExts), `internal/intake/intake.go:252-280` (skipFile), `internal/intake/intake.go:282-298` (isSensitiveFileName)
- Modify: `internal/model/types.go:54-64` (InputManifest)
- Test: `internal/intake/intake_test.go`

**Step 1: Write the failing tests**

Add to `internal/intake/intake_test.go`:

```go
func TestStageFolder_SecurityRelevantFilesCounted(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")
	mustWrite(t, filepath.Join(root, "server.pem"), "-----BEGIN CERTIFICATE-----")
	mustWrite(t, filepath.Join(root, "private.key"), "-----BEGIN PRIVATE KEY-----")
	mustWrite(t, filepath.Join(root, ".env"), "SECRET=abc")

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  10,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}

	if res.Manifest.SecurityRelevantSkipped != 3 {
		t.Fatalf("expected 3 security-relevant skipped, got %d", res.Manifest.SecurityRelevantSkipped)
	}
	// .pem and .key should use "security_relevant_excluded" reason, not "skip_ext"
	if got := res.Manifest.SkippedByReason["security_relevant_excluded"]; got < 2 {
		t.Fatalf("expected security_relevant_excluded >= 2, got %d", got)
	}
	// .env should also use "security_relevant_excluded"
	if got := res.Manifest.SkippedByReason["skip_secret"]; got != 0 {
		t.Fatalf("expected skip_secret == 0 (replaced by security_relevant_excluded), got %d", got)
	}
}

func TestSkipFile_SecurityRelevantReason(t *testing.T) {
	tests := []struct {
		name       string
		filename   string
		wantReason string
		wantSkip   bool
	}{
		{"pem file", "server.pem", "security_relevant_excluded", true},
		{"key file", "private.key", "security_relevant_excluded", true},
		{"p12 file", "cert.p12", "security_relevant_excluded", true},
		{"pfx file", "cert.pfx", "security_relevant_excluded", true},
		{"crt file", "ca.crt", "security_relevant_excluded", true},
		{"env file", ".env", "security_relevant_excluded", true},
		{"env variant", ".env.production", "security_relevant_excluded", true},
		{"secrets yaml", "secrets.yaml", "security_relevant_excluded", true},
		{"credentials json", "credentials.json", "security_relevant_excluded", true},
		{"png still skipped", "image.png", "skip_ext", true},
		{"exe still skipped", "app.exe", "skip_ext", true},
		{"go not skipped", "main.go", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, skip := skipFile(tc.filename, tc.filename, 100, 0o644)
			if skip != tc.wantSkip {
				t.Errorf("skipFile(%q) skip=%v, want %v", tc.filename, skip, tc.wantSkip)
			}
			if reason != tc.wantReason {
				t.Errorf("skipFile(%q) reason=%q, want %q", tc.filename, reason, tc.wantReason)
			}
		})
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test -run 'TestStageFolder_SecurityRelevantFilesCounted|TestSkipFile_SecurityRelevantReason' ./internal/intake/`
Expected: FAIL — `SecurityRelevantSkipped` field doesn't exist, reasons don't match

**Step 3: Implement the changes**

In `internal/model/types.go`, add `SecurityRelevantSkipped` to `InputManifest`:

```go
type InputManifest struct {
	RootPath                string         `json:"root_path"`
	InputPath               string         `json:"input_path"`
	InputType               string         `json:"input_type"`
	IncludedFiles           int            `json:"included_files"`
	IncludedBytes           int64          `json:"included_bytes"`
	SkippedFiles            int            `json:"skipped_files"`
	SecurityRelevantSkipped int            `json:"security_relevant_skipped,omitempty"`
	SkippedByReason         map[string]int `json:"skipped_by_reason"`
	Files                   []ManifestFile `json:"files"`
	GeneratedAt             time.Time      `json:"generated_at"`
}
```

In `internal/intake/intake.go`:

1. Remove `.pem`, `.key`, `.p12`, `.pfx`, `.crt` from `skipFileExts` (line 52).

2. Add a new set after `skipFileNames`:

```go
var securityRelevantExts = map[string]struct{}{
	".pem": {}, ".key": {}, ".p12": {}, ".pfx": {}, ".crt": {},
}
```

3. In `skipFile` (line 252-280), restructure to check security-relevant files *before* regular ext skip. Change the `isSensitiveFileName` and `isSensitiveFilePath` calls to return `"security_relevant_excluded"` instead of `"skip_secret"`. Add a check for `securityRelevantExts`:

```go
func skipFile(name string, rel string, size int64, mode os.FileMode) (reason string, skip bool) {
	if mode&os.ModeSymlink != 0 {
		return "symlink", true
	}
	if size > maxFileBytes {
		fmt.Fprintf(os.Stderr, "[governor] warning: skipping oversized file (%d bytes): %s\n", size, rel)
		return "file_too_large", true
	}
	if isSensitiveFileName(name) || isSensitiveFilePath(rel) {
		return "security_relevant_excluded", true
	}
	if _, ok := skipFileNames[name]; ok {
		return "skip_name", true
	}
	if size == 0 {
		return "empty", true
	}
	ext := strings.ToLower(filepath.Ext(name))
	if _, ok := securityRelevantExts[ext]; ok {
		return "security_relevant_excluded", true
	}
	if _, ok := skipFileExts[ext]; ok {
		return "skip_ext", true
	}
	if hasSkippedDirComponent(rel) {
		return "skip_dir", true
	}
	return "", false
}
```

4. In `stageFolderToWorkspace` (line 226-230), after the `skipFile` call, increment `SecurityRelevantSkipped` when the reason is `"security_relevant_excluded"`:

```go
if reason, skip := skipFile(name, rel, info.Size(), info.Mode()); skip {
	manifest.SkippedByReason[reason]++
	manifest.SkippedFiles++
	if reason == "security_relevant_excluded" {
		manifest.SecurityRelevantSkipped++
	}
	return nil
}
```

5. Update the existing `TestStageFolder_BuildManifestAndSkip` test assertion at line 48 from `skip_secret` to `security_relevant_excluded`:
```go
if got := res.Manifest.SkippedByReason["security_relevant_excluded"]; got < 1 {
	t.Fatalf("expected security_relevant_excluded >= 1, got %d", got)
}
```

Note: The `skipFile` function signature currently takes `os.FileMode` as the 4th parameter. The test needs to pass a valid `os.FileMode` value (e.g., `0o644`). Check the existing signature — it's `(name string, rel string, size int64, mode os.FileMode)`.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/intake/ && go test ./internal/model/`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/intake/intake.go internal/intake/intake_test.go internal/model/types.go
git commit -m "feat(intake): split security-relevant file skipping from binary skipping"
```

---

### Task 2: Fix 1b — Emit warning for security-relevant file skips

**Files:**
- Modify: `internal/intake/intake.go:59-155` (Stage function)
- Test: `internal/intake/intake_test.go`

**Step 1: Write the failing test**

Add to `internal/intake/intake_test.go`:

```go
func TestStageFolder_SecurityRelevantWarning(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main")
	mustWrite(t, filepath.Join(root, "server.pem"), "cert")
	mustWrite(t, filepath.Join(root, ".env"), "SECRET=x")

	// Capture stderr
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	out := t.TempDir()
	_, err := Stage(StageOptions{
		InputPath: root,
		OutDir:    out,
		MaxFiles:  10,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}

	_ = w.Close()
	var buf strings.Builder
	_, _ = io.Copy(&buf, r)
	os.Stderr = old

	stderr := buf.String()
	if !strings.Contains(stderr, "security-relevant files skipped") {
		t.Fatalf("expected security-relevant warning on stderr, got: %q", stderr)
	}
	if !strings.Contains(stderr, "secrets scanner") {
		t.Fatalf("expected secrets scanner suggestion in warning, got: %q", stderr)
	}
}
```

(Add `"io"` to imports if not already present.)

**Step 2: Run test to verify it fails**

Run: `go test -run TestStageFolder_SecurityRelevantWarning ./internal/intake/`
Expected: FAIL — no such warning printed

**Step 3: Implement the warning**

In `internal/intake/intake.go`, in the `Stage` function, after `stageFolderToWorkspace` / `stageZipToWorkspace` completes (around line 147), before the sort, add:

```go
if manifest.SecurityRelevantSkipped > 0 {
	fmt.Fprintf(os.Stderr, "[governor] warning: %d security-relevant files skipped (secrets, keys, certs) — consider running a dedicated secrets scanner\n", manifest.SecurityRelevantSkipped)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/intake/`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/intake/intake.go internal/intake/intake_test.go
git commit -m "feat(intake): emit warning when security-relevant files are skipped"
```

---

### Task 3: Fix 1c — Configurable rule-engine file size limit with report warnings

**Files:**
- Modify: `internal/worker/rule_engine.go:16-19` (maxRuleFileBytes), `internal/worker/rule_engine.go:35` (executeRuleCheck)
- Modify: `internal/worker/runner.go` (RunOptions — add MaxRuleFileBytes)
- Modify: `internal/app/audit.go:28-66` (AuditOptions — add MaxRuleFileBytes)
- Modify: `cmd/cli.go` (add `--max-rule-file-bytes` flag to `runAudit` and `runCI`)
- Test: `internal/worker/rule_engine_test.go`

**Step 1: Write the failing test**

Add to `internal/worker/rule_engine_test.go` (create if it doesn't exist):

```go
func TestExecuteRuleCheck_RespectsCustomMaxFileBytes(t *testing.T) {
	// Create a workspace with a file slightly over 1KB
	dir := t.TempDir()
	content := strings.Repeat("password = 'secret'\n", 100) // ~2000 bytes
	if err := os.WriteFile(filepath.Join(dir, "config.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := model.InputManifest{
		RootPath: dir,
		Files:    []model.ManifestFile{{Path: "config.txt", Size: int64(len(content))}},
	}
	checkDef := checks.Definition{
		ID:     "test_check",
		Engine: checks.EngineRule,
		Rule: checks.RuleSpec{
			Detectors: []checks.RuleDetector{
				{ID: "d1", Kind: checks.RuleDetectorContains, Pattern: "password"},
			},
		},
	}

	// With limit lower than file size, file should be skipped
	result := executeRuleCheck(context.Background(), dir, manifest, checkDef, 1000)
	if len(result.payload.Findings) != 0 {
		t.Fatalf("expected 0 findings with 1KB limit, got %d", len(result.payload.Findings))
	}

	// With limit higher than file size, file should be scanned
	result2 := executeRuleCheck(context.Background(), dir, manifest, checkDef, 5000)
	if len(result2.payload.Findings) == 0 {
		t.Fatal("expected findings with 5KB limit")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestExecuteRuleCheck_RespectsCustomMaxFileBytes ./internal/worker/`
Expected: FAIL — `executeRuleCheck` doesn't accept a maxFileBytes parameter

**Step 3: Implement the changes**

1. In `internal/worker/rule_engine.go`, change `maxRuleFileBytes` from a const to a default:
```go
const (
	defaultDetectorMaxMatches   = 5
	defaultRuleConfidence       = 0.7
	DefaultMaxRuleFileBytes     = 2 * 1024 * 1024
	MaxAllowedRuleFileBytes     = 20 * 1024 * 1024
	regexMatchTimeout           = 5 * time.Second
)
```

2. Add `maxFileBytes int` parameter to `executeRuleCheck`:
```go
func executeRuleCheck(ctx context.Context, workspace string, manifest model.InputManifest, checkDef checks.Definition, maxFileBytes int) ruleExecResult {
```

Update the size check (line 83):
```go
if len(contentBytes) > maxFileBytes {
```

And the notes message (line 85):
```go
notes = append(notes, fmt.Sprintf("skipped %s (size=%d exceeds %d)", rel, len(contentBytes), maxFileBytes))
```

Also update `ScanFiles` to use `DefaultMaxRuleFileBytes`:
```go
if len(contentBytes) > DefaultMaxRuleFileBytes {
```

3. In `internal/worker/runner.go`, add `MaxRuleFileBytes int` to `RunOptions`. Find where `executeRuleCheck` is called and pass the value:
```go
maxRuleBytes := opts.MaxRuleFileBytes
if maxRuleBytes <= 0 {
	maxRuleBytes = DefaultMaxRuleFileBytes
}
// ... pass maxRuleBytes to executeRuleCheck
```

4. In `internal/app/audit.go`, add `MaxRuleFileBytes int` to `AuditOptions`. Thread it through to `worker.RunOptions`.

5. In `cmd/cli.go`, add `--max-rule-file-bytes` flag to both `runAudit` and `runCI` flag sets:
```go
maxRuleFileBytes := fs.Int("max-rule-file-bytes", 0, "Max file size for rule-engine scanning (default 2MB, max 20MB)")
```

Add validation after parse:
```go
if *maxRuleFileBytes < 0 || *maxRuleFileBytes > worker.MaxAllowedRuleFileBytes {
	return fmt.Errorf("--max-rule-file-bytes must be between 0 and %d", worker.MaxAllowedRuleFileBytes)
}
```

Thread into `AuditOptions`:
```go
MaxRuleFileBytes: *maxRuleFileBytes,
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/worker/ && go test ./internal/app/ && go test ./cmd/`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/worker/rule_engine.go internal/worker/runner.go internal/app/audit.go cmd/cli.go internal/worker/rule_engine_test.go
git commit -m "feat(worker): make rule-engine file size limit configurable via --max-rule-file-bytes"
```

---

### Task 4: Fix 3a — Ban wildcard-only suppression check IDs

**Files:**
- Modify: `internal/suppress/inline.go:82-126` (parseSuppressionComment)
- Modify: `internal/suppress/suppress.go:82-105` (ruleMatches), `internal/suppress/suppress.go:108-132` (matchInline)
- Test: `internal/suppress/inline_test.go`, `internal/suppress/suppress_test.go`

**Step 1: Write the failing tests**

Add to `internal/suppress/inline_test.go`:

```go
func TestParseSuppressionComment_RejectsWildcard(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		wantOK bool
	}{
		{"bare wildcard", "// governor:suppress *", false},
		{"wildcard with reason", "// governor:suppress * -- suppress all", false},
		{"specific check ok", "// governor:suppress hardcoded_credentials", true},
		{"glob pattern ok", "// governor:suppress hardcoded_*", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, ok := parseSuppressionComment(tc.line)
			if ok != tc.wantOK {
				t.Errorf("parseSuppressionComment(%q) ok=%v, want %v", tc.line, ok, tc.wantOK)
			}
		})
	}
}
```

Add to `internal/suppress/suppress_test.go`:

```go
func TestApply_WildcardCheckRejected(t *testing.T) {
	findings := []model.Finding{
		{Title: "SQL injection", SourceTrack: "appsec"},
		{Title: "Hardcoded key", SourceTrack: "hardcoded_credentials"},
	}

	// File rule with check="*" should be rejected (not match anything)
	rules := []Rule{
		{Check: "*", Reason: "blanket suppress"},
	}
	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 2 {
		t.Fatalf("expected 2 active (wildcard rejected), got %d", len(active))
	}
	if len(suppressed) != 0 {
		t.Fatalf("expected 0 suppressed, got %d", len(suppressed))
	}
}

func TestApply_WildcardTitleRejected(t *testing.T) {
	findings := []model.Finding{
		{Title: "SQL injection", SourceTrack: "appsec"},
	}

	rules := []Rule{
		{Title: "*", Reason: "blanket suppress"},
	}
	active, suppressed := Apply(findings, rules, nil)
	if len(active) != 1 {
		t.Fatalf("expected 1 active (wildcard title rejected), got %d", len(active))
	}
	if len(suppressed) != 0 {
		t.Fatalf("expected 0 suppressed, got %d", len(suppressed))
	}
}

func TestApply_InlineWildcardRejected(t *testing.T) {
	findings := []model.Finding{
		{Title: "Key found", SourceTrack: "hardcoded_credentials", FileRefs: []string{"config.go"}},
	}

	inline := map[string][]InlineSuppression{
		"config.go": {
			{CheckID: "*", Reason: "suppress all", File: "config.go", Line: 5},
		},
	}

	active, suppressed := Apply(findings, nil, inline)
	if len(active) != 1 {
		t.Fatalf("expected 1 active (inline wildcard rejected), got %d", len(active))
	}
	if len(suppressed) != 0 {
		t.Fatalf("expected 0 suppressed, got %d", len(suppressed))
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test -run 'TestParseSuppressionComment_RejectsWildcard|TestApply_WildcardCheckRejected|TestApply_WildcardTitleRejected|TestApply_InlineWildcardRejected' ./internal/suppress/`
Expected: FAIL — wildcards currently accepted

**Step 3: Implement the fixes**

1. In `internal/suppress/inline.go`, in `parseSuppressionComment` (line 121-125), add wildcard rejection before the final return:

```go
	if checkID == "" {
		return "", "", false
	}
	// Reject standalone wildcard — use specific check IDs.
	if checkID == "*" {
		fmt.Fprintf(os.Stderr, "[governor] warning: ignoring wildcard suppression 'governor:suppress *' — use specific check IDs\n")
		return "", "", false
	}
	return checkID, reason, true
```

Add `"fmt"` and `"os"` to imports.

2. In `internal/suppress/suppress.go`, in `ruleMatches` (line 82-105), add wildcard rejection at the top:

```go
func ruleMatches(f model.Finding, r Rule) bool {
	// Reject standalone wildcard check or title — too broad.
	if r.Check == "*" || r.Title == "*" {
		return false
	}
	// ... rest unchanged
}
```

3. In `internal/suppress/suppress.go`, in `matchInline` (line 122), change the wildcard acceptance to rejection:

```go
for _, s := range suppressions {
	if s.CheckID == "*" {
		continue // wildcard rejected
	}
	if matchGlob(s.CheckID, f.SourceTrack) {
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/suppress/`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/suppress/inline.go internal/suppress/suppress.go internal/suppress/inline_test.go internal/suppress/suppress_test.go
git commit -m "fix(suppress): ban standalone wildcard suppression check IDs"
```

---

### Task 5: Fix 3b — Require reason on file-based suppressions

**Files:**
- Modify: `internal/suppress/suppress.go:21-38` (Load function)
- Test: `internal/suppress/suppress_test.go`

**Step 1: Write the failing test**

Add to `internal/suppress/suppress_test.go`:

```go
func TestLoad_MissingReasonReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")
	content := `suppressions:
  - check: hardcoded_credentials
    files: "tests/**"
    reason: "Test fixtures"
  - title: "Hardcoded API key*"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for rule without reason")
	}
	if !strings.Contains(err.Error(), "reason is required") {
		t.Fatalf("expected 'reason is required' error, got: %v", err)
	}
}

func TestLoad_AllReasonsPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")
	content := `suppressions:
  - check: hardcoded_credentials
    files: "tests/**"
    reason: "Test fixtures"
  - title: "Hardcoded API key*"
    reason: "False positive"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}
```

Add `"strings"` to imports if not already present.

**Step 2: Run test to verify it fails**

Run: `go test -run 'TestLoad_MissingReasonReturnsError|TestLoad_AllReasonsPresent' ./internal/suppress/`
Expected: FAIL — Load currently accepts rules without reasons

**Step 3: Implement the validation**

In `internal/suppress/suppress.go`, in the `Load` function (line 21-38), add validation after unmarshalling:

```go
func Load(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, nil
	}
	var sf suppressionsFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, err
	}
	for i, rule := range sf.Suppressions {
		if strings.TrimSpace(rule.Reason) == "" {
			return nil, fmt.Errorf("suppression rule %d: reason is required", i+1)
		}
	}
	return sf.Suppressions, nil
}
```

Add `"fmt"` to imports if not already present.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/suppress/`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/suppress/suppress.go internal/suppress/suppress_test.go
git commit -m "fix(suppress): require reason field on file-based suppression rules"
```

---

### Task 6: Fix 3c — Suppression ratio warning

**Files:**
- Modify: `internal/app/audit.go:276-291` (after Apply call)
- Test: `internal/app/audit.go` (or add a helper test)

**Step 1: Write the failing test**

Since the suppression ratio check is internal to `RunAudit`, we'll extract it as a testable helper. Add to `internal/app/audit.go` and test in a new file `internal/app/suppression_ratio_test.go`:

Create `internal/app/suppression_ratio_test.go`:

```go
package app

import "testing"

func TestCheckSuppressionRatio(t *testing.T) {
	tests := []struct {
		name           string
		active         int
		suppressed     int
		wantWarning    bool
	}{
		{"no findings", 0, 0, false},
		{"all active", 10, 0, false},
		{"below threshold", 8, 2, false},
		{"at threshold 50%", 5, 5, true},
		{"above threshold", 2, 8, true},
		{"100% suppressed", 0, 10, true},
		{"high ratio but low count", 1, 3, false}, // suppressed < 5
		{"exactly 5 suppressed at 50%", 5, 5, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			warning := checkSuppressionRatio(tc.active, tc.suppressed)
			if (warning != "") != tc.wantWarning {
				t.Errorf("checkSuppressionRatio(%d, %d) warning=%q, wantWarning=%v", tc.active, tc.suppressed, warning, tc.wantWarning)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestCheckSuppressionRatio ./internal/app/`
Expected: FAIL — function doesn't exist

**Step 3: Implement the helper and integrate it**

Add to `internal/app/audit.go` (after the `loadSuppressions` function):

```go
// checkSuppressionRatio returns a warning message if the suppression ratio is
// suspiciously high (>50% and at least 5 suppressed). Returns "" if no warning.
func checkSuppressionRatio(activeCount, suppressedCount int) string {
	total := activeCount + suppressedCount
	if total == 0 || suppressedCount < 5 {
		return ""
	}
	ratio := float64(suppressedCount) / float64(total)
	if ratio > 0.5 {
		return fmt.Sprintf("%.0f%% of findings are suppressed (%d/%d) — review suppressions for overly broad rules", ratio*100, suppressedCount, total)
	}
	return ""
}
```

In `RunAudit`, after the suppression apply block (around line 290), add:

```go
if warning := checkSuppressionRatio(len(findings), len(suppressedFindings)); warning != "" {
	runWarnings = append(runWarnings, warning)
	sink.Emit(progress.Event{
		Type:    progress.EventRunWarning,
		RunID:   runID,
		Status:  "warning",
		Message: warning,
	})
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/app/`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/app/audit.go internal/app/suppression_ratio_test.go
git commit -m "feat(audit): warn when suppression ratio exceeds 50%"
```

---

### Task 7: Fix 3d — `--max-suppression-ratio` flag for CI

**Files:**
- Modify: `cmd/cli.go:2124-2335` (runCI function)
- Test: `cmd/cli_test.go` (or dedicated test)

**Step 1: Write the failing test**

Add to an appropriate test file. Since `checkFailOn` is in `cmd/cli.go`, add a test for a new `checkSuppressionRatioCI` function. Create or add to `cmd/cli_suppression_test.go`:

```go
package cmd

import (
	"testing"

	"governor/internal/model"
)

func TestCheckSuppressionRatioCI(t *testing.T) {
	tests := []struct {
		name      string
		maxRatio  float64
		report    model.AuditReport
		wantErr   bool
	}{
		{
			"disabled (1.0)",
			1.0,
			model.AuditReport{
				Findings:        make([]model.Finding, 0),
				SuppressedCount: 100,
			},
			false,
		},
		{
			"below threshold",
			0.5,
			model.AuditReport{
				Findings:        make([]model.Finding, 8),
				SuppressedCount: 2,
			},
			false,
		},
		{
			"exceeds threshold",
			0.3,
			model.AuditReport{
				Findings:        make([]model.Finding, 2),
				SuppressedCount: 8,
			},
			true,
		},
		{
			"no findings at all",
			0.5,
			model.AuditReport{
				Findings:        nil,
				SuppressedCount: 0,
			},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSuppressionRatioCI(tc.maxRatio, tc.report)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkSuppressionRatioCI(%f, ...) err=%v, wantErr=%v", tc.maxRatio, err, tc.wantErr)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestCheckSuppressionRatioCI ./cmd/`
Expected: FAIL — function doesn't exist

**Step 3: Implement the function and CLI flag**

1. Add the function to `cmd/cli.go` (near `checkFailOn`):

```go
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
```

2. In `runCI` (line 2124), add the flag:

```go
maxSuppressionRatio := fs.Float64("max-suppression-ratio", 1.0, "Fail if suppression ratio exceeds threshold (0.0-1.0, default 1.0=disabled)")
```

3. After the `checkFailOn` call (around line 2329), add:

```go
if ratioErr := checkSuppressionRatioCI(*maxSuppressionRatio, report); ratioErr != nil {
	fmt.Fprintf(os.Stderr, "%v\n", ratioErr)
	os.Exit(1)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./cmd/`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/cli.go cmd/cli_suppression_test.go
git commit -m "feat(ci): add --max-suppression-ratio flag for CI enforcement"
```

---

### Task 8: Final verification

**Step 1: Run full test suite**

```bash
make test
```

Expected: all tests pass

**Step 2: Run linter**

```bash
golangci-lint run ./...
```

Expected: no issues

**Step 3: Build and verify help**

```bash
make build && bin/governor --help
bin/governor ci --help 2>&1 | grep max-suppression-ratio
bin/governor audit --help 2>&1 | grep max-rule-file-bytes
```

Expected: new flags visible in help output

**Step 4: Commit any remaining fixes**

If lint or build caught anything, fix and commit.
