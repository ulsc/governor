# Vibe-Coding Check Library & Security Badge — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 10 vibe-coding-specific built-in security checks, a tap/pack system for installable check packs, and a `governor badge` command that generates letter-grade SVG/JSON badges from audit results.

**Architecture:** Three independent features sharing only the `cmd/cli.go` entry point. Built-in checks extend `internal/checks/builtin.go`. The tap/pack system lives in a new `internal/taps/` package. The badge system lives in a new `internal/badge/` package. Each feature is independently testable and deployable.

**Tech Stack:** Go 1.22+, `os/exec` for git operations in taps, `encoding/json` for shields.io output, `fmt.Sprintf` for SVG generation, `gopkg.in/yaml.v3` for tap config.

**NOTE:** The `unsafe_html_rendering` check detects React's dangerous HTML rendering API and Vue's v-html directive. When implementing detector regex patterns, reference the actual API names from the React/Vue documentation. These patterns exist in `builtin.go` as string literals inside regex detector definitions.

---

## Task 1: Add Vibe-Coding Rule-Engine Built-in Checks (Part 1 — 4 checks)

**Files:**
- Modify: `internal/checks/builtin.go` (append to `Builtins()` return slice)
- Test: `internal/checks/builtin_test.go` (existing tests validate all builtins automatically)

**Step 1: Write test for new check count**

Add to `internal/checks/builtin_test.go`:

```go
func TestBuiltins_VibeCodeChecksExist(t *testing.T) {
	vibeCheckIDs := []string{
		"missing_auth_middleware",
		"exposed_env_in_client",
		"permissive_cors",
		"missing_input_validation",
	}
	for _, id := range vibeCheckIDs {
		if _, ok := builtinByID(id); !ok {
			t.Fatalf("expected vibe-coding builtin %q to exist", id)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/checks/ -run TestBuiltins_VibeCodeChecksExist -v`
Expected: FAIL — checks don't exist yet.

**Step 3: Add 4 rule-engine checks to `builtin.go`**

Append these to the `Builtins()` return slice. Each follows the existing pattern — `Definition` struct with `APIVersion`, `ID`, `Name`, `Status: StatusEnabled`, `Source: SourceBuiltin`, `Engine: EngineRule`, `Rule` with detectors, `Scope` with globs, CWE/OWASP refs, and `Origin{Method: "builtin"}`.

Add a section comment: `// -- Vibe-coding rule-engine checks --`

**Check 1: `missing_auth_middleware`**
- Detectors: `express-unprotected-route` (regex for `app.post/put/delete/patch` without middleware), `nextjs-unprotected-api-route` (regex for exported POST/PUT/DELETE/PATCH functions), `fastapi-unprotected-route` (regex for `@app.post` without `Depends`)
- Scope: `**/*.js`, `**/*.ts`, `**/*.jsx`, `**/*.tsx`, `**/*.py`
- Severity: high, CWE-306, OWASP A07:2021
- Categories: `auth`, `vibe_coding`

**Check 2: `exposed_env_in_client`**
- Detectors: `next-public-secret` (regex for `NEXT_PUBLIC_*SECRET*`), `vite-public-secret` (regex for `VITE_*SECRET*`), `react-app-secret` (regex for `REACT_APP_*SECRET*`)
- Scope: `**/*.env`, `**/*.env.*`, `**/*.js`, `**/*.ts`, `**/*.yaml`, `**/*.json`
- Severity: critical, CWE-200, OWASP A01:2021
- Categories: `secrets`, `vibe_coding`

**Check 3: `permissive_cors`**
- Detectors: `cors-wildcard-origin` (regex for `origin: '*'`), `cors-middleware-wildcard` (regex for `cors()`), `fastapi-cors-wildcard` (regex for `allow_origins=['*']`)
- Scope: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.go`, etc.
- Severity: medium, CWE-942, OWASP A05:2021
- Categories: `configuration`, `vibe_coding`

**Check 4: `missing_input_validation`**
- Detectors: `req-body-to-db-js` (regex for `.create(req.body)`), `req-body-to-db-py` (regex for `.insert_one(request.json)`), `spread-req-body` (regex for `{...req.body}`)
- Scope: `**/*.js`, `**/*.ts`, `**/*.py`
- Severity: high, CWE-20, OWASP A03:2021
- Categories: `input_validation`, `vibe_coding`

All checks MUST include `**/checks/builtin.go` in `ExcludeGlobs` to prevent self-matches.

**Step 4: Run all builtin tests to verify they pass**

Run: `go test ./internal/checks/ -run TestBuiltins -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/checks/builtin.go internal/checks/builtin_test.go
git commit -m "feat(checks): add vibe-coding rule checks part 1 — auth, env, cors, validation"
```

---

## Task 2: Add Vibe-Coding Rule-Engine Built-in Checks (Part 2 — 4 checks)

**Files:**
- Modify: `internal/checks/builtin.go`
- Modify: `internal/checks/builtin_test.go`

**Step 1: Write test for remaining rule checks**

Add to `internal/checks/builtin_test.go`:

```go
func TestBuiltins_VibeCodeChecksExistPart2(t *testing.T) {
	vibeCheckIDs := []string{
		"insecure_jwt",
		"missing_helmet_headers",
		"unsafe_html_rendering",
		"unprotected_api_keys_frontend",
	}
	for _, id := range vibeCheckIDs {
		if _, ok := builtinByID(id); !ok {
			t.Fatalf("expected vibe-coding builtin %q to exist", id)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/checks/ -run TestBuiltins_VibeCodeChecksExistPart2 -v`
Expected: FAIL

**Step 3: Add 4 more rule-engine checks to `builtin.go`**

**Check 5: `insecure_jwt`**
- Detectors: `jwt-none-algorithm` (regex for `algorithm: 'none'`), `jwt-verify-disabled` (regex for `verify: false`), `jwt-hardcoded-secret` (regex for jwt.sign with literal string secret)
- Scope: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.go`, `**/*.java`
- Severity: critical, CWE-347, OWASP A02:2021
- Categories: `auth`, `secrets`, `vibe_coding`

**Check 6: `missing_helmet_headers`**
- Detectors: `express-no-helmet` (multiline regex for express require/import through .listen without helmet)
- Scope: `**/*.js`, `**/*.ts`
- Severity: medium, CWE-693, OWASP A05:2021, Confidence: 0.5
- Categories: `configuration`, `vibe_coding`

**Check 7: `unsafe_html_rendering`**
- Detectors: `react-dangerous-html-variable` (regex for React's dangerous HTML setter with variable __html), `vue-v-html-variable` (regex for Vue v-html with variable binding)
- Scope: `**/*.jsx`, `**/*.tsx`, `**/*.vue`, `**/*.svelte`
- Severity: high, CWE-79, OWASP A03:2021
- Categories: `xss`, `vibe_coding`

**Check 8: `unprotected_api_keys_frontend`**
- Detectors: `frontend-api-key-assignment` (regex for api_key/secret assignments with 20+ char values), `frontend-supabase-key` (regex for supabase JWT tokens), `frontend-firebase-key` (regex for firebase config with apiKey)
- Scope: `**/*.jsx`, `**/*.tsx`, `**/*.vue`, `**/*.svelte`, `**/*.js`, `**/*.ts` (exclude `**/server/**`, `**/api/**`, `**/backend/**`)
- Severity: critical, CWE-200, OWASP A01:2021
- Categories: `secrets`, `vibe_coding`

All checks MUST include `**/checks/builtin.go` in `ExcludeGlobs`.

**Step 4: Run all builtin tests**

Run: `go test ./internal/checks/ -run TestBuiltins -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/checks/builtin.go internal/checks/builtin_test.go
git commit -m "feat(checks): add vibe-coding rule checks part 2 — jwt, headers, html, frontend keys"
```

---

## Task 3: Add Vibe-Coding AI-Engine Built-in Checks (2 checks)

**Files:**
- Modify: `internal/checks/builtin.go`
- Modify: `internal/checks/builtin_test.go`

**Step 1: Write test for AI checks**

Add to `internal/checks/builtin_test.go`:

```go
func TestBuiltins_VibeCodeAIChecksExist(t *testing.T) {
	aiCheckIDs := []string{
		"missing_rls_policies",
		"insecure_defaults",
	}
	for _, id := range aiCheckIDs {
		def, ok := builtinByID(id)
		if !ok {
			t.Fatalf("expected vibe-coding AI builtin %q to exist", id)
		}
		if def.Engine != EngineAI {
			t.Fatalf("expected %q to use AI engine, got %q", id, def.Engine)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/checks/ -run TestBuiltins_VibeCodeAIChecksExist -v`
Expected: FAIL

**Step 3: Add 2 AI-engine checks to `builtin.go`**

Add a section comment: `// -- Vibe-coding AI-engine checks --`

**Check 9: `missing_rls_policies`**
- Engine: AI
- Instructions: Focus on SQL migration files without `ENABLE ROW LEVEL SECURITY`, Supabase projects lacking RLS policies, tables with user data missing `CREATE POLICY` statements, `.from('table')` calls without RLS enforcement
- Scope: `**/*.sql`, `**/supabase/**`, `**/*.ts`, `**/*.js`
- CWE-862, OWASP A01:2021
- Categories: `auth`, `data_exposure`, `vibe_coding`

**Check 10: `insecure_defaults`**
- Engine: AI
- Instructions: Focus on `DEBUG=True`, `app.debug=True`, `NODE_ENV=development` in prod configs, default creds (admin/admin), insecure session cookies, missing HTTPS enforcement, default Django SECRET_KEY, verbose error output exposing internals
- Scope: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.go`, `**/*.yaml`, `**/*.env`, `**/Dockerfile`
- CWE-1188, OWASP A05:2021
- Categories: `configuration`, `vibe_coding`

**Step 4: Run all builtin tests**

Run: `go test ./internal/checks/ -run TestBuiltins -v`
Expected: ALL PASS

**Step 5: Run full test suite to check for regressions**

Run: `go test ./... -count=1`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add internal/checks/builtin.go internal/checks/builtin_test.go
git commit -m "feat(checks): add vibe-coding AI checks — RLS policies and insecure defaults"
```

---

## Task 4: Badge Grading Logic

**Files:**
- Create: `internal/badge/grade.go`
- Create: `internal/badge/grade_test.go`

**Step 1: Write failing tests for grading logic**

Create `internal/badge/grade_test.go`:

```go
package badge

import "testing"

func TestGrade(t *testing.T) {
	tests := []struct {
		name     string
		critical int
		high     int
		medium   int
		low      int
		want     string
		color    string
	}{
		{"zero findings", 0, 0, 0, 0, "A+", "brightgreen"},
		{"only low", 0, 0, 0, 5, "A", "green"},
		{"only medium", 0, 0, 3, 0, "A", "green"},
		{"one high", 0, 1, 0, 0, "B", "yellowgreen"},
		{"three high", 0, 3, 0, 0, "B", "yellowgreen"},
		{"four high", 0, 4, 0, 0, "C", "yellow"},
		{"ten high", 0, 10, 0, 0, "C", "yellow"},
		{"one critical", 1, 0, 0, 0, "D", "orange"},
		{"three critical", 3, 0, 0, 0, "D", "orange"},
		{"four critical", 4, 0, 0, 0, "F", "red"},
		{"mixed high severity", 0, 2, 5, 3, "B", "yellowgreen"},
		{"mixed with critical", 2, 5, 3, 1, "D", "orange"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counts := map[string]int{
				"critical": tt.critical,
				"high":     tt.high,
				"medium":   tt.medium,
				"low":      tt.low,
			}
			grade, color := Grade(counts)
			if grade != tt.want {
				t.Errorf("Grade() = %q, want %q", grade, tt.want)
			}
			if color != tt.color {
				t.Errorf("Color() = %q, want %q", color, tt.color)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/badge/ -run TestGrade -v`
Expected: FAIL — package doesn't exist yet.

**Step 3: Implement grading logic**

Create `internal/badge/grade.go`:

```go
package badge

// Grade computes a letter grade and badge color from finding severity counts.
// Only the grade and color are returned — no finding details leak into the badge.
func Grade(countsBySeverity map[string]int) (grade string, color string) {
	critical := countsBySeverity["critical"]
	high := countsBySeverity["high"]
	total := 0
	for _, c := range countsBySeverity {
		total += c
	}

	switch {
	case total == 0:
		return "A+", "brightgreen"
	case critical == 0 && high == 0:
		return "A", "green"
	case critical == 0 && high <= 3:
		return "B", "yellowgreen"
	case critical == 0:
		return "C", "yellow"
	case critical <= 3:
		return "D", "orange"
	default:
		return "F", "red"
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/badge/ -run TestGrade -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/badge/grade.go internal/badge/grade_test.go
git commit -m "feat(badge): add letter-grade computation from severity counts"
```

---

## Task 5: Badge SVG Generation

**Files:**
- Create: `internal/badge/svg.go`
- Create: `internal/badge/svg_test.go`

**Step 1: Write failing test for SVG generation**

Create `internal/badge/svg_test.go`:

```go
package badge

import (
	"strings"
	"testing"
)

func TestRenderSVG(t *testing.T) {
	svg := RenderSVG("governor", "A+", "brightgreen", StyleFlat)

	if !strings.Contains(svg, "<svg") {
		t.Error("expected SVG output to contain <svg tag")
	}
	if !strings.Contains(svg, "governor") {
		t.Error("expected SVG to contain label text")
	}
	if !strings.Contains(svg, "A+") {
		t.Error("expected SVG to contain grade text")
	}
	if !strings.Contains(svg, "</svg>") {
		t.Error("expected SVG to be properly closed")
	}
}

func TestRenderSVG_FlatSquare(t *testing.T) {
	svg := RenderSVG("governor", "F", "red", StyleFlatSquare)

	if !strings.Contains(svg, "<svg") {
		t.Error("expected SVG output")
	}
	// flat-square should use rx="0" not rounded corners
	if !strings.Contains(svg, `rx="0"`) {
		t.Error("flat-square style should have rx=0")
	}
}

func TestRenderSVG_CustomLabel(t *testing.T) {
	svg := RenderSVG("security", "B", "yellowgreen", StyleFlat)

	if !strings.Contains(svg, "security") {
		t.Error("expected SVG to contain custom label")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/badge/ -run TestRenderSVG -v`
Expected: FAIL

**Step 3: Implement SVG rendering**

Create `internal/badge/svg.go` with:
- `Style` type (constants `StyleFlat`, `StyleFlatSquare`)
- `ParseStyle(s string) Style` — parse user input, default to flat
- `hexForColor` map: brightgreen=#4c1, green=#97ca00, yellowgreen=#a4a61d, yellow=#dfb317, orange=#fe7d37, red=#e05d44
- `RenderSVG(label, grade, color string, style Style) string` — generates shields.io-compatible flat SVG badge using `fmt.Sprintf` with an SVG template string. Label width = `len(label)*6.5+10`, grade width = `len(grade)*7.5+10`. rx=3 for flat, rx=0 for flat-square.

**Step 4: Run tests**

Run: `go test ./internal/badge/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/badge/svg.go internal/badge/svg_test.go
git commit -m "feat(badge): add SVG badge rendering with flat and flat-square styles"
```

---

## Task 6: Badge Shields.io JSON Output

**Files:**
- Create: `internal/badge/shields.go`
- Create: `internal/badge/shields_test.go`

**Step 1: Write failing test**

Create `internal/badge/shields_test.go`:

```go
package badge

import (
	"encoding/json"
	"testing"
)

func TestShieldsJSON(t *testing.T) {
	out := ShieldsJSON("governor", "A", "green")

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("expected valid JSON, got error: %v", err)
	}

	if result["schemaVersion"] != float64(1) {
		t.Errorf("schemaVersion = %v, want 1", result["schemaVersion"])
	}
	if result["label"] != "governor" {
		t.Errorf("label = %v, want governor", result["label"])
	}
	if result["message"] != "A" {
		t.Errorf("message = %v, want A", result["message"])
	}
	if result["color"] != "green" {
		t.Errorf("color = %v, want green", result["color"])
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/badge/ -run TestShieldsJSON -v`
Expected: FAIL

**Step 3: Implement shields JSON output**

Create `internal/badge/shields.go` with:
- `shieldsEndpoint` struct: SchemaVersion int, Label string, Message string, Color string
- `ShieldsJSON(label, grade, color string) string` — marshal to indented JSON

**Step 4: Run all badge tests**

Run: `go test ./internal/badge/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/badge/shields.go internal/badge/shields_test.go
git commit -m "feat(badge): add shields.io JSON endpoint output"
```

---

## Task 7: Badge CLI Command

**Files:**
- Modify: `cmd/cli.go` (add `badge` case to `Execute` switch, add `runBadge` function, update `printUsage`)

**Step 1: Add badge command to CLI dispatch**

In `cmd/cli.go` `Execute` function, add after the `scan` case:
```go
case "badge":
    return runBadge(args[1:])
```

Add import: `"governor/internal/badge"`

**Step 2: Implement `runBadge` function**

```go
func runBadge(args []string) error {
    // FlagSet with: --out, --format (svg|shields-json), --style (flat|flat-square), --label
    // Parse positional arg as audit.json path
    // Read and json.Unmarshal into model.AuditReport
    // Call badge.Grade(report.CountsBySeverity) -> grade, color
    // Switch on format: badge.RenderSVG or badge.ShieldsJSON
    // Default output path: governor-badge.svg or governor-badge.json
    // os.WriteFile the content
    // Print: "badge: <label> (grade <grade>) -> <path>"
}
```

**Step 3: Update `printUsage`**

Add: `fmt.Println("  governor badge <audit.json> [flags]")`

**Step 4: Build and test**

Run: `go build -o /dev/null . && go test ./... -count=1`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add cmd/cli.go
git commit -m "feat(badge): add governor badge CLI command"
```

---

## Task 8: Tap/Pack System — Core Types and Config

**Files:**
- Create: `internal/taps/types.go`
- Create: `internal/taps/config.go`
- Create: `internal/taps/config_test.go`

**Step 1: Write failing tests for config operations**

Create `internal/taps/config_test.go` with tests for:
- `TestLoadConfig_EmptyWhenMissing` — returns empty config when file doesn't exist
- `TestSaveAndLoadConfig` — round-trip save/load preserves tap data
- `TestResolveURL_GitHubShorthand` — `acme/checks` -> `https://github.com/acme/checks.git`
- `TestResolveURL_FullURLPassthrough` — full git/https URLs pass through unchanged
- `TestFindTap` and `TestRemoveTap` — lookup and removal operations

**Step 2: Run tests to verify failure**

Run: `go test ./internal/taps/ -v`
Expected: FAIL

**Step 3: Implement types and config**

Create `internal/taps/types.go`:
- `Tap` struct: Name, URL, Path, AddedAt
- `Config` struct: Taps []Tap
- `PackMeta` struct: Name, Description, Version, Author

Create `internal/taps/config.go`:
- `DefaultConfigPath()` -> `~/.governor/taps.yaml`
- `DefaultTapsDir()` -> `~/.governor/taps/`
- `LoadConfig(path)` -> reads YAML, returns empty config if missing
- `SaveConfig(path, cfg)` -> writes YAML with MkdirAll
- `ResolveSource(input)` -> returns (name, url), converts GitHub shorthand to HTTPS URL
- `FindTap(cfg, name)` -> case-insensitive lookup
- `RemoveTap(cfg, name)` -> removes by name, returns bool

**Step 4: Run tests**

Run: `go test ./internal/taps/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/taps/types.go internal/taps/config.go internal/taps/config_test.go
git commit -m "feat(taps): add tap config types, load/save, and source resolution"
```

---

## Task 9: Tap/Pack System — Git Operations and Pack Management

**Files:**
- Create: `internal/taps/git.go`
- Create: `internal/taps/git_test.go`

**Step 1: Write failing tests**

Create `internal/taps/git_test.go` with tests for:
- `TestCloneTap_InvalidURL` — expects error for invalid git URL
- `TestListPacks_EmptyDir` — returns empty for dir with no packs
- `TestListPacks_WithPacks` — finds packs with metadata from pack.yaml
- `TestCopyPackChecks` — copies .check.yaml files to destination dir

**Step 2: Run tests to verify failure**

Run: `go test ./internal/taps/ -run TestCloneTap -v`
Expected: FAIL

**Step 3: Implement git operations**

Create `internal/taps/git.go`:
- `CloneTap(url, destDir)` — `git clone --depth=1`
- `UpdateTap(tapDir)` — `git -C <dir> pull --ff-only`
- `ListPacks(tapDir)` — reads `packs/` subdirectories, loads `pack.yaml` metadata
- `FindPack(tapDir, packName)` — checks if `packs/<name>/` exists
- `CopyPackChecks(packDir, destDir)` — copies all `.check.yaml` files
- `copyFile(src, dst)` — helper using io.Copy

**Step 4: Run tests**

Run: `go test ./internal/taps/ -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/taps/git.go internal/taps/git_test.go
git commit -m "feat(taps): add git clone/pull, pack listing, and check file copying"
```

---

## Task 10: Tap/Pack CLI Commands

**Files:**
- Modify: `cmd/cli.go`

**Step 1: Add new subcommands to `runChecks` dispatch**

Add cases to the `runChecks` switch: `tap`, `untap`, `install-pack`, `list-packs`.
Add import: `"governor/internal/taps"`

**Step 2: Implement `runChecksTap`**
- FlagSet with `--list` and `--update`
- `--list`: print all registered taps
- `--update`: `git pull` all taps
- Positional arg: `ResolveSource`, `CloneTap` to `~/.governor/taps/<name>`, append to config

**Step 3: Implement `runChecksUntap`**
- Takes one positional arg (tap name)
- Finds tap, `os.RemoveAll` the clone dir, removes from config

**Step 4: Implement `runChecksInstallPack`**
- Takes one positional arg: `[source/]pack-name`
- Searches taps for pack, `CopyPackChecks` to `.governor/checks/`
- Prints count of installed checks

**Step 5: Implement `runChecksListPacks`**
- Iterates all taps, calls `ListPacks`, prints source/name/description table

**Step 6: Update `printUsage`**

Add lines for `tap`, `untap`, `install-pack`, `list-packs`.

**Step 7: Build and test**

Run: `go build -o /dev/null . && go test ./... -count=1`
Expected: ALL PASS

**Step 8: Commit**

```bash
git add cmd/cli.go
git commit -m "feat(checks): add tap, untap, install-pack, and list-packs CLI commands"
```

---

## Task 11: Lint and Full Test Suite

**Step 1: Run linter**

Run: `golangci-lint run ./...`
Expected: No issues

**Step 2: Run full test suite with race detector**

Run: `go test -race ./... -count=1`
Expected: ALL PASS

**Step 3: Fix any issues found**

Address any lint or test failures.

**Step 4: Build binary and verify new commands**

Run: `go build -o bin/governor . && bin/governor --help`
Expected: Help output includes `badge` and updated `checks` subcommands.

**Step 5: Commit any fixes**

```bash
git add -A
git commit -m "chore: fix lint and test issues for vibe-coding checks and badge features"
```

---

## Task 12: Verify Features End-to-End

**Step 1: Test badge command with a real audit.json**

Find an existing audit.json or create a minimal test fixture and run:
```bash
bin/governor badge <path-to-audit.json>
```
Verify `governor-badge.svg` is created and renders correctly.

**Step 2: Test badge with shields-json format**

```bash
bin/governor badge <path-to-audit.json> --format shields-json
```
Verify `governor-badge.json` contains valid shields.io endpoint JSON.

**Step 3: Test new checks with governor scan**

Create a test file with a known vibe-coding vulnerability and scan it:
```bash
echo 'const apiKey = "sk-1234567890abcdef1234567890abcdef"' > /tmp/test-vibe.js
bin/governor scan /tmp/test-vibe.js
```

**Step 4: Run quick audit to verify new checks appear**

```bash
bin/governor audit . --quick --only-check missing_auth_middleware,exposed_env_in_client,permissive_cors
```

**Step 5: Commit final state**

```bash
git add -A
git commit -m "feat: add vibe-coding check library, tap/pack system, and security badge command"
```
