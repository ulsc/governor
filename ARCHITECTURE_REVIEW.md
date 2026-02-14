# Architecture Review: Governor

## Overview

Governor is a well-structured Go CLI with approximately 4,700 lines of production code across 18 internal packages. The architecture follows clean separation between CLI plumbing, domain logic, and execution infrastructure. This review identifies areas of strength and concrete improvement opportunities.

## 1. Package Dependency Analysis

### Dependency Graph (simplified)

```
main.go -> cmd/cli.go
cmd -> ai, app, checks, checkstui, config, extractor,
       intake, isolation, model, progress, trust, tui, worker

app/audit.go -> ai, checks, diff, intake, model, progress,
                prompt, redact, report, safefile, worker

worker/runner.go -> ai, checks, envsafe, model, progress,
                    prompt, redact, safefile

report/render.go -> model, redact, safefile
intake/intake.go -> model, safefile
prompt/templates.go -> checks, model, sanitize
checks/* -> (leaf: no internal deps except model via types)
ai/runtime.go -> (leaf: yaml only)
ai/execute.go -> envsafe, safefile
```

### Assessment

**No circular dependencies.** The dependency graph forms a clean DAG:
- `model` is a true leaf package (no internal imports)
- `checks`, `redact`, `safefile`, `sanitize`, `envsafe`, `progress` are near-leaves
- `worker` and `app` are the highest-level internal packages
- `cmd` is the composition root, importing nearly everything

**Unnecessary dependency: `cmd` imports `worker` directly.** The CLI constructs `worker.RunOptions` directly in `runChecksTest()` (line 1312). This couples the CLI layer to worker internals. The `checks test` subcommand should be wrapped in an `app`-level function (similar to `app.RunAudit`) to keep `cmd` one layer removed from execution details.

## 2. cmd/cli.go Thickness

At 1,813 lines, `cmd/cli.go` is the largest file in the codebase. It handles:
- Flag definition and parsing for 6+ subcommands
- Positional argument parsing with pre/post flag extraction
- Config file merging via `applyConfig()`
- Validation of flag values
- AI runtime resolution
- AI binary trust resolution
- TUI mode selection
- Output formatting (`printAuditSummary`, `printIsolateArtifactPaths`)
- Interactive prompt flows (`runCheckCreateFlow`, `promptInput`)
- Enum normalization functions (7 `normalize*Flag` functions)

### Recommendations

**A. Extract flag normalization into a dedicated `flagutil` or move to respective packages.**
The 7 `normalize*Flag` functions (`normalizeExecutionModeFlag`, `normalizeSandboxModeFlag`, `normalizeIsolationRuntimeFlag`, etc.) are pure validation logic. The `worker` package already has its own `normalizeExecutionMode` and `normalizeSandboxMode`. These should be consolidated -- either as exported functions in `worker`/`isolation` or in a shared `flagutil` helper.

**B. Extract the check creation flow.**
`runCheckCreateFlow` (lines 1386-1547) is 160 lines of template resolution, interactive prompting, and definition assembly. This is domain logic, not CLI wiring. Move to `checks.CreateFromInput(input)` or similar.

**C. Extract `printAuditSummary` into `report` package.**
The summary printer (lines 460-527) knows about the full `AuditReport` shape and formatting. It belongs in `report.PrintSummary(w io.Writer, report, paths)` alongside the other renderers.

**D. Consider splitting `runAudit` and `runIsolateAudit`.**
These two functions are 240 and 150 lines respectively. They share significant flag overlap (AI flags, check flags, worker flags). An `auditFlagSet` helper struct could reduce duplication.

## 3. Duplicated Code Patterns

### Severity weight/rank functions

The same `severityWeight` / `severityRank` function appears in:
- `cmd/cli.go:596` (`severityWeightMap` + `countAtOrAbove`)
- `internal/app/audit.go:456` (`severityWeight`)
- `internal/report/render.go:685` (`severityRank`)
- `internal/diff/diff.go:93` (`severityWeight`)

**Recommendation:** Consolidate into `model.SeverityWeight(sev string) int` since severity is a domain concept defined in `model.Finding`.

### Finding dedup key generation

`app/audit.go:422` (`dedupeKey`) and `diff/diff.go:70` (`findingKey`) are nearly identical:

```go
// app/audit.go
func dedupeKey(f model.Finding) string {
    refs := append([]string{}, f.FileRefs...)
    sort.Strings(refs)
    evidence := strings.ToLower(strings.TrimSpace(f.Evidence))
    if len(evidence) > 200 { evidence = evidence[:200] }
    return strings.ToLower(strings.TrimSpace(f.Title)) + "|" +
        strings.ToLower(strings.TrimSpace(f.Category)) + "|" +
        strings.Join(refs, ",") + "|" + evidence
}

// diff/diff.go
func findingKey(f model.Finding) string {
    // identical implementation
}
```

**Recommendation:** Add `model.FindingKey(f Finding) string` and use it everywhere.

### Redaction applied in multiple layers

Secret redaction happens in:
1. `worker/runner.go:normalizeFindings()` -- redacts finding fields
2. `worker/runner.go:redactWorkerOutput()` -- redacts worker output
3. `app/audit.go:redactFindings()` -- redacts finding fields again
4. `app/audit.go:redactWorkerResult()` -- redacts worker result
5. `report/render.go:redactReport()` -- redacts again before rendering
6. `report/render.go:RenderMarkdown()` -- calls `redact.Text()` inline on evidence/impact/remediation

The `redact.Text()` function is idempotent, so this doesn't cause bugs, but it wastes cycles. More importantly, it's unclear which layer "owns" redaction.

**Recommendation:** Redact once at the boundary -- in `app/audit.go` after worker results are collected and before report generation. Remove redundant redaction from worker and report layers.

### `killCommandProcessGroup` duplication

`ai/execute.go:334` and `worker/runner.go:872` define identical `killCommandProcessGroup` functions. Now that AI execution is in `ai/execute.go`, the one in `worker/runner.go` appears unused (the `buildCodexExecArgs` in runner.go also appears to be dead code since execution moved to `ai.ExecuteTrack`).

**Recommendation:** Remove the dead `killCommandProcessGroup` and `buildCodexExecArgs` from `worker/runner.go`.

## 4. Error Handling Consistency

Error handling is generally good. The `fmt.Errorf("context: %w", err)` pattern is used consistently. The `joinErr()` helper in `worker/runner.go` is a reasonable approach for accumulating errors in retry loops.

### Issues

**A. `joinErr` loses error chain for the first error.** The implementation uses `fmt.Errorf("%v; %w", base, next)` -- the `base` error is formatted with `%v` (losing its unwrap chain) while only `next` is wrapped with `%w`. If callers need to `errors.Is()` on the first error, they will fail. Consider using `errors.Join()` (Go 1.20+) since the project requires Go 1.22+.

**B. Warning accumulation vs. error returns.** Some operations accumulate warnings in `[]string` while others return errors. For example, `LoadCustomDirs` returns `(defs, warnings, error)` where warnings include parse failures for individual check files. This is a reasonable design, but the three-return pattern should be documented as a convention.

## 5. worker/runner.go Complexity

At 1,039 lines, `runner.go` is the second-largest file. It handles:
- Concurrent worker orchestration (`RunAll`)
- Per-track execution with timeout (`runOneTrack`)
- Rule engine dispatch (`runRuleTrack`)
- AI execution with retry logic (`executeTrackWithRetries`)
- Failure classification (`classifyCodexFailure`)
- Sandbox-deny host fallback logic
- Output parsing and redaction
- Heartbeat emission
- Schema file writing
- Finding normalization

### Recommendations

**A. `executeTrackWithRetries` (lines 379-540) is 160 lines with deeply nested conditionals.** The sandbox-deny-host-fallback path inside the retry loop adds significant complexity. Consider extracting the host fallback into a separate function:

```go
func executeTrackWithRetries(...) trackExecutionResult {
    result := executeWithRetryLoop(...)
    if shouldAttemptHostFallback(result, opts) {
        return executeHostFallback(ctx, opts, ...)
    }
    return result
}
```

**B. `classifyCodexFailure` uses string matching against error text.** This is fragile -- error messages from upstream tools can change without notice. The function is well-organized with clear categories, but consider adding unit tests for each classification category with realistic error strings.

**C. Dead code.** `buildCodexExecArgs` in `runner.go` (line 572) appears to duplicate the same function now in `ai/execute.go`. It should be removed if it's no longer called.

## 6. Type System Observations

### String-typed enums

Status, severity, source, engine, provider, auth mode, execution mode, and sandbox mode are all `string` types. Some have typed constants (like `checks.Status`, `checks.Engine`) while others are raw strings (execution mode, sandbox mode in `worker`).

**Recommendation:** The typed string enums in `checks` are good. Consider adding similar types for `ExecutionMode` and `SandboxMode` in the `worker` package and for `Provider` / `AuthMode` in the `ai` package. This would make invalid states unrepresentable and enable exhaustive switch checking.

### `WorkerTrack` type is unused

`model/types.go` defines `WorkerTrack` as a typed string with constants (`TrackAppSec`, `TrackDependencies`, `TrackSecrets`) and a `DefaultTracks` slice. However, these are never referenced anywhere in the codebase -- the system now uses `checks.Definition.ID` as the track identifier. This is dead code from before the extensible check system was introduced.

**Recommendation:** Remove `WorkerTrack`, `TrackAppSec`, `TrackDependencies`, `TrackSecrets`, and `DefaultTracks` from `model/types.go`.

### `AuditOptions` field overlap with `RunOptions` and `Runtime`

`app.AuditOptions` carries `AIBin`, `AIVersion`, `AISHA256`, `AIRequest` alongside the `ai.Runtime`. The `RunOptions` in `worker` carries `CodexBin` alongside `AIRuntime`. This creates multiple paths for the same data.

**Recommendation:** Consider putting all AI binary metadata into a struct (e.g., `ai.BinaryInfo{Path, Version, SHA256, RequestedPath}`) and passing it through `Runtime` or alongside it, rather than as separate fields on every options struct.

## 7. Config Layering

The `config.Config` struct uses pointer types (`*int`, `*bool`, `*int64`) for optional values -- this is correct for distinguishing "not set" from zero values in YAML configs. The merge function is straightforward but repetitive.

**Improvement:** The `merge` function could use reflection or code generation to avoid the field-by-field merge. However, given there are only ~16 fields, the explicit approach is maintainable. The bigger issue is `applyConfig` in `cmd/cli.go` which uses three maps (`strFlags`, `intFlags`, `boolFlags`) -- this is awkward and error-prone (easy to forget a flag). Consider having `Config` expose a method that takes a `*flag.FlagSet` and sets values directly.

## 8. Positive Architectural Patterns

These are worth preserving:

1. **Options structs everywhere.** `AuditOptions`, `RunOptions`, `StageOptions`, `ResolveOptions` etc. make function signatures clean and extensible.

2. **Progress sink abstraction.** The `progress.Sink` interface with `NoopSink`, `ChannelSink`, and `PlainSink` cleanly separates progress reporting from business logic.

3. **Atomic file writes via `safefile.WriteFileAtomic`.** Consistent use across report, manifest, and worker output writing prevents partial-write corruption.

4. **Symlink protection throughout.** The intake, checks, and safefile packages all guard against symlink attacks.

5. **Clean domain model.** `model/types.go` is pure data with JSON tags -- no behavior, no imports beyond `time`.

6. **Rule engine separation.** The deterministic `rule` engine shares the same `Definition` schema as AI checks, enabling the same selection, validation, and reporting pipeline.

## 9. Prioritized Improvement Suggestions

| Priority | Area | Effort | Impact |
|----------|------|--------|--------|
| 1 | Remove dead code: `WorkerTrack`, `DefaultTracks`, duplicate `buildCodexExecArgs`/`killCommandProcessGroup` in runner.go | Low | Clarity |
| 2 | Consolidate `severityWeight` into `model` package | Low | DRY |
| 3 | Consolidate `findingKey`/`dedupeKey` into `model.FindingKey` | Low | DRY |
| 4 | Replace `joinErr` with `errors.Join` | Low | Correctness |
| 5 | Extract `runCheckCreateFlow` from cmd to `checks` package | Medium | Separation of concerns |
| 6 | Extract `printAuditSummary` to `report` package | Medium | Separation of concerns |
| 7 | Remove redundant multi-layer redaction | Medium | Performance/clarity |
| 8 | Extract `executeTrackWithRetries` host-fallback into separate function | Medium | Readability |
| 9 | Consolidate `normalize*` flag functions between cmd and worker | Medium | DRY |
| 10 | Wrap `checks test` in an `app`-level function to remove `cmd -> worker` dependency | Medium | Layering |

## 10. Dependency Footprint

The project has minimal external dependencies:
- `bubbletea` + `lipgloss` for TUI
- `yaml.v3` for config/check files
- `go-isatty` for terminal detection
- Standard library for everything else

This is an excellent dependency profile for a security tool. No unnecessary frameworks.
