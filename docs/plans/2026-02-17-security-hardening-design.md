# Design: Security Hardening — Mis-classification & Governance Evasion

**Date:** 2026-02-17
**Status:** Approved

## Finding 1: Mis-classification Attack (Intake & Rule Engine)

### Problem

Two blind spots allow vulnerabilities to evade detection:

1. Intake silently drops security-relevant files (`.pem`, `.key`, `.env`, `.p12`, `credentials.json`) via `skipFileExts` and `isSensitiveFileName` — they never reach any scanner.
2. Rule engine silently skips files >2MB with only a log note, no report-level warning.

### Fix 1a: Split "skip from workspace" vs "security-relevant skip"

In `internal/intake/intake.go`:

- Keep excluding actual binaries (`.exe`, `.dll`, `.so`, images, fonts, archives) in `skipFileExts`
- Move `.pem`, `.key`, `.p12`, `.pfx`, `.crt` from `skipFileExts` to a new `securityRelevantExts` set
- Change `.env`, `.env.*`, `secrets.*`, and credentials files in `isSensitiveFileName` to use a new skip reason `"security_relevant_excluded"` instead of `"skip_secret"`
- Add `SecurityRelevantSkipped int` field to `model.InputManifest`
- Count security-relevant skips separately from regular skips

### Fix 1b: Emit warning for security-relevant file skips

After staging completes, if `SecurityRelevantSkipped > 0`, print to stderr:
```
[governor] warning: N security-relevant files skipped (secrets, keys, certs) — consider running a dedicated secrets scanner
```

### Fix 1c: Configurable rule-engine file size limit with report warnings

- Add `MaxRuleFileBytes` to worker options (default 2MB, max 20MB)
- Thread through `AuditOptions` -> worker execution
- When files are skipped for size, include count in the worker result notes
- Make the limit configurable via `--max-rule-file-bytes` CLI flag

## Finding 3: Governance Evasion (Suppression Hardening)

### Problem

Three exploit paths:

1. Inline `governor:suppress *` suppresses all findings for a file — wildcard is unrestricted
2. File-based suppressions with broad globs (`title: "*"`) blanket-suppress everything
3. CI `checkFailOn` only checks active findings, ignoring suppressed count — 100% suppression passes CI

### Fix 3a: Ban wildcard-only suppression check IDs

In `internal/suppress/inline.go`: after parsing `checkID`, reject `*` as standalone value. Return `"", "", false` and log warning to stderr.

In `internal/suppress/suppress.go` `ruleMatches`: if `r.Check == "*"` or `r.Title == "*"`, skip the rule and accumulate a warning.

### Fix 3b: Require `reason` on file-based suppressions

In `suppress.Load`: after unmarshalling, validate each rule has a non-empty `Reason`. Return error: `suppression rule N: reason is required`.

### Fix 3c: Suppression ratio warning

In `internal/app/audit.go` after `Apply()`: compute `ratio = suppressedCount / (suppressedCount + activeCount)`. If ratio > 0.5 and suppressedCount >= 5, add warning to report errors.

### Fix 3d: `--max-suppression-ratio` flag for CI

In `cmd/cli.go` `runCI`: add `--max-suppression-ratio` float flag (default 1.0 = disabled). After audit, if ratio exceeds threshold, exit non-zero.

## Implementation Notes

- Fix 1a/1b modify `internal/intake/intake.go` and `internal/model/types.go`
- Fix 1c modifies `internal/worker/rule_engine.go`, `cmd/cli.go`, and threading types
- Fix 3a modifies `internal/suppress/inline.go` and `internal/suppress/suppress.go`
- Fix 3b modifies `internal/suppress/suppress.go`
- Fix 3c modifies `internal/app/audit.go`
- Fix 3d modifies `cmd/cli.go`
- All fixes need corresponding test updates
