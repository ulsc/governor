# Security Review -- Devil's Advocate Findings

Review Date: 2026-02-14
Branch: `explore/devils-advocate`

---

## Summary

This review probes Governor's security posture across six focus areas: secret redaction, file intake, worker execution, configuration, check definitions, and input validation. Three redaction bypasses were found and fixed. Several lower-severity gaps are documented for awareness.

---

## Findings

### 1. Redaction Bypass: Compound Secret Key Names (FIXED)

**Severity: HIGH**
**Package: `internal/redact`**
**Status: Fixed in this branch**

The `tokenAssign` regex pattern used `\b` word boundaries to match keywords like `secret`, `token`, `password`. The `\b` anchor failed to match compound identifiers with underscores (e.g., `OPENAI_API_KEY`, `secret_key`, `AWS_SECRET_ACCESS_KEY`) because `\b` does not fire between two word characters.

**Bypasses found:**
- `OPENAI_API_KEY=sk-svcacct-...` -- not caught, full key leaked
- `secret_key = abcdefgh...` -- not caught, value leaked
- `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...` -- not caught, full secret leaked

**Fix:** Replaced the word-boundary anchored pattern with a broader regex that matches compound identifiers ending in a secret-like keyword:

```
Before: \b(api[_-]?key|secret|token|password|passwd|pwd)\b
After:  ("?)([A-Za-z0-9_-]*(?:api[_-]?key|secret[_-]?(?:key|access[_-]?key)?|token|password|passwd|pwd))("?)
```

The new pattern also handles JSON-quoted key names (e.g., `"password": "value"`).

**Test files:** `internal/redact/redact_devils_test.go`

---

### 2. Redaction Bypass: JSON-Quoted Password Fields (FIXED)

**Severity: HIGH**
**Package: `internal/redact`**
**Status: Fixed in this branch (same fix as #1)**

AI output frequently includes JSON. A `"password": "MyS3cr3tP@ssw0rd"` pattern was not caught because the original regex expected the keyword `password` to be immediately followed by `[:=]`, not by `"` then `[:=]`.

**Test files:** `internal/redact/redact_devils_test.go` (`TestText_TokenAssignmentVariants/json_password_field`)

---

### 3. Redaction Gap: Stripe, Slack Bot, and Other Provider Keys (NOT FIXED -- Low Priority)

**Severity: LOW**
**Package: `internal/redact`**
**Status: Documented, no fix applied**

The redaction system lacks specific patterns for:
- Stripe keys (`sk_test_*`, `sk_live_*`, `pk_test_*`, `pk_live_*`)
- Slack bot tokens (`xoxb-*`)
- Twilio keys (`SK*`)
- SendGrid keys (`SG.*`)

These may still be caught by the `tokenAssign` pattern if the surrounding context includes an assignment with a known keyword (e.g., `API_KEY=sk_test_...`), but bare references in AI output (e.g., evidence snippets) will not be redacted.

**Recommendation:** Add targeted patterns for high-value service tokens, following the existing pattern for GitHub, Anthropic, and npm tokens.

---

### 4. Config File Follows Symlinks Without Protection

**Severity: MEDIUM**
**Package: `internal/config`**
**Status: Documented, no fix applied**

`config.Load()` reads `~/.governor/config.yaml` and `./.governor/config.yaml` using `os.ReadFile`, which follows symlinks. A malicious symlink at either location could point to an attacker-controlled file, injecting arbitrary config values including `ai_bin` (the AI binary path).

The CLI validates `ai_bin` downstream via `trust.ResolveAIBinary()`, which checks SHA256 and path resolution. However, other config values like `checks_dir` and `execution_mode` are accepted without further validation.

**Mitigation:** The attack requires write access to `~/.governor/` or `./.governor/`, which limits exposure. Consider adding `os.Lstat` + symlink rejection in `loadFile()`, consistent with the pattern used in `safefile`, `checks/files.go`, and `intake`.

**Test files:** `internal/config/config_devils_test.go` (`TestLoad_SymlinkedConfigFile`)

---

### 5. Config Accepts Arbitrary Values Without Validation

**Severity: LOW**
**Package: `internal/config`**
**Status: Documented**

The config loader deserializes YAML values directly into the `Config` struct without validation. Malicious values such as `workers: -1`, `max_bytes: -1`, or `ai_bin: "; rm -rf / #"` are stored as-is. Validation occurs downstream in `cmd/cli.go`, which checks bounds (e.g., `workers` must be 1-3, `max-bytes` must be > 0).

This is acceptable because:
- Config is a low-privilege data structure
- All values are validated before use
- The attack requires write access to config files

**Test files:** `internal/config/config_devils_test.go` (`TestLoad_MaliciousFieldValues`)

---

### 6. No Size Limit on Check Definition Instructions

**Severity: LOW**
**Package: `internal/checks`**
**Status: Documented**

Check definitions accept arbitrarily large `instructions` strings (tested with 100KB). A malicious custom check could have enormous instructions that consume memory when loaded, or waste tokens when sent to AI. There is no size cap.

**Recommendation:** Add an optional `maxInstructionsBytes` check in `ValidateDefinition()`.

---

### 7. Regex DoS is Mitigated by Go's NFA Engine

**Severity: INFO (Not Vulnerable)**
**Package: `internal/worker`**
**Status: Verified safe**

Go's `regexp` package uses Thompson NFA-based matching, which guarantees polynomial-time execution. Patterns like `(a+)+b` that cause catastrophic backtracking in PCRE-based engines complete in bounded time in Go.

**Test files:** `internal/worker/rule_engine_devils_test.go` (`TestExecuteRuleCheck_PotentialReDoS`)

---

### 8. Intake Path Traversal Protection is Solid

**Severity: INFO (Not Vulnerable)**
**Package: `internal/intake`**
**Status: Verified safe**

Both folder staging and zip extraction correctly prevent path traversal:
- `workspaceTargetPath()` validates that resolved paths stay within the workspace root
- `cleanZipEntryName()` rejects `../` prefixes, absolute paths, and backslash-encoded traversal
- Symlinks are detected and skipped at both the directory entry and file open stages
- Hard links with `nlink > 1` are rejected
- TOCTOU is mitigated by checking `os.SameFile(expected, opened)` after `Open()`

**Test files:** `internal/intake/intake_devils_test.go`, `internal/intake/zip_devils_test.go`

---

### 9. Worker Concurrency is Race-Free

**Severity: INFO (Not Vulnerable)**
**Package: `internal/worker`**
**Status: Verified safe**

The worker runner uses goroutines with a bounded semaphore and indexed channels. Results are written to a pre-sized slice using the original check index, avoiding data races. The `WaitGroup` ensures all goroutines complete before `resCh` is closed.

**Test files:** `internal/worker/runner_devils_test.go` (`TestRunAll_ConcurrentWorkers`)

---

### 10. Environment Variable Filtering is Conservative

**Severity: INFO (Not Vulnerable)**
**Package: `internal/envsafe`**
**Status: Verified safe**

The `AIEnv()` function uses an explicit allowlist. Variables not in the list are stripped. PATH sanitization removes relative entries, deduplicates, and falls back to a hardcoded safe default. The output is deterministic (sorted).

**Test files:** `internal/envsafe/codex_devils_test.go`

---

## Test Summary

| Package | New Test File | Tests Added |
|---------|--------------|-------------|
| `internal/redact` | `redact_devils_test.go` | 14 tests covering bypass attempts, edge cases, false positive guards |
| `internal/intake` | `intake_devils_test.go` | 18 tests covering path traversal, symlinks, sensitive files, boundary conditions |
| `internal/intake` | `zip_devils_test.go` | 6 tests covering zip path traversal, symlink entries, entry limits |
| `internal/worker` | `runner_devils_test.go` | 26 tests covering malformed output, concurrency, retry logic, classification |
| `internal/worker` | `rule_engine_devils_test.go` | 15 tests covering regex DoS, scope filtering, max matches, evidence snippets |
| `internal/config` | `config_devils_test.go` | 8 tests covering YAML bombs, oversized configs, malicious values, symlinks |
| `internal/checks` | `validate_devils_test.go` | 12 tests covering malicious IDs, invalid fields, normalization, unique IDs |
| `internal/sanitize` | `path_devils_test.go` | 8 tests covering control chars, truncation, prompt injection, Unicode |
| `internal/envsafe` | `codex_devils_test.go` | 9 tests covering filtering, path sanitization, malformed entries, determinism |

## Bugs Fixed

| Bug | Severity | File Changed |
|-----|----------|-------------|
| `tokenAssign` regex fails on compound identifiers (e.g., `OPENAI_API_KEY`, `secret_key`) | HIGH | `internal/redact/redact.go` |
| `tokenAssign` regex fails on JSON-quoted key names (e.g., `"password": "value"`) | HIGH | `internal/redact/redact.go` |
