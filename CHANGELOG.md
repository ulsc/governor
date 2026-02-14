# Changelog

All notable changes to Governor are documented here.

## Unreleased

### Added

- **SQL injection rule check** with 7 language detectors (JS/TS, Python, Go, Java, Ruby, PHP)
- **XSS and CSRF AI checks** for cross-site scripting and request forgery detection
- **CWE and OWASP references** on all builtin checks, rendered as links in reports
- **HTML report filtering** — client-side search, severity/category filter buttons, collapsible findings
- **HTTP retry with exponential backoff** for transient AI provider failures (429, 5xx, network errors)
- **Per-file size limit** (10 MB) in intake to skip oversized files automatically
- **Zip bomb detection** with compression ratio limits (100:1) and extraction timeout (5 min)
- **ReDoS timeout protection** for regex matching in the rule engine (5 s per match)
- **Expanded intake detections** — cloud credential files, path-based sensitive file checks, IDE/build directory skipping
- **Init command documentation** in README, getting-started, and configuration guides
- **golangci-lint** added to CI pipeline
- Unit tests for `app/audit` helpers, `isolation` utilities, and `ai/execute` response parsing
- Test file exclusion patterns for security scanning (prevents false positives on test fixtures)
- Self-exclusion patterns to prevent builtin checks from flagging their own pattern definitions
- Documentation: rule engine deep-dive, check authoring guide, isolated runs, reports reference
