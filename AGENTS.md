# CLAUDE.md — Developer Guide for Governor

## Project Summary

Governor is a Go CLI tool for security-auditing AI-generated applications. It runs built-in and custom security checks (AI-powered or deterministic rule-based) against source folders/zips with bounded concurrency, then produces markdown, JSON, and HTML reports. Go 1.22+, minimal dependencies (bubbletea for TUI, lipgloss for styling, yaml.v3).

## Build / Test / Run

```bash
make build          # → bin/governor
make test           # go test -mod=readonly ./...
make run            # go run . audit "." (INPUT=. by default)
make install        # cp bin/governor ~/.local/bin/governor
make build-isolation-image  # Docker image for isolated runs
make clean          # rm -rf bin/
```

All Go commands use `-mod=readonly` via `GOFLAGS`.

## Architecture — Package Layout

```
main.go                  # entrypoint, delegates to cmd
cmd/cli.go               # CLI commands, flags, and routing
internal/
  ai/                    # AI provider/profile system, auth modes, runtime abstraction
  app/                   # Audit orchestration (intake → selection → workers → report)
  checks/                # Check definition model, YAML load/validate, selection, templates, doctor/explain
  checkstui/             # Interactive TUI for checks workspace management
  envsafe/               # Environment variable allowlist filtering for subprocess isolation
  extractor/             # AI-powered check extraction from documents (.md/.txt/.pdf)
  intake/                # Input staging (folder/zip → filtered workspace), manifest generation
  isolation/             # Container-based isolated runs (Docker/Podman), auth bundle staging
  model/                 # Core domain types: Finding, WorkerResult, AuditReport, RunMetadata
  progress/              # Event-based progress reporting (NoopSink, ChannelSink, PlainSink)
  prompt/                # Per-check prompt generation with manifest context and scope hints
  redact/                # Secret/token pattern redaction before persistence
  report/                # Report rendering to JSON, Markdown, HTML
  safefile/              # Safe file I/O with symlink protection, atomic writes via temp+rename
  sanitize/              # Path sanitization for prompts (control chars, length limits)
  trust/                 # AI binary resolution and attestation (SHA256, version, permissions)
  tui/                   # Interactive audit progress TUI (worker status, event filtering)
  worker/                # Bounded-concurrency worker runner, retry logic, rule engine
```

## Key Entry Points

- `cmd/cli.go` — all CLI commands (`audit`, `isolate audit`, `checks [tui|init|add|extract|list|validate|doctor|explain|enable|disable]`)
- `internal/app/audit.go` — `RunAudit()` orchestrates the full audit pipeline
- `internal/worker/runner.go` — worker execution with retry/fallback
- `internal/worker/rule_engine.go` — deterministic rule execution (no AI calls)
- `internal/checks/types.go` — `Definition` struct (check schema)
- `internal/model/types.go` — `Finding`, `WorkerResult`, `AuditReport` types
- `internal/ai/provider.go` — provider/profile resolution and runtime construction

## Key Conventions

### Commit Messages

```
type(scope): description
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`
Scopes: `ai`, `checks`, `audit`, `isolate`, `tui`, `worker`, `intake`

### Options Structs

Public `*Options` structs are the standard pattern for parameterizing operations:
`AuditOptions`, `RunOptions`, `StageOptions`, `SelectionOptions`, `ResolveOptions`, `Options` (in tui/extractor/checkstui packages).

### Error Handling

- Wrap with context: `fmt.Errorf("resolve input path: %w", err)`
- Accumulate errors with `joinErr()` helper where multiple operations can fail independently
- Collect warnings in `[]string` slices alongside the main error path

### Go Naming

- PascalCase for exports, camelCase for unexported
- Descriptive function names that read as verb phrases

### Tests

- Colocated in `*_test.go` files next to the code they test
- Table-driven tests with descriptive subtest names
- Use `t.TempDir()` for filesystem tests
- Use `t.Helper()` in test helpers

## Domain Concepts

### Check Definitions (`checks.Definition`)

A check has: `id`, `name`, `status` (draft/enabled/disabled), `source` (builtin/custom), `engine` (ai/rule), `instructions` (for AI) or `rule` (for deterministic), `scope` (include/exclude globs), and hint fields (categories, severity, confidence).

### Check Engines

- **`ai`**: AI-powered analysis via configured provider/profile — requires model calls
- **`rule`**: Deterministic pattern matching on `file_content` (contains/regex) — no AI, no network

### Findings (`model.Finding`)

Output of a check: `title`, `severity`, `category`, `evidence`, `impact`, `remediation`, `file_refs`, `confidence` (0–1), `source_track`.

### Provider / Profile System (`internal/ai`)

- **Providers**: `codex-cli` (CLI subprocess) and `openai-compatible` (HTTP API)
- **Profiles**: Named configs with defaults (codex, openai, claude, gemini, mistral, deepseek, grok, etc.)
- **Resolution**: built-in defaults → `~/.governor/ai/profiles.yaml` → `./.governor/ai/profiles.yaml`
- **Auth modes**: `auto`, `account`, `api-key`

### Audit Pipeline Flow

1. **Intake**: folder/zip → filtered workspace (skip symlinks, binaries, secrets, `node_modules`, `vendor`, `.git`)
2. **Selection**: merge built-in + custom checks, apply `--only-check`/`--skip-check` filters
3. **Execution**: bounded-concurrency workers (default 3), AI or rule engine per check
4. **Reporting**: deduplicate findings, redact secrets, write `audit.json`/`audit.md`/`audit.html`

### Custom Checks

- Repo-local: `.governor/checks/<id>.check.yaml` (takes precedence)
- Global: `~/.governor/checks/<id>.check.yaml`
- Statuses: `draft` (skipped), `enabled` (runs), `disabled` (skipped)
