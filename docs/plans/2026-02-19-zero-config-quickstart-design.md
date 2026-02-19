# Zero-Config Quick Start — Design Document

**Date**: 2026-02-19
**Goal**: Reduce setup friction for solo devs / indie hackers so `governor audit .` works immediately after install with zero configuration.

## Problem

Today, a new user who runs `governor audit .` after installation hits an error because the default AI profile (codex) isn't available. The path to a working audit requires: understanding AI profiles, getting an API key, running `governor init`, and setting config — too many steps before seeing any value.

## Design

Four changes that work together to create a zero-friction first experience.

### 1. Project Auto-Detection

A new `internal/detect` package that identifies project type by scanning for marker files. Detection is informational — it doesn't change which checks run.

**Detection signals** (checked in order, first match wins per category):

| Signal File | Project Type |
|---|---|
| `next.config.*`, `app/layout.tsx` | Next.js |
| `package.json` + express/fastify dep | Express/Fastify |
| `requirements.txt` + fastapi/flask dep | FastAPI/Flask |
| `go.mod` | Go |
| `Cargo.toml` | Rust |
| `supabase/config.toml` | Supabase |
| `package.json` (fallback) | Node.js |
| `*.py` (fallback) | Python |

**Usage**: Shows "Detected: Next.js project" in audit output header. Future: used by `quickstart` to recommend check packs.

### 2. Rule-Only-First Default Experience

When no AI profile is explicitly configured (no config file, no `--ai-profile` flag), Governor automatically falls back to `--quick` mode (rule-engine only). After the run, prints a hint about enabling AI checks.

**Behavior matrix**:

| Config state | `governor audit .` behavior |
|---|---|
| No config, no flags | Auto-quick (rule-only), print AI hint |
| `--quick` explicit | Rule-only, no hint |
| Config has `ai_profile` | Full audit (AI + rule) |
| `--ai-profile` flag | Full audit (AI + rule) |

**Key principle**: First run after `go install` always works. No setup, no API key, no errors.

**Hint output**:
```
14 rule-engine checks completed (no AI key needed)

Want deeper analysis? Add an AI profile:
  governor init --ai-profile openai
  export OPENAI_API_KEY=sk-...
  governor audit .
```

### 3. `governor quickstart` Interactive Wizard

A new command that guides setup in ~30 seconds. Orchestrates existing commands.

**Flow**:
1. Scan project, show detected type
2. Ask: Initialize `.governor` directory? → runs `init` logic
3. Ask: Install pre-commit hook? → runs `hooks install` logic
4. Ask: Set up AI-powered checks? → configures AI profile if yes
5. Ask: Run first audit now? → runs `audit .` (auto-quick if no AI)
6. Show findings summary + next steps

**Implementation**: New `runQuickstart` function in `cmd/cli.go`. Uses `bufio.Scanner` for Y/n prompts. Calls existing internal functions — no new packages beyond `detect`.

### 4. Improved Terminal Output

Upgrade the `scan/format.go` `FormatHuman` function and audit output path for better readability.

**Changes**:
- **Color-coded severity** via lipgloss: CRITICAL (red bg), HIGH (red), MEDIUM (yellow), LOW (dim)
- **Summary header**: `governor audit complete — 5 findings (1 critical, 2 high, 2 medium)`
- **Sorted by severity**: critical first, then high, medium, low, info
- **Condensed default**: title + file + one-line remediation. `--verbose` for full evidence
- **Report path footer**: `Reports: .governor/runs/<timestamp>/audit.{json,md,html,sarif}`

**Example**:
```
governor audit complete — 3 findings (1 critical, 1 high, 1 medium)

  CRITICAL  Hardcoded Supabase key in frontend code
            src/lib/supabase.ts
            → Store Supabase keys in environment variables.

  HIGH      Missing auth middleware on POST /api/users
            src/routes/users.ts
            → Add requireAuth middleware before route handlers.

  MEDIUM    CORS middleware with default permissive settings
            src/server.ts
            → Pass explicit origin allowlist to cors().

Reports: .governor/runs/2026-02-19T2045/audit.{json,md,html,sarif}
```

No changes to report file formats (JSON/MD/HTML/SARIF stay the same).

## Files Affected

| File / Package | Change |
|---|---|
| `internal/detect/` (new) | Project type auto-detection |
| `internal/app/audit.go` | Auto-quick fallback logic, detect integration, output changes |
| `internal/scan/format.go` | Color-coded, sorted, condensed terminal output |
| `cmd/cli.go` | New `quickstart` command, `runQuickstart` function |
| `cmd/cli.go` (`runAudit`) | Auto-quick when no AI configured |

## Non-Goals

- Changing report file formats (JSON/MD/HTML/SARIF)
- Auto-selecting checks based on project type (future enhancement)
- GitHub Action changes (already exists in separate repo)
- Interactive fix mode (possible future feature)
