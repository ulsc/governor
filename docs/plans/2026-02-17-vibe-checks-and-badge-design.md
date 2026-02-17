# Design: Vibe-Coding Check Library & Security Badge

**Date:** 2026-02-17
**Status:** Approved

## Feature 1: Vibe-Coding Check Library

### Problem

AI coding tools (Cursor, Claude Code, Bolt, Replit, etc.) produce code with recurring security anti-patterns: missing auth on routes, hardcoded API keys in frontend code, permissive CORS, no input validation. Governor's existing 15 built-in checks cover general security but lack checks targeting these AI-specific patterns.

### Design

#### 1A: New Built-in Checks (compiled into binary)

10 new checks added to `internal/checks/builtin.go`, bringing the total from 15 to 25.

**Rule-engine checks (8)** — fast, deterministic, work with `--quick`:

| Check ID | Name | Target Pattern |
|----------|------|----------------|
| `missing_auth_middleware` | Missing Auth on Routes | Express/Fastify/Next.js/FastAPI route handlers without auth middleware |
| `exposed_env_in_client` | Client-Exposed Environment Variables | Secrets in `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` prefixed vars |
| `permissive_cors` | Overly Permissive CORS | `cors({ origin: '*' })`, `Access-Control-Allow-Origin: *` |
| `missing_input_validation` | Missing Request Validation | Direct `req.body`/`req.query` usage in DB operations without validation |
| `insecure_jwt` | Insecure JWT Configuration | JWT `none` algorithm, missing verification, hardcoded secrets |
| `missing_helmet_headers` | Missing Security Headers | Express apps without helmet, missing security middleware |
| `unsafe_html_rendering` | Unsafe React HTML Rendering | React unsafe HTML rendering with variable input (XSS risk) |
| `unprotected_api_keys_frontend` | API Keys in Frontend Code | Key assignments in `.jsx`/`.tsx`/`.vue`/`.svelte` |

**AI-engine checks (2)** — deeper semantic analysis:

| Check ID | Name | Target Pattern |
|----------|------|----------------|
| `missing_rls_policies` | Missing Row-Level Security | Supabase/Postgres schemas without RLS policies |
| `insecure_defaults` | Insecure Default Configuration | Development defaults in production code (debug mode, verbose errors, admin:admin) |

#### 1B: Installable Check Pack System

**New CLI commands:**

```bash
# Install a pack from a source
governor checks install-pack <name>              # from default source
governor checks install-pack <source>/<pack>     # from a specific tap

# Manage sources (like brew tap)
governor checks tap <owner/repo>                 # GitHub shorthand
governor checks tap <git-url>                    # full SSH/HTTPS URL
governor checks tap --list                       # show all sources
governor checks tap --update                     # git pull all taps
governor checks untap <name>                     # remove source

# Browse available packs
governor checks list-packs                       # show all packs from all sources
```

**Source resolution:**

- Default source: `github.com/governor-security/governor-checks` (built-in, no tap needed)
- Custom sources registered via `governor checks tap`
- Taps are shallow-cloned to `~/.governor/taps/<owner>/<repo>/`
- Private repos work automatically — cloning uses the user's existing git auth (SSH keys, `gh auth`, credential helpers)
- Supports GitHub shorthand (`owner/repo`) and full URLs (`git@gitlab.internal:team/checks.git`)

**Tap configuration — `~/.governor/taps.yaml`:**

```yaml
taps:
  - name: acme-corp/private-checks
    url: git@github.com:acme-corp/private-checks.git
    path: /Users/tiger/.governor/taps/acme-corp/private-checks
    added_at: 2026-02-17T12:00:00Z
```

**Expected tap repo structure:**

```
packs/
  nextjs/
    missing-middleware-auth.check.yaml
    api-route-exposure.check.yaml
    pack.yaml
  supabase/
    missing-rls.check.yaml
    pack.yaml
```

**`pack.yaml` metadata:**

```yaml
name: nextjs
description: Security checks for Next.js applications
version: 1.0.0
author: governor-security
checks: 3
```

**Install behavior:**

- `install-pack` copies `.check.yaml` files into `.governor/checks/` (repo-local)
- Existing files with the same name are overwritten (latest wins)
- A `.pack-origin` comment is added to each installed check for traceability

## Feature 2: Security Badge

### Problem

Projects need a way to signal they've been security-audited without exposing their actual findings. A README badge creates organic visibility for governor while giving projects a trust signal.

### Design

**New CLI command:**

```bash
governor badge <audit.json> [flags]
```

**Grading logic:**

| Grade | Criteria |
|-------|----------|
| A+ | 0 findings |
| A | 0 critical, 0 high |
| B | 0 critical, <=3 high |
| C | 0 critical, >3 high |
| D | 1+ critical, <=3 critical |
| F | >3 critical |

**Output formats:**

1. **SVG** (default): Self-contained flat badge — `[governor | A]` with color coding
2. **Shields.io JSON**: `{ "schemaVersion": 1, "label": "governor", "message": "A", "color": "brightgreen" }`

**Privacy by design:**

- Badge contains ONLY the letter grade and color — no finding counts, no severity breakdown, no details
- `audit.json` is read locally to compute the grade; no audit data is embedded or referenced
- No flag to include counts — we do not offer the option to leak details
- The badge is a one-way function: results in, grade out, results discarded

**Color mapping:**

| Grade | Color |
|-------|-------|
| A+ | brightgreen |
| A | green |
| B | yellowgreen |
| C | yellow |
| D | orange |
| F | red |

**Flags:**

- `--out <path>`: Output file path (default: `governor-badge.svg` or `governor-badge.json`)
- `--format svg|shields-json`: Output format (default: `svg`)
- `--style flat|flat-square`: Badge style variant (default: `flat`)
- `--label <text>`: Custom left-side label (default: `governor`)

**CI integration pattern:**

Users commit `governor-badge.svg` to their repo and reference it in README:
```markdown
![Governor Security](./governor-badge.svg)
```

Audit results stay in CI artifacts or `.governor/runs/` (gitignored). The badge is the only artifact that crosses the boundary.

## Implementation Notes

- New built-in checks go in `internal/checks/builtin.go` following the existing pattern
- Pack system needs new files: `internal/taps/` package for tap management, CLI commands in `cmd/cli.go`
- Badge needs: `internal/badge/` package for grading + SVG generation, CLI command in `cmd/cli.go`
- All checks need self-exclusion in their `ExcludeGlobs` to avoid matching their own detector patterns in `builtin.go`
