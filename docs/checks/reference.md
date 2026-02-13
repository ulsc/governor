# Checks Reference

## File Location

- Repo-local: `./.governor/checks/<id>.check.yaml`
- Home-level: `~/.governor/checks/<id>.check.yaml`

## Required Fields

- `api_version`: `governor/v1`
- `id`: `^[a-z0-9][a-z0-9_-]{1,63}$`
- `status`: `draft|enabled|disabled`
- `source`: `builtin|custom`
- `instructions`: non-empty guidance for the worker

## Optional Fields

- `name`
- `description`
- `scope.include_globs`
- `scope.exclude_globs`
- `categories_hint`
- `severity_hint`: `critical|high|medium|low|info`
- `confidence_hint`: `0..1`
- `origin.method`
- `origin.inputs`
- `created_at`, `updated_at`

## Runtime Behavior

- `draft`: excluded from normal audits.
- `enabled`: eligible for selection.
- `disabled`: always excluded.
- Duplicate IDs: first loaded definition wins (repo-local first by default).

## Useful Commands

```bash
governor checks
governor checks tui
governor checks init --list-templates
governor checks validate
governor checks doctor
governor checks explain <id>
governor checks enable <id>
```
