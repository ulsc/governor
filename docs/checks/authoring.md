# Checks Authoring Guide

This guide is for creating high-signal Governor checks quickly and safely.

## Fast Path

0. Open the checks workspace to inspect/triage:

```bash
governor checks
```

1. Initialize a check from template:

```bash
governor checks init
```

2. Diagnose quality/conflicts:

```bash
governor checks doctor
```

3. Enable once ready:

```bash
governor checks enable <check-id>
```

4. Run targeted audit:

```bash
governor audit . --only-check <check-id>
```

## Non-Interactive Path

```bash
governor checks init \
  --non-interactive \
  --template authz-missing-checks \
  --id authz-admin-enforcement \
  --name "Admin authorization enforcement"
```

Deterministic non-AI rule template:

```bash
governor checks init \
  --non-interactive \
  --template prompt-injection-rule \
  --id prompt-injection-local \
  --name "Prompt Injection Local Rule"
```

## Quality Checklist

- Instructions are concrete and actionable.
- Scope hints (`include_globs`/`exclude_globs`) are present.
- Categories and severity reflect expected findings.
- Check status starts as `draft`, then moves to `enabled` after validation.

## Storage and Precedence

- Repo-local checks: `./.governor/checks`
- Home-level checks: `~/.governor/checks`
- Duplicate IDs: repo-local wins by default.
