# Checks Troubleshooting

## `check "<id>" not found`

Run:

```bash
governor checks explain <id>
```

Confirm where Governor searched and which paths were considered.

## Check exists but does not run

Common causes:
- status is `draft` or `disabled`
- check was shadowed by a repo-local duplicate
- check filtered out by `--only-check`/`--skip-check`

Use:

```bash
governor checks doctor
governor checks explain <id>
```

## Duplicate IDs across repo/home

Governor loads both directories and keeps the repo-local definition.

Use `checks doctor` to find shadowed files, then rename/remove duplicates.

## Invalid YAML / schema errors

Run:

```bash
governor checks validate
```

Then fix:
- `api_version`
- `id` format
- `status/source`
- missing `instructions`
- invalid `severity_hint` or `confidence_hint`
