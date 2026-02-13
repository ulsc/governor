# Check Templates

Use templates to bootstrap robust checks without writing YAML from scratch.

## List Templates

```bash
governor checks init --list-templates
```

## Built-In Templates

- `blank`: generic scaffold for custom logic.
- `authz-missing-checks`: missing authorization and IDOR-style patterns.
- `secrets-handling`: hardcoded secrets and secret exposure risks.
- `input-validation`: injection and unsafe input handling.
- `dependency-supply-chain`: dependency and CI/CD trust risks.
- `config-hardening`: insecure default and hardening gaps.
- `web-headers`: missing/weak HTTP security headers.

## Choosing a Template

- Start with the closest risk family.
- Narrow with include/exclude globs.
- Tune severity/confidence hints to expected findings.
- Keep instructions specific to your architecture and stack.
