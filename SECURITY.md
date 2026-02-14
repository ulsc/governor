# Security Policy

Governor is an open source project. Security reports are handled on a best-effort
basis by maintainers.

## Reporting Vulnerabilities

Open a GitHub issue:
**https://github.com/ulsc/governor/issues/new**

Use the title prefix **[SECURITY]** and include:

- A clear description of the issue
- Reproduction steps
- Affected versions or commit SHAs
- Potential impact

Do not include active credentials, secrets, or other sensitive data in the issue.

## Supported Versions

Security fixes are applied to the latest release on `main`.

## Project Scope

Security issues are accepted for this project and its maintained artifacts,
including:

- Governor CLI (`governor`)
- Built-in checks bundled in this repository
- Install script (`install.sh`)
- Isolation runner image (`Dockerfile.isolate-runner`)

## Security Hardening Notes

Governor includes several defensive controls, including:

- ZIP extraction protections against traversal/absolute paths
- Symlink skipping during intake
- Constrained environment allowlist for worker subprocesses
- Secret-pattern redaction before report persistence
- Restrictive permissions for run directories and artifacts
