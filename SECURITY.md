# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Governor, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@governor.sh**

Include:

- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential impact assessment

## Response Timeline

- **Acknowledgment**: Within 48 hours of receipt
- **Initial assessment**: Within 5 business days
- **Fix or mitigation**: Depends on severity, but we aim for:
  - Critical: 7 days
  - High: 14 days
  - Medium/Low: Next scheduled release

## Scope

The following are in scope:

- Governor CLI (`governor` binary)
- Built-in check definitions
- Install script (`install.sh`)
- GitHub Action (`ulsc/governor-action`)
- Container image (`Dockerfile.isolate-runner`)

The following are out of scope:

- Third-party AI providers and their APIs
- User-authored custom checks
- Vulnerabilities in dependencies (report these upstream, but let us know)

## Supported Versions

Security fixes are applied to the latest release only. We recommend always running the latest version.

## Disclosure Policy

- We follow coordinated disclosure. We will work with you to understand and address the issue before any public disclosure.
- Credit will be given to reporters in release notes unless anonymity is requested.

## Security Design

Governor is built with security in mind:

- ZIP extraction blocks path traversal and absolute paths
- Symlinks are skipped during intake
- Worker subprocesses run with a constrained environment allowlist
- AI binaries are resolved and attested before execution
- Report text is redacted for common secret patterns before persistence
- Run directories and artifacts use restrictive file permissions (0700/0600)
- Container-isolated runs use read-only root filesystems and non-root users
