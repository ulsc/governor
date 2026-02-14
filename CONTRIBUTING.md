# Contributing to Governor

Contributions are welcome. This document explains how to get started.

## Development Setup

Requirements:

- Go 1.24+ (toolchain 1.25.7 is used automatically via `go.mod`)
- `make`

```bash
git clone https://github.com/ulsc/governor.git
cd governor
make build
make test
```

## Making Changes

1. Fork the repository and create a feature branch from `main`.
2. Make your changes.
3. Add or update tests for any new behavior.
4. Run `make test` and ensure all tests pass.
5. Run `golangci-lint run ./...` and fix any issues.
6. Commit with a descriptive message following the convention below.
7. Open a pull request against `main`.

## Commit Messages

```
type(scope): description
```

**Types**: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`

**Scopes**: `ai`, `checks`, `audit`, `isolate`, `tui`, `worker`, `intake`, `ci`, `cli`

Examples:

```
feat(checks): add CSRF detection rule
fix(worker): handle timeout during stream retry
docs: update installation guide
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `PascalCase` for exports, `camelCase` for unexported identifiers
- Wrap errors with context: `fmt.Errorf("resolve input: %w", err)`
- Use table-driven tests with descriptive subtest names
- Use `t.TempDir()` and `t.Helper()` in tests

## What to Contribute

Good first contributions:

- New rule-based checks (no AI dependency, easy to test)
- Documentation improvements
- Bug fixes with reproducible test cases
- Performance improvements with benchmarks

Larger changes (new features, architectural changes) benefit from opening an issue first to discuss the approach.

## Testing

```bash
# Run all tests
make test

# Run tests for a specific package
go test -mod=readonly ./internal/checks/...

# Run with verbose output
go test -mod=readonly -v ./internal/worker/...
```

## Pull Request Guidelines

- Keep PRs focused on a single change.
- Update documentation in the same PR if behavior changes.
- Ensure CI passes before requesting review.
- Include a clear description of what changed and why.

## Security Vulnerabilities

Report security vulnerabilities via GitHub issues using the process in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
