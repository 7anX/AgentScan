# Contributing to AgentScan

Thank you for your interest in contributing to AgentScan! This guide will help you get started.

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git

### Build

```bash
git clone https://github.com/7anX/AgentScan
cd AgentScan
go build -o agentscan .
```

### Run Tests

```bash
go test -race -v ./...
```

### Lint

We use [golangci-lint](https://golangci-lint.run/). Make sure your code passes before submitting a PR:

```bash
golangci-lint run
```

## How to Contribute

1. **Fork** the repository
2. **Create a branch** for your feature or fix: `git checkout -b feature/my-feature`
3. **Make your changes** and commit with clear messages
4. **Run tests and lint** to ensure nothing is broken
5. **Push** your branch and open a **Pull Request**

## Guidelines

- Keep PRs focused — one feature or fix per PR
- Add tests for new functionality when possible
- Follow existing code style and patterns
- Update documentation if your change affects user-facing behavior

## Reporting Issues

- Use [GitHub Issues](https://github.com/7anX/AgentScan/issues) to report bugs or request features
- Include steps to reproduce for bug reports
- Provide target environment details (OS, Go version) when relevant

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
