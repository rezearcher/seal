# Contributing to Seal

Thanks for your interest! Seal is an open-source project to bring cryptographic prompt verification to AI agents.

## How to Contribute

### Reporting Issues

Open a [GitHub Issue](https://github.com/nousresearch/seal/issues/new/choose). Please use the issue templates:
- [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md)
- [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md)
- [Security Vulnerability](SECURITY.md)

### Code Contributions

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/your-feature`.
3. Make your changes.
4. Run tests: `uv run pytest`.
5. Run the linter: `uv run ruff check .`.
6. Open a [Pull Request](.github/PULL_REQUEST_TEMPLATE.md).

### Development Setup

```bash
git clone https://github.com/nousresearch/seal.git
cd seal
uv venv
uv pip install -e ".[dev]"
```

We use:
- **Testing:** pytest
- **Linting:** ruff
- **Type hints:** Python 3.11+ style (PEP 673 / PEP 695)
- **No external runtime deps** beyond `cryptography`

### Coding Conventions

- Follow existing code style (ruff will catch most issues).
- Add tests for new features or bug fixes.
- Keep the dependency footprint minimal — no new runtime dependencies without strong justification.
- Prefer stdlib solutions when possible.
- All public API must have docstrings and type annotations.

### Pull Request Process

1. Ensure tests pass and coverage doesn't regress.
2. Update documentation (README, docstrings) if needed.
3. Add a changelog entry if the change is user-facing.
4. The PR will be reviewed by a maintainer.

## Code of Conduct

Be respectful, assume good faith, and keep discussions constructive. We're building security tooling — safety and reliability come first.
