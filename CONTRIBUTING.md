# Contributing to Torshammer 2.0

Thank you for your interest in contributing to Torshammer 2.0! This document provides guidelines for contributing to the project.

## Code of Conduct

### Principles

- **Respect:** Be respectful to all contributors
- **Inclusivity:** Welcome contributors from all backgrounds
- **Collaboration:** Work together constructively
- **Focus:** Focus on what is best for the project
- **Security:** Maintain security and authorization requirements

### Unacceptable Behavior

- Harassment or discrimination
- Personal attacks
- Unprofessional conduct
- Security violations
- Unauthorized testing

## Getting Started

### Development Setup

See [Development Guide](docs/development.md) for detailed setup instructions.

Quick start:

```bash
# Clone repository
git clone <repository-url>
cd torshammer

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

### Understanding the Codebase

Read the [Architecture Documentation](docs/architecture.md) to understand the system design.

Key modules:
- `cli.py` - Command-line interface
- `config.py` - Configuration model
- `engine.py` - Attack engine
- `profiles.py` - Attack profiles
- `conn.py` - Connection factory
- `proxies.py` - Proxy management

## Contribution Workflow

### Merge Policy (enforced)

- **A pull request may only be merged into `main` when its CI pipeline is
  fully green** (pytest + coverage ≥ 85%, ruff check, ruff format, mypy,
  compileall syntax gate; Rust changes additionally require `cargo fmt`,
  `cargo clippy -D warnings`, and `cargo test`).
- A red pipeline blocks the merge — it must never be ignored or bypassed.
  If CI infrastructure itself is broken, fix or disable the pipeline
  explicitly before merging; do not merge around it.

### 1. Choose an Issue

- Check existing issues for what needs work
- Create a new issue if needed
- Comment on the issue to claim it

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `test/` - Test changes
- `refactor/` - Code refactoring

### 3. Make Changes

- Write code following [Coding Standards](#coding-standards)
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 4. Commit Changes

```bash
git add .
git commit -m "Clear commit message"
```

Commit message format:
```
Brief description (50 chars or less)

Detailed explanation (72 chars per line)

- Bullet points for specific changes
- Reference issue numbers if applicable
```

### 5. Test Changes

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=torshammer

# Run specific tests
pytest tests/test_cli.py
```

### 6. Update Documentation

- Update relevant documentation files
- Add new documentation for new features
- Update CHANGELOG.md

### 7. Submit Pull Request

- Push branch to repository
- Create pull request with clear description
- Reference related issues
- Include screenshots if applicable

## Coding Standards

### Python Version

- **Minimum:** Python 3.11
- **Target:** Python 3.11+

### Type Hints

Type hints are required for all public functions:

```python
from __future__ import annotations


def example_function(param: str) -> int:
    return len(param)
```

### Code Style

Use `ruff` for linting and formatting:

```bash
# Check code
ruff check src/

# Auto-fix issues
ruff check --fix src/

# Format code
ruff format src/
```

Configuration in `pyproject.toml`:
```toml
[tool.ruff]
line-length = 100
target-version = "py311"
```

### Docstrings

Use Google-style docstrings:

```python
def example_function(param: str) -> int:
    """Brief description.

    Args:
        param: Description of parameter.

    Returns:
        Description of return value.

    Raises:
        ValueError: If param is invalid.
    """
```

### Import Style

```python
from __future__ import annotations

import asyncio
import ssl

from .config import Config
from .proxies import Proxy
```

## Testing

### Test Requirements

- All contributions must include tests
- Tests must pass for all changes
- Aim for high test coverage
- Use existing fixtures when possible

### Test Structure

```
tests/
├── conftest.py          # Shared fixtures
├── test_cli.py          # CLI tests
├── test_conn.py         # Connection tests
├── test_profiles.py     # Profile tests
└── test_proxies.py      # Proxy tests
```

### Writing Tests

```python
def test_new_feature():
    """Test new feature description."""
    # Arrange
    input_data = ...

    # Act
    result = function_under_test(input_data)

    # Assert
    assert result == expected
```

### Running Tests

```bash
# All tests
pytest

# Verbose
pytest -v

# Specific file
pytest tests/test_cli.py

# Specific test
pytest tests/test_cli.py::test_parse_https_url

# Coverage
pytest --cov=torshammer
```

## Documentation

### Documentation Requirements

- Update README.md for user-facing changes
- Update relevant docs/*.md files
- Add new documentation for new features
- Update CHANGELOG.md

### Documentation Files

- `README.md` - User-facing documentation
- `docs/architecture.md` - Architecture details
- `docs/installation.md` - Installation guide
- `docs/cli.md` - CLI reference
- `docs/configuration.md` - Configuration guide
- `docs/security.md` - Security documentation
- `docs/attack-modes.md` - Attack mode details
- `docs/proxy-support.md` - Proxy documentation
- `docs/output-formats.md` - Output format documentation
- `docs/testing.md` - Testing guide
- `docs/troubleshooting.md` - Troubleshooting guide
- `docs/development.md` - Development guide

### Documentation Style

- Use clear, concise language
- Include code examples
- Use tables for structured data
- Use Mermaid diagrams for architecture
- Cross-reference related documentation

## Security-Sensitive Changes

### Authorization Requirements

The tool is designed for authorized security testing only. When contributing:

- Do not add features that bypass authorization
- Do not add exploit payloads
- Do not add persistence mechanisms
- Do not add credential theft functionality
- Do not make the tool more destructive

### Security Review

Security-sensitive changes require:
- Additional review from maintainers
- Security impact assessment
- Documentation updates
- Test coverage for security aspects

### Security Reporting

If you discover a security vulnerability:
- Do not create a public issue
- Follow [Security Policy](docs/security.md) for reporting
- Wait for coordinated disclosure

## Types of Contributions

### Bug Fixes

- Include clear description of the bug
- Include steps to reproduce
- Include test that fails before fix
- Ensure test passes after fix

### New Features

- Propose feature in issue first
- Get maintainers' approval
- Include documentation
- Include tests
- Update CHANGELOG.md

### Documentation

- Improve clarity of existing docs
- Fix typos or errors
- Add missing documentation
- Add examples

### Refactoring

- Maintain existing behavior
- Update tests if needed
- No breaking changes
- Document reasons for refactoring

## Pull Request Process

### Before Submitting

- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Commit messages are clear
- [ ] Branch is up to date with main

### Pull Request Description

Include:
- Clear description of changes
- Related issue numbers
- Testing performed
- Breaking changes (if any)
- Screenshots (if applicable)

### Review Process

1. Maintainer reviews the PR
2. Request changes if needed
3. Address feedback
4. Update PR
5. Approve and merge

### Merge Guidelines

- Squash and merge for small changes
- Rebase and merge for feature branches
- Maintain clean commit history
- Delete branch after merge

## Release Process

Maintainers handle releases:

1. Update version number
2. Update CHANGELOG.md
3. Create release branch
4. Tag release
5. Build distributions
6. Publish to PyPI (if applicable)
7. Create Forgejo release

## Getting Help

### Questions

- Create an issue with "question" label
- Be specific about what you need help with
- Include relevant code snippets

### Discussions

- Use Forgejo Discussions for broader topics
- Be respectful and constructive
- Search existing discussions first

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md (if created)
- Release notes
- Git commit history

## License

By contributing, you agree that your contributions will be licensed under the GPL-2.0-or-later license.

## Additional Resources

- [Development Guide](docs/development.md) - Development details
- [Architecture Documentation](docs/architecture.md) - System design
- [Testing Guide](docs/testing.md) - Test suite details
- [Security Policy](docs/security.md) - Security guidelines

## Contact

For questions about contributing:

```
[MAINTAINER CONTACT]
```

**For Maintainers:** Replace with actual contact information.

---

Thank you for contributing to Torshammer 2.0!
