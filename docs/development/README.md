# Orbit Auth JWT: development

This package declares support for `>=3.11,<3.15` in `pyproject.toml`. That declaration is distinct from evidence that hosted CI ran.

Use the checks for each language manifest present in this repository:

### Python package

```bash
python -m pip install -e '.[dev]' build
pytest
ruff check src tests
ruff format --check src tests
mypy
pip-audit --skip-editable --progress-spinner off
```

Optional SDKs and live-service tests are described by the package README. Do not run an opt-in live test against a shared or production service unless its own documentation explicitly supports that use.

The current local quality matrix passes on CPython 3.11, 3.12, 3.13, and 3.14: all 31 tests, Ruff
lint and format checks, strict mypy, dependency audits with no known vulnerabilities, and wheel/sdist
builds pass on each interpreter. Tests use local keys and deterministic verification cases; hosted CI,
external key rotation/JWKS behavior, and identity-provider interoperability remain separate
validation gates.

## Contribution expectations

Add focused regression coverage for behavior changes. Update the README and relevant guide when a contract, configuration option, security property, lifecycle rule, or operational assumption changes. Report the exact versions and services exercised; local checks do not imply hosted CI or release validation.
