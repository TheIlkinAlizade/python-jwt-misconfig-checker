# Contributing

This is a small educational project. Contributions are welcome, but there is no
guaranteed review time.

## Setup

    python -m venv .venv
    pip install -e ".[dev]"

All of these must pass before a pull request:

    ruff format .
    ruff check .
    mypy src tests
    pytest

## Adding a check

1. Create `src/jwt_misconfig_checker/checks/your_check.py` with a class that has
   `id`, `title`, `severity`, `description`, `remediation`, `references`
   (a `tuple[str, ...]`) and a `run(token, context) -> list[Finding]` method.
   Build findings with `build_finding` from `checks/common.py`.
2. Pass token-derived values through `safe_evidence`, and never put a secret in
   a finding's evidence.
3. Register the class in `registry.py`.
4. Add `tests/checks/test_your_check.py` with good tokens, bad tokens and edge
   cases such as wrong types, unicode and oversized values. Build tokens with
   `tests/tokens.py`.
5. Add a row to the check table in the README.

## Rules

- Checks must work offline. No network requests.
- Check ids follow `JWT-<AREA>-<NNN>` and are never reused.
- No explanatory comments in code; use clear names and small functions.
- Anything sensitive or opt-in needs an explicit confirmation flag.