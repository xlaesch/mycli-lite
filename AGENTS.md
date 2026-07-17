# mycli-lite

A dependency-free, single-file MySQL client and CLI.

## Project structure

```text
mycli_lite.py              Runtime module and executable artifact.
tests/                     Protocol, CLI, output, and optional live tests.
docs/usage.md              Detailed user and security documentation.
pyproject.toml             Package and development configuration.
.github/workflows/         CI and GitHub release workflows.
```

## Development rules

- Preserve Python 3.10 through 3.14 compatibility.
- Keep `mycli_lite.py` standard-library-only and independently executable.
- Add type annotations to new Python code.
- Prefer lower-case built-in generics and `Type | None` unions.
- Prefer single quotes in new code.
- Keep comments concise, direct, and punctuated as full sentences.
- Do not restore dependencies or functionality from full mycli unless it fits
  the single-file scope.

Use uv for Python commands:

```bash
uv run -- pytest -m 'not live'
uv run -- ruff check .
uv run -- ruff format .
uv run -- mypy mycli_lite.py tests
uv build
```

Before a release, verify the wheel contains only `mycli_lite.py`, distribution
metadata, the console entry point, and the license. Test the raw artifact with
`python -I -S` to prove it does not import site packages.

Preserve `LICENSE.txt`, the embedded license header, and `ATTRIBUTION.md`.
