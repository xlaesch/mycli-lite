# mycli-lite

A dependency-free, single-file MySQL client and CLI.

## Project structure

```text
mycli_lite.py              Modern runtime module and executable artifact.
mycli_lite_legacy.py       Legacy runtime module and executable artifact.
tests/                     Modern protocol, CLI, output, and live tests.
legacy_tests/              Dependency-free legacy unit and live tests.
docs/usage.md              Detailed user and security documentation.
pyproject.toml             Modern package and development configuration.
MANIFEST.in                Legacy source-archive inclusion boundary.
.github/workflows/         CI and GitHub-only release workflows.
```

## Development rules

- Preserve CPython 3.10 through 3.14 compatibility in `mycli_lite.py`.
- Preserve CPython 2.7.9 through 2.7.18 and 3.4 through 3.9 compatibility in
  `mycli_lite_legacy.py`; CPython 2.7.18 is the Python 2 CI reference.
- Keep both runtime files standard-library-only and independently executable.
- Keep the two public APIs, CLI flags, protocol behavior, security boundaries,
  output, exit codes, and `__version__` values aligned.
- Add type annotations to modern Python code. Prefer lower-case built-in
  generics and `Type | None` unions.
- Use Python 2.7-compatible syntax and explicit compatibility helpers in the
  legacy artifact; do not add annotations, f-strings, dataclasses, keyword-only
  syntax, exception chaining, or newer standard-library dependencies there.
- Prefer single quotes in new modern code and the existing legacy style in the
  compatibility artifact.
- Keep comments concise, direct, and punctuated as full sentences.
- Fail closed when a legacy runtime cannot provide requested authentication or
  TLS verification. Never silently weaken a security mode for compatibility.
- Do not restore dependencies or functionality from full mycli unless it fits
  the single-file scope.

Install the development tooling, then run the standard checks:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -m 'not live'
ruff check .
ruff format .
mypy mycli_lite.py tests
python -m build
```

Run the legacy unit suite with a target interpreter:

```bash
python -B -E -s -S -m unittest discover -s legacy_tests \
  -p 'test_mycli_lite_legacy.py'
```

CI runs that suite in isolated, digest-pinned CPython containers across 2.7.18
and 3.4 through 3.9. Keep the checkout read-only and disable networking for
offline legacy tests.

Before a release, verify the wheel contains only `mycli_lite.py`, distribution
metadata, the console entry point, and the licenses. The GitHub release must
attach only the two standalone runtime files, `mycli_lite.py` and
`mycli_lite_legacy.py`; do not attach the wheel, source archive, checksums, or
license files as release assets. Test the modern raw artifact with `python -I -S`
and the legacy raw artifact with `python -B -E -s -S` to prove neither imports
site packages.

This fork publishes GitHub releases only. Preserve the
`Private :: Do Not Upload` classifier and do not add package-index publishing.

Preserve `LICENSE.txt`, the embedded license header, and `ATTRIBUTION.md`.
