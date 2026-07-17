# Contributing

Contributions are welcome when they preserve the project's central constraint:
`mycli_lite.py` must remain a useful, dependency-free, transferable artifact.

## Set up

Install [uv](https://docs.astral.sh/uv/) and create the development environment:

```bash
uv sync --group dev
```

## Validate a change

```bash
uv run -- pytest -m 'not live'
uv run -- ruff check .
uv run -- ruff format --check .
uv run -- mypy mycli_lite.py tests
uv run -- python -I -S mycli_lite.py --version
uv build
```

Tests must not depend on the original mycli package. Protocol behavior should
normally be covered with scripted packet fixtures. A bug involving a real
server should also receive an opt-in live regression test when practical.

Run live tests by setting the connection variables and selecting the marker:

```bash
export MYCLI_LITE_TEST_HOST=127.0.0.1
export MYCLI_LITE_TEST_PORT=3306
export MYCLI_LITE_TEST_USER=root
export MYCLI_LITE_TEST_PASSWORD=secret
export MYCLI_LITE_TEST_DATABASE=mysql
export MYCLI_LITE_TEST_GET_SERVER_PUBLIC_KEY=1
uv run -- pytest -m live
```

## Scope

Runtime dependencies are not accepted. Features that require completion,
syntax highlighting, configuration frameworks, ORMs, or plugin ecosystems
belong in full database clients rather than this project.

Keep public APIs typed, comments concise, and code compatible with Python 3.10
through 3.14. Prefer single quotes in new Python code.

User-visible changes should include a changelog entry. Commit subjects should
use the present tense and stay under 50 characters.

By contributing, you agree that your contribution is distributed under the
BSD 3-Clause License in `LICENSE.txt`.
