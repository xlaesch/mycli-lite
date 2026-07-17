## Summary

## Test evidence

- [ ] Unit tests pass on the affected Python versions.
- [ ] Ruff formatting and lint checks pass.
- [ ] Mypy passes.
- [ ] `python -I -S mycli_lite.py --version` succeeds.
- [ ] The affected legacy suite passes with `python -B -E -s -S`.
- [ ] Both raw artifacts remain independently executable with no runtime dependency.
- [ ] Public behavior and `__version__` remain aligned across both artifacts.
- [ ] Protocol or security behavior has regression coverage.
- [ ] User-visible behavior is documented in `CHANGELOG.md`.
- [ ] Copied or derived code includes its provenance and compatible license.

## Scope impact

Describe the effect on artifact size, supported servers, authentication, and
security boundaries. Document any intentional difference between the modern
CPython 3.10 through 3.14 artifact and the legacy CPython 2.7.9 through 2.7.18
or 3.4 through 3.9 artifact.
