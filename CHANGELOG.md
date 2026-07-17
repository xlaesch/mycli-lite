# Changelog

All notable changes to mycli-lite are documented here.

## Unreleased

### Added

- Interactive REPL reconnaissance slash commands: `\whoami`, `\serverinfo`,
  `\privs`, `\dbs`, `\tables [DB]`, `\columns DB.TABLE|TABLE`, `\loot SQL`,
  and `\dump [PATH]`. `\loot` writes query results to numbered TSV files
  under `./loot/`; `\dump` writes a portable SQL dump of accessible user
  databases to stdout, or to `PATH` when one is given, skipping the system
  catalogs.

### Changed

- Refactored the interactive REPL loop to dispatch slash commands through a
  single helper and to run statement execution through a shared query helper,
  preserving the existing exit codes for interrupts and lost connections.

## 0.2.0 - 2026-07-17

### Added

- A separate dependency-free `mycli_lite_legacy.py` artifact for CPython 2.7.9
  through 2.7.18 and 3.4 through 3.9.
- Isolated legacy protocol, authentication, output, CLI, and live-MySQL test
  coverage, with CPython 2.7.18 as the Python 2 reference.
- Legacy artifact checksums and uploads in GitHub releases, plus inclusion in
  source archives.

### Changed

- Kept the wheel and `mycli-lite` console entry point on the typed modern
  CPython 3.10 through 3.14 implementation.
- Documented the artifact selection, end-of-life runtime status, and TLS limits
  imposed by older Python and OpenSSL builds.
- Kept output deterministic under ASCII-only locales and made closed output
  pipes return the documented exit status without shutdown diagnostics.
- Marked distribution metadata `Private :: Do Not Upload` so this fork remains
  GitHub-only.

## 0.1.0 - 2026-07-17

### Added

- A dependency-free, single-file MySQL classic-protocol client.
- An importable synchronous connection and query API.
- TCP, Unix-socket, TLS, native-password, and SHA-2 authentication support.
- Table, TSV, CSV, vertical, batch, and minimal interactive modes.
- Protocol, authentication, output, and isolated-runtime tests.
- Packaging for the `mycli-lite` distribution and `mycli-lite` command.

### Changed

- Replaced the full upstream mycli application with the focused lightweight
  implementation.
