# mycli-lite

`mycli-lite` is a dependency-free MySQL client for constrained hosts. It is a
single Python file that can be copied to a machine with Python 3.10 through 3.14 and
used immediately as either a CLI or a small synchronous library.

The project is aimed at authorized penetration tests, incident response, and
other environments where installing a full database client is impractical.

## Quick start

Copy the artifact and run it directly:

```bash
scp mycli_lite.py operator@target:/tmp/
ssh operator@target 'python3 -I -S /tmp/mycli_lite.py --version'
```

Connect interactively:

```bash
python3 mycli_lite.py -h db.internal -u analyst -p inventory
```

Execute a query without putting the password in the process arguments:

```bash
export DB_PASSWORD='replace-me'
python3 mycli_lite.py \
  -h db.internal -u analyst --password-env DB_PASSWORD \
  -e 'SELECT VERSION(), CURRENT_USER();'
```

From a cloned GitHub fork, the same module and `mycli-lite` command can
optionally be installed into an isolated environment:

```bash
uv tool install .
mycli-lite --version
```

Direct transfer never requires package installation or network access on the
target.

## Included

- MySQL classic-protocol v10 handshakes and text queries.
- TCP, IPv4/IPv6, and explicit Unix-domain sockets.
- TLS modes from opportunistic encryption through CA and hostname validation.
- `mysql_native_password`, `caching_sha2_password`, and `sha256_password`.
- Secure SHA-2 authentication over TLS or with a pinned/requested RSA key.
- Multiple statements and result sets.
- Table, TSV, CSV, and vertical output.
- A small REPL and an importable `Connection` API.
- Packet fragmentation, size limits, strict sequence checks, and safe terminal
  escaping.

## Deliberately omitted

The single-file constraint means there is no completion, syntax highlighting,
history, configuration discovery, keyring, SSH tunnel, pager, editor, LLM,
plugin system, ORM, parameter binding, prepared statements, streaming cursor,
or `LOCAL INFILE` support.

All result rows are buffered in memory. Library callers must construct SQL
safely; this project is not a query builder and does not make string
interpolation safe.

See the [usage and security guide](docs/usage.md) for the full CLI reference,
library API, authentication behavior, and compatibility boundaries.

## Library example

```python
from mycli_lite import connect

with connect(
    host='db.internal',
    user='analyst',
    password='secret',
    database='inventory',
    ssl_mode='required',
) as connection:
    for result in connection.query('SELECT id, hostname FROM assets LIMIT 20'):
        print(result.rows)
```

## Security posture

- `LOAD DATA LOCAL INFILE` is never advertised or serviced.
- Cleartext authentication requires explicit opt-in and secure transport.
- SHA-2 full authentication fails closed on plaintext TCP unless an RSA-key
  mode was explicitly selected.
- `verify-identity` should be used with a trusted CA when server identity
  matters. The default `preferred` mode does not prevent TLS downgrade or
  authenticate the server.
- Use this software only on systems you own or are explicitly authorized to
  assess.

Security issues should be reported according to [SECURITY.md](SECURITY.md).

## Development

```bash
uv sync --group dev
uv run -- pytest -m 'not live'
uv run -- ruff check .
uv run -- ruff format --check .
uv run -- mypy mycli_lite.py tests
uv build
```

The project supports Python 3.10 through 3.14. Runtime imports must remain
standard-library-only, and `mycli_lite.py` must remain independently
transferable.

## Independent fork

This project is derived from [mycli](https://github.com/dbcli/mycli) but is not
affiliated with, sponsored by, or endorsed by the mycli or dbcli maintainers.
The implementations now have intentionally different scope and architecture.
See [ATTRIBUTION.md](ATTRIBUTION.md) and [LICENSE.txt](LICENSE.txt).

MySQL is a trademark of Oracle and/or its affiliates. This project is not
affiliated with or endorsed by Oracle.
