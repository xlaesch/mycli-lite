# mycli-lite

`mycli-lite` is a dependency-free, single-file MySQL client for constrained
hosts. It provides a CLI and small synchronous library for authorized security
testing, incident response, and administration when installing a full client is
impractical.

| Artifact | CPython versions |
| --- | --- |
| `mycli_lite.py` | 3.10 through 3.14 |
| `mycli_lite_legacy.py` | 2.7.9 through 2.7.18, and 3.4 through 3.9 |

The legacy runtimes are end-of-life and remain limited by their bundled SSL
support. CPython 2.7.18 is the Python 2 CI reference.

## Use

Copy the appropriate file to the target and run it directly:

```bash
scp mycli_lite.py operator@target:/tmp/
python3 -I -S /tmp/mycli_lite.py --version

# Python 2.7 or Python 3.4-3.9
python -B -E -s -S /tmp/mycli_lite_legacy.py --version
```

Connect interactively or execute a query without placing the password in the
process arguments:

```bash
python3 mycli_lite.py -h db.internal -u analyst -p inventory

export DB_PASSWORD='replace-me'
python3 mycli_lite.py -h db.internal -u analyst \
  --password-env DB_PASSWORD -e 'SELECT VERSION(), CURRENT_USER();'
```

Run `python3 mycli_lite.py --help` for all options.

## Library

```python
from mycli_lite import connect

with connect(
    host='db.internal',
    user='analyst',
    password='secret',
    ssl_mode='verify-identity',
    ssl_ca='/path/to/ca.pem',
) as connection:
    print(connection.query('SELECT VERSION()')[0].rows)
```

Use `mycli_lite_legacy` instead on a legacy interpreter.

## Scope and safety

Supported functionality includes the MySQL classic protocol, TCP and Unix
sockets, TLS verification, native and SHA-2 authentication, RSA key exchange,
multiple result sets, table/TSV/CSV/vertical output, and a minimal REPL.

- `LOCAL INFILE`, plugins, completion, history, prepared statements, and
  streaming cursors are intentionally omitted.
- Results are buffered in memory, and SQL parameters are not escaped for you.
- The default `preferred` TLS mode encrypts when available but does not prevent
  downgrade or authenticate the server; use `verify-identity` with a trusted CA
  when identity matters.
- Cleartext authentication requires explicit opt-in and secure transport.
- Python 2.7 and 3.4 reject IP literals with `verify-identity`; use a DNS name.
- Use this software only on systems you own or are explicitly authorized to
  assess.

See [docs/usage.md](docs/usage.md) for the complete CLI, library, authentication,
and compatibility reference.

## Distribution

This fork is released only through GitHub. The wheel and installed `mycli-lite`
command contain the modern artifact; source archives and GitHub releases contain
both standalone files.

Derived from [mycli](https://github.com/dbcli/mycli), with a deliberately smaller
scope and independent implementation. See [ATTRIBUTION.md](ATTRIBUTION.md) and
[LICENSE.txt](LICENSE.txt).
