# mycli-lite

[![CI](https://shieldcn.dev/github/xlaesch/mycli-lite/ci.svg?variant=outline&theme=slate&size=xs)](https://github.com/xlaesch/mycli-lite/actions/workflows/ci.yml)
[![Release](https://shieldcn.dev/github/xlaesch/mycli-lite/release.svg?variant=outline&theme=slate&size=xs)](https://github.com/xlaesch/mycli-lite/releases/latest)
[![Python](https://shieldcn.dev/badge/python-3.10%E2%80%933.14-3776ab.svg?variant=outline&theme=slate&size=xs)](#use)
[![License](https://shieldcn.dev/github/xlaesch/mycli-lite/license.svg?variant=outline&theme=slate&size=xs)](LICENSE.txt)

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

## Distribution

This fork is released only through GitHub. Each release attaches only the two
standalone runtime files, `mycli_lite.py` and `mycli_lite_legacy.py`. The wheel
and `mycli-lite` console entry point contain the modern artifact and can be built
locally from source with `python -m build`.

See [docs/usage.md](docs/usage.md) for the complete CLI, library, authentication,
and compatibility reference.

Derived from [mycli](https://github.com/dbcli/mycli), with a deliberately smaller
scope and independent implementation. See [ATTRIBUTION.md](ATTRIBUTION.md) and
[LICENSE.txt](LICENSE.txt).
