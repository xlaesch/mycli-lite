# mycli-lite

`mycli_lite.py` is a single-file MySQL classic-protocol client for Python 3.10 through 3.14. It uses only the Python standard library and works as both a command-line program and an importable module. Direct transfer requires no installation or runtime dependency on the target.

## Transfer and run

Copy the one file to the target and invoke it with Python:

```console
$ sha256sum mycli_lite.py
$ scp mycli_lite.py operator@target:/tmp/
$ ssh operator@target 'chmod 700 /tmp/mycli_lite.py'
$ ssh operator@target 'python3 /tmp/mycli_lite.py --version'
mycli-lite 0.1.0
```

It can also be executed directly after `chmod +x mycli_lite.py` when `/usr/bin/env python3` is available.

Common uses:

```console
# Prompt for a password and open the REPL.
$ python3 mycli_lite.py -h db.internal -u analyst -p inventory

# Execute SQL and emit stable TSV when stdout is redirected.
$ python3 mycli_lite.py -h db.internal -u analyst -p \
    -e 'SELECT user, host FROM mysql.user' > users.tsv

# Read multiple statements from stdin or a UTF-8 file.
$ printf 'SHOW DATABASES; SELECT VERSION();' | \
    python3 mycli_lite.py -h 10.0.0.15 -u root --password-env DB_PASSWORD
$ python3 mycli_lite.py -S /run/mysqld/mysqld.sock -u root -f checks.sql

# Require TLS, or verify a server against a trusted CA and hostname.
$ python3 mycli_lite.py -h db.internal -u analyst -p --ssl-mode required
$ python3 mycli_lite.py -h db.internal -u analyst -p \
    --ssl-mode verify-identity --ssl-ca internal-ca.pem
```

Do not put a password directly in a command argument. `-p` prompts through `getpass`; `--password-file PATH` reads its first line; and `--password-env NAME` reads the explicitly named variable. `MYSQL_PWD`, DSN passwords, option files, and login paths are not read.

## Library API

The convenience function `connect()` constructs and immediately connects a `Connection`:

```python
from mycli_lite import ServerError, connect

try:
    with connect(
        host='db.internal',
        user='analyst',
        password='secret',
        database='inventory',
        ssl_mode='required',
    ) as connection:
        for result in connection.query('SELECT id, name FROM assets LIMIT 20'):
            if result.has_rows:
                print([column.name for column in result.columns])
                for row in result.rows:
                    print(row)
            else:
                print(result.affected_rows)
except ServerError as exc:
    print(exc.code, exc.sqlstate, exc.message)
```

Use `Connection(...)` directly for delayed connection. Its constructor accepts:

- `host='127.0.0.1'`, `port=3306`, `user=<OS user>`, `password=''`, `database=None`, and `unix_socket=None`;
- `charset='utf8mb4'`, one of `ascii`, `latin1`, `utf8`, `utf8mb3`, or `utf8mb4`;
- `ssl_mode='preferred'`, `ssl_ca`, `ssl_cert`, and `ssl_key`;
- `connect_timeout=10.0`;
- `multi_statements=True`;
- `get_server_public_key=False`, `server_public_key=None`, and `allow_cleartext_plugin=False`;
- `max_message_size=67108864`, the maximum accepted logical protocol message.

The connection is synchronous and supports `connect()`, `close()`, `ping()`, `select_db(name)`, and `query(sql)`. `execute` is an alias of `query`. A connection is a context manager and exposes `connected`, `secure`, `tls_active`, `tls_version`, `server_version`, `connection_id`, `server_capabilities`, `client_capabilities`, and `server_status`.

`query()` returns a `list[Result]`, including every result set produced by a multi-statement query or stored procedure. Each `Result` contains column metadata, buffered row tuples, affected-row and last-insert IDs, warning count, status flags, and server info text. Text-protocol values are returned as `str`, binary string/blob/bit fields with binary charset metadata as `bytes`, and SQL `NULL` as `None`; values are not converted to Python numeric or date types.

The exception hierarchy is `MySQLError`, with `MySQLConnectionError`, `AuthenticationError`, `ProtocolError`, and `ServerError`. `ServerError` exposes `code`, `sqlstate`, and `message`.

`write_results()` formats a `list[Result]` as `table`, `tsv`, `csv`, or `vertical`, with separate result and status streams. The CLI resolves its `auto` choice before calling this function.

## CLI behavior

```text
python3 mycli_lite.py [OPTIONS] [DATABASE]
```

Connection options:

- `-?, --help` prints usage; `--version` prints the artifact version.
- `-h, --host HOST`: command value, then `MYSQL_HOST`, then `127.0.0.1`.
- `-P, --port PORT`: command value, then `MYSQL_TCP_PORT`, then `3306`.
- `-S, --socket PATH`: command value, then `MYSQL_UNIX_SOCKET`. A socket takes precedence over TCP settings.
- `-u, --user USER`: command value, then `MYSQL_USER`, then the current OS user.
- positional `DATABASE` or `-D, --database DATABASE`, but not both.
- `-p, --password`, `--password-env NAME`, and `--password-file PATH` are mutually exclusive.
- `--charset`, `--connect-timeout`, TLS options, and authentication opt-ins described below.

Input modes:

- `-e, --execute SQL` sends the argument and exits.
- `-f, --file PATH` reads an entire UTF-8 file; `-f -` reads stdin.
- With neither option, non-TTY stdin is read in full as batch SQL.
- With neither option and a TTY on stdin, the interactive REPL starts.
- Empty batch input exits successfully without connecting.

`-e` and `-f` are mutually exclusive. Input is sent as one `COM_QUERY`; it is not split or rewritten locally. Multi-statements are enabled by default, so semicolon-separated input can yield multiple `Result` objects. A server error aborts the command, and the CLI has no `--force` or partial-result output mode. Client directives such as `DELIMITER` and `SOURCE` are not interpreted.

Output options:

- `--format auto|table|tsv|csv|vertical`; in batch mode, `auto` uses a table when stdout is a TTY and TSV otherwise. The REPL resolves `auto` to table output.
- `-N, --skip-column-names` suppresses headers.
- `--null TEXT` changes the SQL `NULL` marker from its default, `NULL`.

Text control characters and backslashes are escaped, binary values are written as lowercase hexadecimal prefixed with `0x`, and CSV/TSV quoting is handled by the standard-library `csv` module. Rows go to stdout; diagnostics and interactive status go to stderr. Batch status is printed only when stdout is a TTY.

The REPL waits for a semicolon outside quotes/comments, `\g`, or `\G`. `\G` selects vertical output for that query. Its built-in commands are `\q`/`quit`/`exit`, `\c`, `\u DATABASE`, `\s`, and `\?`. Ctrl-C clears an input buffer; Ctrl-C during a query closes the connection and exits 130. Ctrl-D exits normally.

CLI exit codes are:

- `0`: success or normal REPL exit;
- `2`: argparse or local input configuration error;
- `3`: connection, TLS, or authentication failure;
- `4`: server `ERR` packet in batch mode;
- `5`: protocol or other client-level MySQL error in batch mode, or a lost REPL connection;
- `130`: interrupted query or process;
- `141`: broken output pipe.

## Authentication and TLS

The implemented authentication plugins are:

- `mysql_native_password` challenge-response;
- `caching_sha2_password`, including fast and full authentication;
- `sha256_password`;
- `mysql_clear_password` only with `--allow-cleartext-plugin`, and only over TLS or a Unix socket.

SHA-2 full authentication uses the clear password only inside TLS or over a Unix socket. On plaintext TCP it can use a pinned PEM key supplied by `--server-public-key PATH`, or request the server key with `--get-server-public-key`. RSA OAEP encryption and PEM parsing are implemented in the file without a cryptography package.

`--ssl-mode` has these behaviors:

- `disabled`: plaintext TCP;
- `preferred` (default): use TLS when advertised, otherwise continue over plaintext TCP;
- `required`: require TLS, without validating the certificate;
- `verify-ca`: require TLS and validate the certificate chain;
- `verify-identity`: additionally validate the certificate hostname against `--host`.

Unix sockets are treated as secure local transport and are not wrapped in TLS, regardless of SSL mode. `--ssl-cert` and `--ssl-key` provide a client certificate. A key without a certificate is rejected when TLS is initialized.

Security caveats:

- The default `preferred` mode neither prevents capability-stripping downgrade nor validates server identity. Use `required` to prevent plaintext fallback, and `verify-identity` with a trusted CA to authenticate the server. Merely passing `--ssl-ca` does not enable verification unless a verify mode is selected.
- `--get-server-public-key` trusts a key obtained over the same unauthenticated connection and is vulnerable to an active man-in-the-middle. Prefer TLS verification or a separately obtained pinned key.
- `mysql_native_password` and plaintext TCP do not provide transport confidentiality. `mysql_clear_password` deliberately requires both an explicit opt-in and secure transport.
- Environment variables may be visible to other local processes. Password files with group/other permission bits produce a warning but are still read.
- `-p` refuses to prompt when neither stdin nor `/dev/tty` is an interactive terminal, preventing a password prompt from consuming piped SQL. Use `--password-file` or `--password-env` in headless processes.
- Multi-statements increase the impact of SQL injection. Library callers handling untrusted input should set `multi_statements=False`, but this module has no parameter binding and is not an application ORM or safe query builder.
- `LOAD DATA LOCAL INFILE` is never advertised or serviced. A server request aborts and closes the connection so an untrusted server cannot request a local file.
- `connect_timeout` bounds socket setup and authentication. Successful connections return to blocking reads, so long-running queries are not cut off by that setting.
- Each result is buffered fully in memory. The 64 MiB message limit bounds one logical protocol message, not the total size of all rows.

## Compatibility and omissions

The module implements protocol-v10 greetings, protocol-4.1 capabilities, packet fragmentation, classic text queries, multiple statements/results, classic EOF-terminated result sets, OK/ERR packets, and explicit database selection. It is intended for MySQL 5.7/8.x and MariaDB servers that use a supported authentication plugin, but compatibility depends on the server's advertised classic-protocol behavior.

It does not implement old pre-4.1 authentication, prepared/binary protocol, parameter binding, compression, LOCAL INFILE, connection attributes, MFA, Kerberos/GSSAPI, MariaDB ed25519/dialog plugins, Windows named pipes/shared memory, automatic socket discovery, automatic reconnect, query cancellation, streaming cursors, DSNs/config files/keyrings, SSH tunnels, completion, highlighting, history, pager/editor/shell integration, destructive-query warnings, client-side `DELIMITER`, or output logging.

Invalid bytes in non-binary text fields are decoded with replacement characters. Use binary columns when byte-for-byte preservation matters.

## Test the artifact

The strongest quick portability check starts Python without site initialization or site-packages:

```console
$ python3 -I -S ./mycli_lite.py --version
mycli-lite 0.1.0
$ python3 -I -S ./mycli_lite.py --help >/dev/null
```

The repository unit tests use scripted sockets and cover packet framing, length-encoded fields, authentication scrambles and RSA OAEP, a full handshake/query/quit exchange, multiple results, LOCAL INFILE rejection, output escaping, REPL statement termination, and standard-library-only imports:

```console
$ uv run -- pytest -q tests/test_mycli_lite.py
```

For an authorized live target, exercise both the chosen authentication path and transport before relying on the artifact:

```console
$ python3 -I -S ./mycli_lite.py -h db.internal -u analyst -p \
    --ssl-mode required -e 'SELECT VERSION(); SHOW STATUS LIKE "Ssl_cipher";'
```

Recompute and compare `sha256sum mycli_lite.py` after transfer to detect truncation or modification.
