# Security policy

## Supported versions

Until the first stable release, security fixes are made only on the latest
`0.x` release and the default branch.

## Reporting a vulnerability

Use the repository's private vulnerability-reporting feature under the GitHub
Security tab. If private reporting is unavailable, open a public issue asking
the maintainer to establish a private channel, without including vulnerability
details.

Include:

- the mycli-lite version and SHA-256 of the artifact;
- Python, operating system, architecture, and database server versions;
- the authentication plugin, transport, and TLS mode;
- a minimal sanitized reproduction and the expected security property; and
- whether credentials, local files, terminal output, or protocol state can be
  exposed or modified.

Do not include real credentials, private hostnames, customer data, or sensitive
query output.

## Security boundaries

mycli-lite is a low-level client, not a sandbox, ORM, or safe query builder. It
executes SQL supplied by the caller with the connected account's privileges.
It intentionally refuses `LOCAL INFILE`, but a database server can still return
untrusted data and error messages. Review the security caveats in
`docs/usage.md` before using it against an untrusted server.

Use mycli-lite only on systems you own or are explicitly authorized to assess.
