# Safe Quick-Start Demo

This demo uses only fictional names, reserved `.example` domains, reserved
example phone numbers, and non-secret project identifiers. It needs no private
data, network access, local model, or third-party credentials.

Run the commands from the repository root after installing
`redacted-context-mcp` from PyPI:

```sh
pipx install redacted-context-mcp
redctx --root examples/quickstart/context \
  --config examples/quickstart/context/demo-redaction-config.toml audit
redctx --root examples/quickstart/context \
  --config examples/quickstart/context/demo-redaction-config.toml \
  bundle . --glob "*.md" --max-files 10
redctx-mcp --root examples/quickstart/context \
  --config examples/quickstart/context/demo-redaction-config.toml
```

The audit should report `PASS` checks. The bundle command prints representative
redacted content with category placeholders such as `[ORG_<opaque-id>]`,
`[PERSON_<opaque-id>]`, `[EMAIL_<opaque-id>]`, and `[DOMAIN_<opaque-id>]`.
Opaque ids are derived from a local vault salt, so their exact values will
differ. File listings and MCP resources use opaque `@p_<id>` and
`redctx://p_<id>` references.

The final command starts the stdio MCP server and waits for a client; press
Ctrl-C when running it directly in a terminal. To inspect both supported MCP
protocol modes with the official MCP Inspector, see the validation commands in
[CONTRIBUTING.md](../../CONTRIBUTING.md).

The demo's `demo-redaction-config.toml` is intentionally committed because all
of its values are fictional. A real `.agent-context-redactor.toml` can contain
private terms and should remain untracked.
