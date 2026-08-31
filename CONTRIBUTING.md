# Contributing

This project is security-adjacent, so small changes should still be treated with
care. Keep the package boring, explicit, and easy to audit.

## Local Setup

```sh
python3 -m pip install -e .
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile src/redacted_context_mcp/core.py src/redacted_context_mcp/server.py
```

Optional release tooling:

```sh
python3 -m pip install -e '.[dev]'
python3 -m build
python3 -m twine check dist/*
```

## Standards

- Keep runtime dependencies at zero unless there is a strong reason to add one.
- Keep tool output redacted by default and avoid raw paths, owner/repo names,
  author logins, tokens, or sensitive config values.
- Prefer clear, local functions over framework abstractions.
- Keep examples neutral. Do not use real client names, employer names,
  stakeholder names, internal project names, or domain-specific customer
  technology defaults in tracked files.
- Treat `.agent-context-redactor.toml` and generated discovery output as private
  local files.

## Privacy Checks

Before publishing or opening a PR, run:

```sh
rg -n -i '(<your-company>|<client-name>|<private-repo>|<token-prefix>)' .
```

Substitute terms that are relevant to your environment before running the scan.
Some placeholders appear intentionally in docs and examples. Replace anything
that refers to a real organization, client, person, private repo, token, or
project codename.

## Release Checks

At minimum, a release must pass:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile src/redacted_context_mcp/core.py src/redacted_context_mcp/server.py
python3 -m build
python3 -m twine check dist/*
```

## MCP Protocol Validation

The repository's unit tests exercise MCP JSON-RPC behavior directly. The
official MCP Inspector adds an installed-command integration check for both the
legacy initialization lifecycle and the modern stateless lifecycle.

From the repository root, with `redctx-mcp` installed and Node.js 22.19 or
newer available, run:

```sh
npx --yes @modelcontextprotocol/inspector@2.4.0 --cli \
  --config examples/mcp-inspector.json \
  --server redacted_context_legacy \
  --method tools/list \
  --strict
npx --yes @modelcontextprotocol/inspector@2.4.0 --cli \
  --config examples/mcp-inspector.json \
  --server redacted_context_modern \
  --method tools/list \
  --strict
```

These commands validate connection negotiation plus the advertised tool
schemas through the official Inspector. They are protocol smoke tests, not a
claim of full MCP conformance. The official conformance framework's server
runner currently accepts an HTTP URL, while this project intentionally exposes
only stdio transport.
