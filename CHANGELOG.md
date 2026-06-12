# Changelog

## 0.1.0

- Initial release candidate.
- Adds `redctx` CLI for redacted local file discovery, read, search, stat, and
  bundle operations.
- Adds `redctx-mcp` stdio MCP server exposing `redctx_*` tools for coding
  agents.
- Supports opaque stable path ids, local TOML redaction configuration, and
  no-dependency runtime operation.
- Adds `redctx discover`, an offline setup command that uses a local Ollama
  model to draft raw redaction terms for human review.
- Discovery output is generically post-processed to reduce noisy `terms`
  entries and move public/default-allowed technical vocabulary to `allow`.
- Adds optional redacted GitHub issue access through configured neutral repo
  aliases and MCP tools.
