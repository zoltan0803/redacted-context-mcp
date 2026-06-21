# Changelog

## 0.4.0

- Revalidates stale opaque ids, rejects detected symlink/reparse substitutions,
  and verifies file metadata around content reads where the standard library
  allows.
- Changes default vault-salt handling so missing state creates and persists a
  new random salt, while malformed or unsafe existing state fails closed instead
  of silently rotating aliases.
- Adds per-call redaction receipts, bounded operation budgets, and a bounded
  redacted-only MCP resource cache.
- Preserves line counts when multi-line secrets are redacted before search
  output is split into lines.
- Speeds ordinary no-match literal searches by using a raw-byte prefilter while
  keeping placeholder-sensitive and regex searches on the full redaction path.
- Adds security regression tests, UTF-8 stdio handling, SHA-pinned CI actions,
  and CI package validation for the 0.4.0 release.

## 0.3.0

- Adds redacted MCP resources with `redctx://p_<id>` URIs alongside the
  existing `redctx_*` tools.
- Updates MCP protocol support to `2025-11-25` and advertises read-only tool
  annotations with stricter input schemas.
- Changes path ids to local-salted HMAC ids to make common filename guesses
  harder.
- Changes placeholders from order-based counters to deterministic HMAC aliases,
  such as `[PERSON_1a2b3c4d]`.
- Expands generic redaction coverage for secrets, tokens, common personal
  identifiers, IP addresses, UUIDs, and domains.
- Adds a CLI-only `redctx rehydrate` command for restoring redacted file or
  folder exports locally from the private source root.
- Adds opt-in MCP `redctx_submit_doc` controlled writes for rehydrating generated
  redacted documents into a configured private-root subdirectory.
- Fixes `redctx discover --format json`.
- Handles UTF-8 BOMs in TOML config and text file reads.
- Adds regression coverage for discovery JSON output, MCP resources, stricter
  tool schemas, salted ids, deterministic placeholders, and redaction leak
  benchmarks.

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
