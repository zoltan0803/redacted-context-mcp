# Security Invariants

`redacted-context-mcp` is a practical privacy guardrail for local context, not a
formal anonymization system or hard isolation boundary. These invariants define
the guarantees the project aims to keep machine-tested.

## Containment

- Traversal does not follow symlinks.
- Traversal starts from validated paths under the configured root, skips symlink
  and reparse entries, and revalidates paths before content reads and opaque-id
  resolution.
- Opaque path ids are collision-checked before resolution.

## Output Safety

- Configured private values must not appear in CLI output, MCP tool content,
  MCP resources, errors, paths, metadata, or logs.
- Multi-line secrets are redacted before search results are split into lines.
- Dynamic upstream errors are summarized without relaying raw response text.

## Vault Unlinkability

- Default vault salts are random 256-bit values stored in user-local state.
- Default salt files are created under an exclusive lock, read back after
  atomic replacement, and rejected if empty or malformed.
- The same identity produces different GitHub user aliases for different vaults
  and different configured repo aliases.

## Determinism

- Opaque path ids and placeholders remain stable within one vault salt.
- User aliases remain stable within one vault and repo alias.

## Bijection

- Generated redaction placeholders use at least 128 bits of HMAC output.
- Distinct private values cannot silently share one placeholder; collisions
  raise an error instead of building an unsafe rehydration map.

## Write Confinement

- MCP writes are disabled unless explicitly enabled.
- Enabled writes stay under the configured write subdirectory.
- Symlink write destinations are rejected.
- Writes use same-directory atomic replacement.

## Bounded Operation

- Read, bundle, discovery, search, and benchmark commands expose explicit file,
  byte, recursion, or result limits where content could otherwise grow without
  bound.
- MCP resources are cached only after redaction, bounded by bytes, and
  invalidated by file metadata changes or explicit index refresh.

## Protocol Compatibility

- MCP tools expose schemas, output schemas, annotations, and text content for
  compatibility with clients that do or do not consume structured content.
