# Security Invariants

`redacted-context-mcp` is a practical privacy guardrail for local context, not a
formal anonymization system or hard isolation boundary. These invariants define
the guarantees the project aims to keep machine-tested. A `PASS` audit status
means the named check was actively evaluated for the current run; it is not a
claim of hard OS isolation.

## Containment

- Traversal does not follow symlinks.
- Traversal starts from validated paths under the configured root, skips symlink
  and reparse entries, and revalidates paths before content reads and opaque-id
  resolution.
- Content reads verify file metadata before and after the read. A process that
  can mutate the source tree concurrently can still race standard-library path
  opening on some platforms; run the agent without direct private-root access
  for hard isolation.
- Opaque path ids are collision-checked before resolution.

## Output Safety

- Configured private values must not appear in CLI output, MCP tool content,
  MCP resources, errors, paths, metadata, or logs.
- Multi-line secrets are redacted before search results are split into lines.
- Dynamic upstream errors are summarized without relaying raw response text.

## Vault Unlinkability

- Missing default salt state creates and persists a new random 256-bit salt in
  user-local state.
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
- No-overwrite writes publish a fully written same-directory temporary file
  without replacing an existing target where hard links are supported. Overwrite
  writes use same-directory atomic replacement. Directory fsync is best-effort
  and POSIX-only.

## Bounded Operation

- Read, tail, stat, bundle, discovery, search, audit, benchmark, resource
  listing, path-index refresh, and controlled-write rehydration scans expose
  explicit file, byte, recursion, deadline, or result limits where content could
  otherwise grow without bound.
- MCP resources are cached only after redaction, bounded by bytes, and
  invalidated by file metadata changes, redaction mode/config changes, submit
  writes, or explicit index refresh.

## Protocol Compatibility

- MCP tools expose schemas, output schemas, annotations, and text content for
  compatibility with clients that do or do not consume structured content.
