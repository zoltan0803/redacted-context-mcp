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
- The redaction config, configured term files, `.env*`, `*.key`, `*.pem`, and
  `*.crt` files are never served, listed, or readable through redacted tools,
  even when the operator passes `--include-private`.

## Output Safety

- Configured private values must not appear in CLI output, MCP tool content,
  MCP resources, errors, paths, metadata, or logs.
- Multi-line secrets are redacted before search results are split into lines.
- Dynamic upstream errors are summarized without relaying raw response text.
- Bare 128-bit-plus hex strings (the persisted vault-salt shape) and
  `salt`-keyed assignments are redacted as secrets in the default detector
  profile, so an echoed vault salt cannot be served back to an agent.

## Vault Unlinkability

- Missing default salt state creates and persists a new random 256-bit salt in
  user-local state.
- Default salt files are created under an exclusive lock, read back after
  atomic replacement, and rejected if empty or malformed.
- The same identity produces different GitHub user aliases for different vaults
  and different configured repo aliases.
- Placeholders are deterministic HMACs over the vault salt. Anyone holding the
  salt can verify dictionary guesses against placeholders, so the salt is
  treated as key material: keep it in the local config or user-local state
  rather than `REDACTED_CONTEXT_SALT`, which is visible in process
  environments on some platforms.

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
- Rehydration maps for controlled writes never scan the write subdirectory, so
  agent-written content cannot extend or poison later rehydration.
- Before publication, restored content is re-redacted and rejected when any
  restored value would survive read-back redaction (for example when glued
  into a surrounding token that defeats word boundaries).
- No-overwrite writes publish a fully written same-directory temporary file
  without replacing an existing target where hard links are supported. Overwrite
  writes use same-directory atomic replacement. Directory fsync is best-effort
  and POSIX-only.

## Bounded Operation

- Read, tail, stat, bundle, discovery, search, audit, benchmark, resource
  listing, path-index refresh, and controlled-write rehydration scans expose
  explicit file, byte, recursion, deadline, or result limits where content could
  otherwise grow without bound.
- MCP-driven searches enforce a server-side operation deadline evaluated per
  file and per matching line.
- User-supplied search regexes are screened for catastrophic-backtracking
  shapes (nested quantifiers and overlapping alternations under unbounded
  quantifiers) and fail closed; the screen is a mitigation, not a proof, so
  deadlines back it up between matches.
- MCP stdio request lines are size-capped so a client cannot exhaust server
  memory with an unbounded line.
- MCP resources are cached only after redaction, bounded by bytes, and
  invalidated by file metadata changes, redaction mode/config changes, submit
  writes, or explicit index refresh.
- File sizes, line counts, and benchmark timings remain visible metadata side
  channels by design; treat them as coarse structural information about hidden
  content.

## Protocol Compatibility

- MCP tools expose schemas, output schemas, annotations, and text content for
  compatibility with clients that do or do not consume structured content.
