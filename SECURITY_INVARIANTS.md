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
- The redaction config (default or explicit `--config`), configured term
  files, `.env*`, `*.key`, `*.pem`, and `*.crt` files are never served,
  listed, or readable through redacted tools, even when the operator passes
  `--include-private`. Matching is case-folded so case-mangled variants such
  as `.ENV` or `server.PEM` are refused on case-insensitive filesystems.

## Output Safety

- Configured private values must not appear in CLI output, MCP tool content,
  MCP resources, errors, paths, metadata, or logs.
- Multi-line secrets are redacted before search results are split into lines.
- Dynamic upstream errors are summarized without relaying raw response text.
- Bare 256-bit-plus hex strings (the persisted vault-salt shape), salt-keyed
  assignments (including short, spaced, and triple-quoted values), and
  underscore-qualified secret assignments such as `DB_PASSWORD=...` are
  redacted as secrets in the default detector profile, so an echoed vault salt
  cannot be served back to an agent.

## Retrieval and Document Extraction

- Ranked retrieval tokenizes and scores redacted text, never raw content or raw
  filenames. Complete placeholders and opaque file references remain usable.
- Content is redacted before passage splitting and read/head/tail line slicing.
- Optional document extraction requires `--documents`. Enabling it preserves
  configured exclusions, protected paths, and path-containment checks.
- Workers receive only verified local bytes and the supported extension, with
  no URL or private filename. Only the selected converter runs; plugins and
  cloud/model clients are not enabled. Parser diagnostics are suppressed.
- Extraction has source-byte, OOXML expansion, output-character, and worker-time
  limits. These are workflow guards, not a memory sandbox or formal guarantee
  against hostile parser inputs. Failed conversions never return raw diagnostics.

## Live Policy Updates

- MCP tool calls and resource listing/reads check config and term-file metadata
  before accessing context. Detected changes replace the policy and invalidate
  cached redacted content, opaque path indexes, and old rehydration mappings.
- Invalid or unreadable policy inputs, or disappearance of a previously loaded
  config or still-referenced term file, block context access rather than serving
  with stale rules. Error responses contain no raw parser or filesystem details.
- Repairing the inputs allows a later request to recover. Salt rotation requires
  restart or restoration of the original salt.
- Reload checks operate at request boundaries and are subject to the same
  concurrent-mutation limitations as filesystem reads. Already returned content
  cannot be revoked.

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
- Rehydration maps for controlled writes are derived solely from the scanned
  source corpus: the write subdirectory is never scanned, and aliases created
  by earlier interactive reads cannot leak into the map, so agent-written
  content cannot extend or poison later rehydration.
- Before publication, restored content is re-redacted under both strict and
  balanced modes and rejected when any restored value or distinctive value
  token would survive read-back redaction (for example when glued into a
  surrounding token that defeats word boundaries).
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
- User-supplied search regexes are matched inside an isolated child process
  that is terminated when the deadline expires; CPython's `re` engine cannot
  be interrupted mid-match in-process, so process isolation is the hard bound.
- User-supplied regexes are additionally screened for catastrophic
  backtracking shapes (nested or high-repetition quantifiers and ambiguous
  alternations) and fail closed before any match attempt. The screen is a
  fast-fail mitigation, not a proof of safety; the killable worker is the
  enforcement boundary.
- MCP stdio request lines are size-capped so a client cannot exhaust server
  memory with an unbounded line, including unterminated final lines.
- MCP resources are cached only after redaction, bounded by bytes, and
  invalidated by file metadata changes, redaction mode/config changes, submit
  writes, or explicit index refresh.
- File sizes, line counts, and benchmark timings remain visible metadata side
  channels by design; treat them as coarse structural information about hidden
  content.

## Protocol Compatibility

- MCP tools expose schemas, output schemas, annotations, and text content for
  compatibility with clients that do or do not consume structured content.
