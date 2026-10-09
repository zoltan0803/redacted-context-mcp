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
- Source adapters return raw content plus opaque references and do not import
  the redaction layer. Every content field they yield (file text and paths,
  issue titles, bodies, labels, states, and timestamps) is redacted by the
  CLI/MCP boundary before output; upstream issue numbers and counts are printed
  only as validated non-negative integers. Source references never contain raw
  paths, logins, or upstream repository names.
- Multi-line secrets are redacted before search results are split into lines.
- Dynamic upstream errors are summarized without relaying raw response text.
- Bare 256-bit-plus hex strings (the persisted vault-salt shape), salt-keyed
  assignments (including short, spaced, and triple-quoted values), and
  underscore-qualified secret assignments such as `DB_PASSWORD=...` are
  redacted as secrets in the default detector profile, so an echoed vault salt
  cannot be served back to an agent.

## Detectors

- The built-in detection baseline always runs. Plugged detectors enabled with
  `--detector` are additive: they can add redaction but cannot replace or
  disable any part of the baseline.
- Detector nominations go through the same deterministic placeholder,
  collision-detection, and rehydration machinery as configured terms.
- Every nominated span is redacted at its own position, except characters
  inside allow-listed phrases or existing placeholder tokens (and ASCII
  whitespace or ASCII punctuation left at the edge of a remnant, such as the
  `-` between two placeholders). This holds when the span overlaps other
  nominations or allow-listed words, when the baseline already redacted part
  of it, when it sits inside a longer word, and when it exceeds a size limit.
  Spans whose whole value is blank, allow-listed, or a reserved placeholder
  word are ignored.
- Other occurrences of each nominated value are redacted too, with the same
  exceptions, as long as the value is within the per-value limits (256
  characters, 16 whitespace-separated tokens) and the alternation budget
  (32,768 characters of values per text, longest values leave first) and its
  span does not overlap an existing placeholder token. Other occurrences
  match through the regex engine's simple case folding, and only where the
  neighbouring characters are not ASCII letters or digits (strictly ASCII:
  `İ`, `ı`, `ſ`, or the Kelvin sign next to a value do not block a match).
  Configured terms use the same boundaries, except that their guard is
  case-insensitive and so also treats those four letters as word
  characters. Case variants that simple case folding does not equate
  (`Weiß` and `WEISS`) are redacted only when each is nominated. Beyond
  those limits only the nominated spans themselves are redacted.
- Detectors run only on original text: they never see or produce placeholders
  or internal markers, and detectors never run on path strings.
- Nominations are applied after every baseline stage, so a plugged detector
  can never prevent or split a baseline redaction: every character the
  baseline redacts without detectors is still redacted, with the same
  placeholder, when detectors are active.
- Nomination volume is bounded per text (20,000 spans per detector, 2,000
  distinct values in total); exceeding a bound fails closed with
  `Detector nomination limit exceeded.`. Over-size spans and values beyond the
  alternation budget do not fail; they are redacted by position only.
- Receipts record, per detector, the number of distinct values it nominated
  into the alternation (`nominated`) and the number of its spans redacted by
  position only because of the size limits or the budget (`positional`).
- Spans are validated (bounds and canonical category) and invalid output fails
  closed. Detector failures fail closed with input-free messages such as
  `Detector failed.`; library, model, and input text is never relayed.
- Detectors must run locally and be deterministic for identical input. This is
  a contract for adapter authors that the engine cannot verify; a non-local or
  non-deterministic detector weakens these guarantees.
- Controlled-write rehydration and round-trip verification use the active
  detectors; a value that is no longer detected makes the write fail closed.
- Detector rule files under the served root (such as `patterns` files), and
  everything under a directory a detector declares as protected, are never
  served, listed, readable, or writable through controlled writes, even with
  `--include-private`.
- `patterns` rules are operator-trusted configuration that runs in-process;
  the static screen and launch-time stress test reduce, but do not remove,
  the risk that a pathological rule stalls the operator's own server.
- Receipts and `redctx doctor` record active detectors by name and version,
  never their arguments, except that the bundled adapters name their public
  model package: `presidio` records the spaCy model package and its version,
  and `gliner` names only its default model (`custom` for anything else).
- The bundled `presidio` and `gliner` adapters make no network calls at
  request time and write nothing to disk. Without `offline=true`, `gliner`
  contacts the Hugging Face Hub at startup, and only with a validated Hub id;
  local-looking model values must be absolute paths to existing directories.

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
  before accessing context. Detected changes replace the policy and every
  registered source together and invalidate cached redacted content, opaque
  path indexes, and old rehydration mappings.
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
- Controlled writes never replace the config file, configured term files,
  detector protected paths (or anything under a protected directory), or
  never-serve names (`.env*`, `*.key`, `*.pem`, `*.crt`), compared
  case-folded, even with `overwrite`.
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
- GitHub API responses are read up to a fixed byte cap (8 MiB); a larger
  response fails closed with an input-free error.
- MCP resources are cached only after redaction, bounded by bytes, and
  invalidated by file metadata changes, redaction mode/config changes, submit
  writes, or explicit index refresh.
- File sizes, line counts, and benchmark timings remain visible metadata side
  channels by design; treat them as coarse structural information about hidden
  content.

## Protocol Compatibility

- MCP tools expose schemas, output schemas, annotations, and text content for
  compatibility with clients that do or do not consume structured content.
