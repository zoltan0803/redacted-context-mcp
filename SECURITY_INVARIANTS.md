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
  issue titles, bodies, labels, states, and timestamps, mail subjects, bodies,
  display names, addresses, attachment filenames, and attachment text) is
  redacted by the CLI/MCP boundary before output; upstream issue numbers and
  counts are printed only as validated non-negative integers, and mail dates
  only as generated UTC timestamps. Source references never contain raw
  paths, logins, upstream repository names, Message-IDs, or mailbox storage
  keys.
- Text from outside the operator's control (GitHub issues and mail) is
  labelled as untrusted external content in tool output and in ranked
  retrieval passages.
- Multi-line secrets are redacted before search results are split into lines.
- Dynamic upstream errors are summarized without relaying raw response text.
- GitHub request errors name only the neutral repo alias and the HTTP status
  code; the upstream owner/repo, API URL, and configured token environment
  variable name never appear in them.
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

- Opaque path ids and placeholders remain stable within one vault salt,
  including alias forms for an unchanged alias group.
- User aliases remain stable within one vault and repo alias.

## Bijection

- Generated redaction placeholders use at least 128 bits of HMAC output.
- Distinct private values cannot silently share one placeholder; collisions
  raise an error instead of building an unsafe rehydration map.
- Declared alias forms add a 32-bit form suffix to their group's 128-bit
  entity hex. A config in which two aliases of one group would share a suffix
  is refused, and any other clash still fails through the collision check.

## Alias Groups

- Alias groups exist only in `[redaction.aliases]` of the local config:
  written by the operator, carried from a reviewed `--seed-config`, or merged
  from discovery only with `discover-update --include-discovered-aliases`.
  The config is never served, and no other persisted store of raw values is
  created.
- Discovery's alias proposals are review-only in `redctx discover`. Every
  proposed value occurs in the sampled source, and every proposal passes the
  same checks as a hand-written group, against the draft or the merged lists,
  before it is written. Invalid, unsourced, or conflicting proposals are
  dropped and only counted; their values never appear in output or errors.
- Alias merging in `discover-update` is monotonic: existing groups are never
  removed or rewritten, and a proposal that conflicts with them is skipped and
  counted.
- Linking is an intentional, bounded disclosure: an agent learns that the
  declared forms belong to one entity (they share the canonical placeholder's
  entity hex) and nothing more about the values.
- The canonical value's placeholder is never changed by alias groups, so
  existing redacted documents still rehydrate. A canonical value that is not
  configured, or that a built-in stage redacts before configured terms, is
  refused.
- Each alias form is redacted in its own right, and every stage and plugged
  detector that redacts it produces `[<CATEGORY>_<entity hex>.<form suffix>]`
  in its own category. The suffix is an HMAC keyed by the vault salt over the
  normalized form, domain-separated from placeholder digests, so it can be
  neither computed nor checked without the salt.
- Invalid alias groups fail closed. Their messages name groups by position
  only and never echo a canonical value or alias; `doctor` and `audit` report
  counts only.
- Rehydration maps for alias forms are rebuilt from the scanned source corpus
  like every other placeholder; an alias's previous placeholder in the same
  category restores it too, so documents redacted before the group was
  declared still rehydrate. Controlled writes re-redact restored alias forms
  before publication.

## Mail

- Mail access is read-only and local. Mailbox files are opened `rb` only,
  never through the stdlib `mailbox` classes, and nothing is written, locked,
  renamed, or flagged; Maildir `new/` messages stay in `new/`. Mailbox bytes,
  modification times, and directory layout are unchanged by every operation.
  The mail source makes no network requests.
- Directory readers skip dot-entries, symlinks, and reparse points, and a
  mailbox path that is itself a symlink is refused. Unreadable mailboxes fail
  with input-free messages.
- Only `Date`, `From`, `Sender`, `Reply-To`, `To`, `Cc`, `Bcc`, and `Subject`
  are rendered. Every other header value, including `Received`,
  `Return-Path`, `DKIM-Signature`, `ARC-*`, `Authentication-Results`,
  `Delivered-To`, `List-*`, and `X-*`, never appears in output; dates are
  regenerated as UTC.
- Every display name and address in an address header is replaced by a
  structural placeholder, whether or not it is configured and whether or not
  a pattern would match it. A header that does not parse, reports
  non-obsolete defects, or holds an address without a local part and a
  domain renders `[unparsed]` and contributes no harvested identity, on
  every supported Python version.
- Message, thread, and attachment refs are `@m_<hex>` HMACs over the vault
  salt. Raw Message-IDs, mailbox paths, storage keys, and filenames never
  appear in refs or errors, and every mail error is a fixed message.
- Harvested names and addresses are kept in memory only, in a mail redactor
  derived per policy with its own placeholder caches. Mail never changes file
  or GitHub output; configured people, terms, and alias-group links win over
  harvested links; addresses keep their ordinary `EMAIL` placeholder; and a
  name seen with more than one address is not linked.
- Mail content is labelled untrusted (`untrusted_subject`,
  `body_untrusted_external:`, `attachment_untrusted_external:`, and
  `untrusted_external` on retrieval passages).
- Hidden HTML (scripts, styles, `hidden` and inline-hidden elements) and
  invisible characters (zero-width and bidi format characters, the soft
  hyphen, the combining grapheme joiner, invisible fillers, variation
  selectors, and tag characters; the full list is in `ARCHITECTURE.md`) are
  removed before redaction, so they can neither carry hidden text nor split
  a name or address.
- Attachment MIME types are redacted as content, and attachment filenames
  are path-redacted with every remaining token of three or more letters and
  digits that starts with a letter in any script redacted too. `_`,
  brackets, and every other non-alphanumeric character separate tokens, and
  a token may start after digits.
- A UTF-8, UTF-16, or UTF-32 byte-order mark wins over a text part's
  declared charset. A text attachment that still decodes to NUL characters or
  to more than 15% replacement characters is refused with `Unsupported
  attachment type.`, and such a body is withheld whole as `[body omitted: not
  text]`, so wide-encoded or binary text cannot slip past redaction.
- A harvested name that contains a configured client or organization term
  is matched before the configured terms, so the term cannot split the name
  and leave the rest of it raw.
- Mailbox exports configured under the served root are never listed, read,
  searched, bundled, or served as resources by the file tools.
- Each mailbox index is bounded by `max_messages`, a 256 KiB per-message
  header read, 1 GiB of header bytes, and a deadline; reads by
  `max_message_bytes`; listing by `limit` and `offset`; threads by a message
  cap; output by character caps; document attachments by `--documents` and
  the extraction limits; and mail retrieval by message, byte, and deadline
  limits. Exceeding a limit fails closed.
- Live policy reload adds or removes the mail source and drops its indexes
  and cached mail redactor together with the policy.

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
- Mail indexes, message reads, lists, threads, bodies, attachments, and mail
  retrieval are bounded by message counts, byte caps, character caps, and
  deadlines, and fail closed instead of serving part of a mailbox as if it
  were complete.
- MCP resources are cached only after redaction, bounded by bytes, and
  invalidated by file metadata changes, redaction mode/config changes, submit
  writes, or explicit index refresh.
- File sizes, line counts, and benchmark timings remain visible metadata side
  channels by design; treat them as coarse structural information about hidden
  content.

## Protocol Compatibility

- MCP tools expose schemas, output schemas, annotations, and text content for
  compatibility with clients that do or do not consume structured content.
