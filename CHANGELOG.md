# Changelog

## Unreleased

- Introduces an internal source adapter interface so private data sources
  plug into one redaction boundary. Sources own opaque references (path ids,
  issue references, author aliases); the CLI and MCP layer redacts all content
  before it leaves the process.
- Ports the filesystem root and GitHub issues onto that interface. GitHub
  issues are now fetched as structured records and redacted by a shared
  renderer, and the MCP GitHub tools call the GitHub source directly instead
  of routing through CLI command plumbing. Tool names, schemas, output text,
  error messages, placeholders, path ids, and author aliases are unchanged.
- GitHub issue numbers and comment counts are printed only when upstream sends
  non-negative integers (otherwise `?` and `0`), so crafted upstream values
  cannot bypass redaction. GitHub responses larger than 8 MiB now fail with
  `GitHub response too large.`, and GitHub limit arguments are validated
  before any upstream request.
- Ranked retrieval now ranks documents yielded by a source rather than walking
  the filesystem itself, with identical ranking, citations, and limits.
- Live policy reload rebuilds the whole source registry (filesystem and
  GitHub) together with the redaction rules from the same validated policy. A
  failed rebuild blocks context access and keeps the previous sources, like any
  other invalid policy.
- Adds source conformance tests and pins the advertised MCP tool surface.
- Adds pluggable detectors. The built-in detectors remain the always-on,
  dependency-free baseline; additional local detectors enabled with the
  repeatable `--detector NAME[=ARGUMENT]` option on `redctx` and `redctx-mcp`
  can only add redaction. Detectors nominate spans with canonical placeholder
  categories, and the engine redacts every occurrence through the existing
  deterministic placeholder, collision, and rehydration machinery. The allow
  list wins over plugged detectors, detectors never run on paths, and detector
  failures fail closed with `Detector failed.`. Output without detectors is
  byte-identical, and the MCP tool surface is unchanged.
- Adds the built-in `patterns` detector (`--detector patterns=rules.toml`) for
  operator regex rules. Rules are screened for catastrophic backtracking and
  stress-tested once at startup in a killable process over inputs built from
  each rule's own character classes and literal prefix (including inputs that
  alternate word and non-word characters, which reject `\b`-anchored rules
  such as the common unbounded email regex), at 10,000 and 40,000
  characters (about 2.5 s for 256 simple rules); a rule is rejected by number
  as too slow (over 2 s on one input) or superlinear (more than 8x the CPU
  time on the larger input). Its rules file is never served or overwritten
  when it lies under the root.
- Detector nominations are applied after every built-in stage, so detectors
  never weaken the baseline. Every nominated span is redacted at its own
  position, except characters of allow-listed phrases and existing
  placeholder tokens, even when nominations overlap each other or an allowed
  word, when the baseline already redacted part of it, or when it sits inside
  a longer word; remnants keep only ASCII whitespace and ASCII punctuation at
  their edges. Other occurrences of each value are redacted too, with
  strictly ASCII word boundaries; overlapping occurrences of one value merge
  into one range, so output stays proportional to the text. Nominated case
  variants that `casefold()` and the regex engine treat differently are all
  matched, and the longest value wins across categories.
- Nominations are bounded per text (20,000 spans per detector, 2,000 distinct
  values) and fail closed with `Detector nomination limit exceeded.`. Spans
  over 256 characters or 16 words, and the longest values once a text's values
  exceed 32,768 characters, are redacted only where they were nominated and
  counted as `positional`.
- A directory declared in a detector's `protected_paths` protects everything
  below it.
- `redctx_submit_doc` refuses any `target_path` containing `:`, so an NTFS
  alternate data stream such as `terms.txt:notes` can no longer slip past the
  protected-path checks, and a failed publication removes its temporary file
  and reports `Could not publish output atomically.`.
- `resources/read` errors go through the same safe-message filter as tool
  errors.
- `redctx_submit_doc` refuses to write the config file, term files, detector
  protected paths, and never-serve names (`.env*`, `*.key`, `*.pem`, `*.crt`)
  with `Write target is protected.`, even with `overwrite`.
- Ships `redacted_context_mcp.testing.DetectorConformance` so third-party
  detectors can run the engine's contract tests.
- Third-party detector factories can register under the
  `redacted_context_mcp.detectors` entry-point group.
- Controlled-write rehydration and round-trip verification use the active
  detectors, and live policy reload keeps the same detector instances.
- Receipts gain a `detectors` list (name, version, nominated values,
  positional-only spans) when detectors are active, and the tool output schema
  declares this optional `receipt.detectors` property; `redctx doctor` and
  `redctx audit` report active detectors without their arguments.
- `redctx discover` and `discover-update` accept their own `--detector` to
  draft terms with a local detector instead of an Ollama model. The global
  `--detector` does not switch discovery away from Ollama, and `--model` or
  `--endpoint` together with the subcommand `--detector` is an error.
- Adds the optional `presidio` detector (`pip install
  "redacted-context-mcp[presidio]"`, `--detector presidio[=OPTIONS]`), a
  Microsoft Presidio adapter with options `model`, `language`, `threshold`,
  `entities`, `include_dates`, and `map`. Presidio entity types map to
  canonical categories; unmapped types and dates are skipped by default.
  Missing spaCy models are reported at startup and never downloaded
  implicitly. The adapter makes no network calls and writes nothing at request
  time (its email recognizer uses the Public Suffix List bundled with
  `tldextract` instead of downloading and caching one), keeps spaCy on the CPU
  (`PRESIDIO_DEVICE=cpu` unless set), rejects `map` entity types Presidio does
  not report, and records its version as
  `<presidio-analyzer version>/<spaCy model package>-<model version>`.
- Adds the optional `gliner` detector (`pip install
  "redacted-context-mcp[gliner]"`, `--detector gliner[=OPTIONS]`), a GLiNER
  zero-shot NER adapter with options `model`, `revision`, `threshold`,
  `labels`, `offline`, `window`, `overlap`, and `max_tokens`. Long text is
  analyzed in overlapping windows of at most 300 words and 512 subword tokens
  (label prompt included, counted with the model's tokenizer), so token-heavy
  text cannot hide a later name; runs longer than 64 characters without a
  break are split for windowing, and windows made only of them are skipped.
  `model` must be a Hub id or an absolute path to an existing directory, so a
  relative or mistyped path is never sent to the Hub. Without `offline=true`
  the Hub is contacted at every startup; pin `revision` for reproducible
  detections. Models with a non-whitespace word splitter are rejected.
  Receipts record `<gliner version>/urchade/gliner_small-v2.1` for the default
  model and `<gliner version>/custom` for any other model id or local
  directory.
- Adapter spans of one category nested inside another span of the same
  category collapse into it; nested spans of a different category are kept so
  their other occurrences are redacted. Span ends are extended over trailing
  combining marks, so decomposed accents are never cut off.
- Both adapters are lazy built-ins; importing the package never imports the
  optional libraries, and `dependencies` stays empty. Built-in detectors are
  no longer also registered as entry points, which they could never be
  resolved through. A CI job runs the Presidio adapter against the real
  library.
- Moves the regex backtracking screen into `regex_safety.py`; `core` keeps
  re-exporting it.
- The `patterns` stress test no longer sporadically rejects linear rules
  (such as the bounded email rule) on busy machines. Growth is measured in
  process CPU time instead of wall time, the limit is 8x (midway between
  linear 4x and quadratic 16x) instead of 6x, and a suspicious rule is
  re-timed with interleaved runs up to five times instead of three. The
  2-second wall-time limit per input is unchanged.
- Rewrites the MCP tool descriptions so each one states what the tool returns
  and the shape of its output, when to use it instead of a sibling
  (`redctx_search` versus `redctx_retrieve`, `redctx_tree` versus
  `redctx_list`, `redctx_read` versus `redctx_bundle`, the GitHub list and
  search tools, `redctx_doctor` versus `redctx_audit`), and the limits,
  truncation markers, untrusted-content labels, and network use an agent
  needs to know. Every tool parameter now has a description with its format,
  default, and bounds, and the shared output schema documents `text` and the
  redaction receipt fields. Tool names, parameter names, types, constraints,
  annotations, and behaviour are unchanged. The MCP server instructions now
  name `redctx_search` for exact or regex line matches, and the README lists
  every MCP tool, including the GitHub tools and `redctx_submit_doc`.
- Marks `redctx_github_repos` as closed-world (`openWorldHint: false`): it
  only reads the local repo aliases and never contacts GitHub.

## 0.8.0 — 2026-09-12

- Adds dependency-free `redctx retrieve` / `redctx_retrieve` for ranked,
  redacted passages with opaque references, line citations, and output budgets.
- Adds the optional `documents` extra and explicit `--documents` flag for local
  MarkItDown extraction of DOCX, PPTX, PDF, XLSX, and XLS across context tools.
- Redacts whole files before applying read/head/tail line ranges so multiline
  secrets cannot escape when a range excludes their delimiters.
- Automatically reloads local MCP redaction rules and referenced term files
  before context requests, including updates made by `discover-update`.
- Invalidates cached resources, path indexes, and old rehydration mappings when
  the policy changes. Invalid or removed previously loaded inputs block access
  until repaired, with non-sensitive errors and recovery on a later request.
- Refuses live salt rotation to preserve reference consistency; salt changes
  require restarting the server and obtaining new opaque references.

## 0.7.1

Public-launch polish release.

- Refreshes the README and setup guide around the published PyPI package,
  including a shorter introduction, working quick start, and clearer security
  boundary.
- Adds a self-contained fictional-data demo for auditing, redacted output, and
  MCP server startup without private data or third-party credentials.
- Adds a valid Documentation project link and strengthens CI checks for built
  distributions and installed console commands.
- Separates non-privileged package building from PyPI Trusted Publishing and
  publishes the exact distributions produced by the build job.
- Adds official MCP Inspector smoke validation for the supported legacy and
  modern stdio protocol modes. This is protocol integration coverage, not a
  claim of full MCP conformance.

## 0.7.0

Security hardening release.

- Never serves the redaction config, configured term files, `.env*`, `*.key`,
  `*.pem`, or `*.crt` through redacted tools, even with `--include-private`.
- Redacts bare long hex strings (the persisted vault-salt shape) and
  `salt`-keyed assignments as secrets in the default detector profile, closing
  a vault-salt disclosure path.
- Adds Google API key (`AIza...`) detection to the default secret patterns.
- Screens user-supplied search regexes for catastrophic-backtracking shapes
  and rejects them; MCP searches now enforce a server-side operation deadline
  checked per file and per matching line.
- Caps MCP stdio request line size so clients cannot exhaust server memory.
- Controlled-write rehydration maps no longer scan the write subdirectory,
  preventing agent-written content from poisoning later rehydration.
- Verifies `redctx_submit_doc` output re-redacts consistently on read-back and
  rejects writes that would leak restored values past redaction boundaries.
- Refuses non-loopback plain-http Ollama discovery endpoints unless
  `--allow-remote-endpoint` is passed.
- Truncation no longer splits redaction placeholders mid-token.
- Matches user-supplied search regexes in an isolated, killable child process
  so catastrophic patterns can never hang the single-threaded server; the
  static backtracking screen now also rejects ambiguous dots, negated
  classes, nested-group hazards, and high-repetition bounded quantifiers.
- Case-folds never-serve matching so `.ENV`, `server.PEM`, and similar
  case-mangled variants are refused on case-insensitive filesystems, and
  protects an explicit `--config` file like the default config.
- Redacts salt assignments with short, spaced, or triple-quoted values,
  256-bit-plus hex runs of any length, and underscore-qualified secret
  assignments such as `DB_PASSWORD=...`; treats configured GitHub
  owner/repo identifiers as redaction terms.
- Verifies `redctx_submit_doc` output against both strict and balanced
  redaction modes and builds rehydration maps solely from the scanned
  corpus, closing adjacent-placeholder and interactive-read aliasing gaps.
- Reports an error for oversized unterminated stdio request lines and accepts
  `localhost.` (trailing-dot) Ollama endpoints.

## 0.6.0

- Adds dual-era MCP support for stateless protocol version `2026-07-28` while
  preserving the legacy initialization flow through `2025-11-25`.
- Adds `server/discover`, per-request modern metadata validation, structured
  unsupported-version errors, modern result metadata, and cache hints.
- Keeps opaque path ids, the redacted content cache, and the persistent vault
  salt independent of MCP protocol sessions.

## 0.5.0

- Adds a reusable document-discovery and monotonic TOML-update API plus the
  `redctx discover-update` JSONL CLI for local Git-hook integrations.
- Rejects discovery values absent from their source document and supports
  fail-closed document-size limits and seed-only config merges.
- Adds extended-profile detection for common `sp-`, `svc-`, and `sa-` service
  account identifiers.

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
