# Architecture

`redacted-context-mcp` exposes a private local knowledgebase through a narrow
redaction layer. The default MCP surface is read-only; controlled writes are
available only when the server is started with explicit write flags. The project
is intentionally small: it avoids runtime dependencies, stores no persistent
index, and keeps all sensitive configuration local.

## Data Flow

```text
agent workspace
  -> MCP client or redctx CLI
    -> redaction boundary (Redactor + rendering)
      -> source registry
        -> filesystem source (private root)    -> raw text + @p_<id> refs
        -> GitHub source (configured aliases)  -> raw issue records + alias#N refs
        -> mail source (configured mailboxes)  -> raw message records + @m_<id>
  <- redacted text plus opaque references
```

The agent should start from a neutral workspace that does not contain the raw
private context files. The MCP server receives tool calls: file tools use the
filesystem source directly, which resolves paths inside the configured root and
reads allowed text files, GitHub tools call the GitHub source, which fetches
issues for configured aliases, and mail tools call the mail source, which reads
local mailbox exports for configured aliases. Sources return raw text plus
opaque references, and the server or CLI redacts every content field before
returning only the redacted result. If controlled writes are enabled,
generated redacted text can be rehydrated locally and written under a
configured private-root subdirectory.

## Core Boundaries

- The server is read-only by default.
- Controlled MCP writes require `--enable-writes` and are constrained to
  `--write-subdir`.
- Path resolution is constrained to the configured root.
- Known private/cache paths and binary-like files are excluded by default.
- File navigation uses local-salted HMAC ids such as `@p_1a2b3c4d5e6f`.
- Filesystem traversal starts from validated paths, skips symlink and reparse
  entries, and revalidates paths before content reads and opaque-id resolution.
- Content reads compare file metadata before and after reading to detect common
  substitutions, but the project remains a guardrail rather than a hard
  concurrent-mutation sandbox.
- Redacted files are available as MCP resources with `redctx://p_<id>` URIs.
- MCP resource content is cached only after redaction and is bounded by byte
  limits.
- The stdio server supports both stateless MCP `2026-07-28` requests and the
  legacy initialization-based protocol through `2025-11-25`.
- Opaque path references are explicit request arguments rather than implicit
  protocol-session state. In-memory path and content indexes are reconstructable
  caches; the persistent vault salt is durable server configuration.
- Redaction happens before file content, file paths, search results, bundles,
  GitHub issue text, and mail are returned.

## Source Adapters

Every private data source implements the small `ContextSource` protocol in
`sources.py`. The layering rule is:

- **Sources own identity and reference opaqueness.** A source decides how its
  private identifiers become neutral references (`@p_<id>` / `redctx://p_<id>`
  path ids, `<alias>#<number>` issue refs, `user_<hex>` author aliases,
  `@m_<id>` message refs) and enforces its own containment, exclusion, and
  never-serve policy.
- **The redaction boundary owns content redaction.** Sources never redact.
  Everything a source yields (file text, file paths used as locators, issue
  titles, bodies, labels, timestamps, mail headers, bodies, and attachments)
  is raw and is redacted by the CLI/MCP layer (`Redactor`, `rendering.py`,
  the command functions in `core.py`) before it leaves the process.

The protocol surface is deliberately small:

- `name`: stable registry key (`"filesystem"`, `"github"`, `"mail"`).
- `untrusted_content`: true for text outside the operator's control, such as
  GitHub issues and mail. Ranked retrieval appends `untrusted_external` to the
  passage header of every passage from such a source. GitHub and mail
  rendering do not read the flag; they label external text with fixed field
  names (`untrusted_title=`, `untrusted_subject`, `body_untrusted_external:`,
  `comment_untrusted_external:`, `attachment_untrusted_external:`).
- `supports_document_iteration`: whether `iter_documents` yields documents for
  source-agnostic scans such as ranked retrieval. (This is unrelated to
  `RedactedContext.documents`, which enables Office/PDF extraction.)
- `owns_reference(ref)` and `resolve_reference(ref)`: syntactic ownership and
  resolution of the source's own opaque references. Raw paths, foreign
  references, and malformed or unknown references are refused with messages
  that never echo raw identifiers. MCP `redctx://p_<id>` resource URIs are
  resolved through the filesystem source's `resolve_reference`.
- `iter_documents(budget, scope=..., patterns=...)`: yield raw
  `SourceDocument(ref, locator, text)` items while charging traversal, file,
  byte, and deadline limits to the shared `OperationBudget`. Exceeding a limit
  fails closed with `OperationLimitError`. Sources that do not declare
  `supports_document_iteration` refuse before any I/O.

`RedactedContext` is the filesystem source. `GitHubSource` serves GitHub
issues as structured `GitHubIssue` / `GitHubComment` records whose authors are
already opaque aliases; it does not offer document iteration, so it cannot be
crawled by ranked retrieval. `MailSource` serves local mailbox exports as
structured `MailSummary` / `MailMessage` records with raw header values and
opaque refs, and iterates messages as documents (see
[Mail Access](#mail-access)). `build_sources` assembles a `SourceRegistry`:
the filesystem source is always present, GitHub appears only when the config
defines `[github.repos.<alias>]`, and mail only when it defines
`[mail.sources.<alias>]`. The MCP server rebuilds the registry together with
the `Redactor` on every accepted policy reload.

Ranked retrieval consumes `iter_documents` from any source, so it does not
walk the filesystem itself. The controlled-write rehydration scan and Ollama
discovery of files remain filesystem-specific because they need directory
entries, write-subdirectory pruning, and operator-only raw output. Mail
discovery (`discover`/`discover-update --source mail`,
`discover_mail_entities` and `sample_mail` in `discovery.py`) lists the scope
newest first through `MailSource.list_messages` and `resolve_reference`, so
each message's date and size are checked before it is read, then reads each
sampled message through `MailSource.iter_documents` under a mail budget. It
takes the same messages' From identities from `MailSource.message_identities`
and turns them into model-free people and one-to-one alias proposals with
`mail_header_aliases`; those proposals reach only a `discover` draft.

### Adding a Source

1. Implement `ContextSource` (`name`, `untrusted_content`,
   `supports_document_iteration`, `owns_reference`, `resolve_reference`,
   `iter_documents`) in its own module.
   Do not import `redaction` or `rendering` from it.
2. Return raw text plus opaque references only. Derive references with the
   vault salt (HMAC) or neutral operator-chosen aliases, and never place raw
   identifiers such as paths, addresses, logins, or upstream names in them.
3. Declare `untrusted_content = True` for anything the operator does not
   control, and label that content in rendered output.
4. Charge every entry, document, byte, and deadline check to the supplied
   `OperationBudget` (`consume_entry`, `consume_file`, `consume_document`,
   `check_deadline`) and fail closed when a limit is exceeded.
   `consume_document` is the hook for documents that are not standalone files
   (the mail source and the in-memory test source use it); the filesystem
   source uses `consume_file`. GitHub does not iterate documents: its fetches
   are bounded by the response-size cap and per-request page and result
   limits rather than `OperationBudget`.
5. Register it in `build_sources` so live policy reload rebuilds it with the
   redactor, and render its output through the redaction boundary.
6. Add it to `tests/test_sources.py` by subclassing `SourceConformance`, and
   keep error messages on the server's safe-message list.

## Detectors

Detection and transformation are separate. The built-in baseline in
`Redactor` (configured terms, regexes for emails, URLs, phones, secrets, IPs,
and the name heuristics) is the detection floor and always runs. Plugged
detectors implement the small `Detector` protocol in `detectors.py`:

```python
@dataclass(frozen=True)
class Span:
    start: int
    end: int
    category: str

class Detector(Protocol):
    name: str
    version: str
    def detect(self, text: str) -> Sequence[Span]: ...
```

The binding design decisions are:

1. **Additive only.** Plugged detectors can only add redaction on top of the
   baseline; they cannot replace or disable any part of it. With no detectors,
   output is byte-identical to the baseline.
2. **Detectors nominate spans; the engine redacts, after the baseline.** A
   detector returns spans over the original text. The engine validates them
   and redacts through the existing placeholder machinery. Detectors run on
   the original text, but their nominations are substituted only after every
   baseline stage (including strict mode's acronym and title-case passes),
   immediately before markers are restored. The baseline is therefore
   authoritative: a nomination can never split a value the baseline would
   have caught (a surname nominated alone cannot stop the name heuristic from
   redacting `Anna Kovacs`), and everything the baseline redacts keeps the
   baseline's category. The intermediate text is mapped back onto
   original-text offsets through per-marker records (each marker's original
   length and the trailer of preserved line breaks that follows it, including
   line breaks orphaned when a later stage stopped right after an inner
   marker). Coverage is then the union, in original offsets, of two kinds of
   ranges, overlaps allowed:
   - every nominated span itself, by position and without any boundary guard
     (so `123456` in `ID123456` or `Ali` in `Aliİ` is redacted), and
   - every occurrence of every value in the alternation (below), found by a
     scan that restarts one character after each match's start, so
     overlapping occurrences are all found. Overlapping and adjacent
     occurrences of the same value merge into one range, so a value that
     overlaps itself (`éé` in a megabyte of `é`) yields one range per run
     rather than one per position, and output stays proportional to the
     number of runs.

   Characters inside allow-listed phrases, existing placeholder tokens, and
   baseline placeholders are subtracted. Overlapping ranges are resolved
   longest first (a merged range ranks as its longest occurrence), then by
   detector order and span order: each claims the characters no earlier
   range claimed. A nominated span, or a range that is exactly one
   occurrence, that claims its whole extent inside one untouched raw run
   becomes one placeholder for the whole value, exactly as before. Every
   other claimed raw run, including every merged range of several
   occurrences, is a remnant (the digits
   strict mode leaves of `TICKET-12345`, or `Contoso` and `Services` around an
   allowed `Data`): it is trimmed of ASCII whitespace and ASCII punctuation at
   its edges only, so combining marks, private-use characters, and emoji are
   redacted, and becomes a placeholder in the claiming range's category.

   The alternation holds each value at most once, deduplicated on its exact
   whitespace-collapsed text, so case variants on which `casefold()` and
   case-insensitive regex matching disagree (`Weiß` and `WEISS`, `ﬁ` and
   `fi`) are each matched when each is nominated; other occurrences are
   found only through the regex engine's simple case folding. Values are
   ordered longest first across categories. Each match's category and rank
   are looked up by its whitespace-collapsed `lower()` form, then its
   `casefold()` form, with `SENSITIVE` as the fallback, so a match is always
   redacted. Matching is case-insensitive, guarded by word boundaries on
   ASCII letters and digits only: the guards are scoped case-sensitive
   (`(?-i:[A-Za-z0-9])`), so `İ`, `ı`, `ſ`, and the Kelvin sign (U+212A) next to a
   value do not block a match. Configured terms keep their older guard,
   compiled under `re.IGNORECASE`, which also treats those four letters as
   word characters (kept for byte-identical output). The guard applies only
   to other occurrences, never to the nominated spans. Detectors never
   produce placeholders and never see internal markers.

   If the mapping ever fails, a conservative fallback works on the
   intermediate text: alternation occurrences are redacted there, every
   exact occurrence of a span's text is redacted, and, because the span's
   own position may be partly consumed by the baseline, every raw run
   between markers whose token next to a marker overlaps the span's text is
   redacted whole as well; the same holds for a token that overlaps an
   alternation value once both are whitespace-collapsed and case-folded,
   because other occurrences can be partly consumed too. No known input
   reaches the fallback; it trades precision for completeness.
3. **Canonical categories.** Spans carry a category from
   `PLACEHOLDER_CATEGORIES`. The placeholder HMAC key includes the category,
   so mapping library labels is the detector's job; unknown categories fail
   closed.
4. **Allow list wins over plugged detectors** (configured terms still beat the
   allow list). Spans whose whole value is allow-listed, a reserved
   placeholder word, empty, or whitespace-only are ignored. Inside a
   nomination, the characters of an allow-listed phrase in the text are never
   redacted, but nothing else of the nomination survives: a nominated `York`
   inside an allowed `New York Times` leaves the phrase as it is, and a
   nominated `Contoso Data Services` with `Data` allowed becomes
   `[ORG_…] Data [ORG_…]`. A span overlapping an existing placeholder token is
   redacted outside the token, but its value never joins the alternation. A
   value nominated under two categories keeps the first, in `--detector`
   order then span order.
5. **Local and deterministic.** Detectors must run locally and return the same
   spans for identical input. The engine cannot verify this; it is a contract
   for adapter authors.
6. **Launch-time, not live-reloaded.** Detectors are enabled with the
   repeatable `--detector NAME[=ARGUMENT]` option on `redctx` and
   `redctx-mcp`, not in the TOML policy. A policy reload rebuilds the
   `Redactor` with the same detector instances, so models load once.
7. **Write path uses the active detectors.** The controlled-write rehydration
   scan and both round-trip verification redactors include the detectors. If a
   value stops being detected, the write fails closed; add the value to the
   configured terms.
8. **Never on path strings.** `redact_path` uses the baseline only.
9. **Receipts record detectors.** When detectors are active,
   `Redactor.receipt()` adds a `detectors` list of `name`, `version`, the
   number of distinct values each detector nominated into the alternation
   (`nominated`), and the number of its spans redacted by position only
   because of the size limits or the alternation budget (`positional`). The
   MCP output schema declares this optional list.
10. **Fail closed with safe messages.** A detector failure at request time
    surfaces as `Detector failed.` (or the invalid-span, category, and
    nomination-limit messages) through `safe_error_message` for MCP and as a
    `SystemExit` for the CLI. `run_detector` guards detection, iteration of
    the returned spans, and span validation together and converts every
    exception except `KeyboardInterrupt` (including `SystemExit` and
    `asyncio.CancelledError`-style `BaseException`s) so a detector cannot
    stop the stdio server; offsets may be any `__index__` integer type.
    Startup errors such as unknown names, or a factory that exits with a
    success status, are reported to the operator's terminal with a non-zero
    exit, without echoing detector arguments.
11. **Bounded.** Per text, each detector may return at most
    `MAX_DETECTOR_SPANS` (20,000) spans and all detectors together at most
    `MAX_NOMINATED_VALUES` (2,000) distinct values; exceeding either fails
    closed with `Detector nomination limit exceeded.`. Spans longer than
    `MAX_NOMINATED_VALUE_CHARS` (256) characters or
    `MAX_NOMINATED_VALUE_TOKENS` (16) whitespace-separated tokens are still
    redacted by position but stay out of the alternation, and are counted as
    `positional`. The alternation also has a budget,
    `MAX_NOMINATED_PATTERN_CHARS` (32,768 characters of values per text):
    beyond it the longest values leave the alternation first and their spans
    become positional too, so beyond the budget only the nominated spans
    themselves are redacted, not their other occurrences. The
    placeholder-overlap check and every segment lookup bisect sorted lists.
    Overlapping ranges are resolved by one sort and then a union-find
    "next unclaimed" array, with path compression, over the elementary
    intervals between distinct range endpoints: each interval is claimed at
    most once and claimed intervals are skipped in amortized near-constant
    time, so resolution is O(n log n) in the number of ranges, dominated by
    the sort, and substitution is O(n log n) overall (250,000 interleaved
    occurrences of 2,000 values in 1 MB take about 6.6 s, against 1.0 s for
    the baseline alone; a 1 MB text with 80,000 nominated occurrences next
    to 80,000 baseline placeholders takes about 2.6 s, against 1.5 s).
    The alternation is built from sorted values so identical nomination sets
    reuse `re`'s compiled-pattern cache. That cache keeps up to 512 compiled
    patterns; at the budget one alternation measures about 0.35 MB (ASCII
    values) to 0.65 MB (values full of case-folding letters such as `k`,
    `s`, `ß`), so the worst-case retention is roughly 180 to 330 MB, down
    from about 5.3 MB per alternation (2.7 GB) at the old 2,000 by
    256-character cap.

Factories have the signature `factory(argument: str | None) -> Detector` and
receive the free-form text after `=`. `load_detectors` resolves names against
the built-in registry (`patterns`, plus the lazy `presidio` and `gliner`
adapters) first and then the `redacted_context_mcp.detectors` entry-point
group; built-ins cannot be shadowed, so they are not also registered as entry
points. The adapter built-ins import their module and optional library only
inside the factory, so importing `detectors`, `redaction`, `core`, `server`,
`testing`, or the adapter modules never imports Presidio, spaCy, tldextract,
GLiNER, transformers, or torch (a test refuses those imports through a
`sys.meta_path` finder). Both adapters parse a comma-separated `key=value`
argument with the shared helpers in `detectors.py`, load their model once at
startup, serialize library calls with a lock, analyze long text in
overlapping windows taken from the original string (Presidio: character
chunks cut at paragraph or line breaks; GLiNER: windows bounded by GLiNER
words and by subword tokens counted with the model's tokenizer, including the
label prompt, because the model silently truncates past its word limit and
attends to a bounded number of tokens), and run results through the shared
`collect_window_spans` helper: library labels map to canonical categories
(unmapped labels are skipped), offsets shift back onto the original text,
span ends extend over trailing combining marks, and `drop_contained_spans`
collapses identical ranges and same-category nesting while keeping nested
spans of another category, whose other occurrences the engine must still
redact. Neither adapter touches the network at request time: Presidio's
`tldextract` is switched to its bundled suffix list with no disk cache, and
GLiNER loads its model only in the factory. A detector may expose `protected_paths` (files or directories it reads,
such as the `patterns` rules file); those under the served root join the
never-serve set through `config.with_protected_paths`, including after live
reloads. A protected directory protects everything below it
(`RedactedContext.is_protected_rel` checks every ancestor, case-folded), and
`redctx_submit_doc` refuses to write any protected path, the config file, a
term file, or a never-serve name.

`patterns` rules are operator-trusted configuration, like the term list: they
run in-process at request time. At startup each rule passes the static
backtracking screen and then a stress test (`regex_safety.regex_stress_report`)
in one killable worker process (the same `run_in_killable_process` machinery
as regex search). The inputs are derived from the parsed rule: a run of each
character that a repeated atom matches (both ends of every range, so
`[一-鿿]+X` meets a run of CJK characters and `[0-9a-f]+g` a run of
hex digits), every pairing of a word character with a non-word character
from those repeated atoms cycled, alone and after the literal prefix (`a.`
for an email rule, `eyJA-` for a JWT rule: a word boundary at every position
starts a new attempt, which exposes `\b`-anchored rules over classes that mix
`.` or `-` with word characters), the literal prefix in its own, upper, and
lower case followed by a run of the next atom's character, the rule's
one-character-per-atom
skeleton and its near miss cycled, and generic word, digit, and punctuation
inputs. Every input is timed at 10,000 and 40,000 characters. A rule is
rejected by number as "too slow" when one run exceeds 2 seconds of wall
time (the worker is killed), or as "superlinear" when the larger input
takes more than eight times as much CPU time as the smaller one (linear
growth is 4x, quadratic 16x; 8x is their geometric midpoint, a 2x margin
on both sides). Growth is measured with `time.process_time`, so other
processes preempting the worker inflate neither run, and is judged only
when the larger run takes at least 20 ms of CPU time. Where the CPU clock
is coarse (Windows advances it in 15.625 ms ticks, measured at worker
start) one tick of error is allowed in the rule's favour and the smaller
run is also bounded by its wall time. A suspicious pair is re-timed, small
and large runs interleaved, up to five runs each, and rejected only when
the fastest large run still exceeds eight times the fastest small run, so
CPU frequency changes and core migration do not reject linear rules. This catches the
common quadratic shapes (`[A-Z]+\d`, unanchored `[A-Z][A-Z0-9]+-\d+`,
`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`) but is
not a guarantee: a pathological rule can still stall the operator's own
server, so rules should be anchored and simple. Spawning the worker needs
the usual `multiprocessing` main-module guard in any script that loads
detectors.

`DetectorDiscoveryClient` in `discovery.py` adapts detectors to the
`DiscoveryClient` protocol for `redctx discover --detector` (PERSON to people,
ORG to organizations, CLIENT to clients, SENSITIVE and ENTITY to terms; other
categories are already covered by the baseline regexes; post-processing may
drop values, but never moves a value into another of these buckets or to
`allow`). Only the discover
subcommands' own `--detector` (argparse dest `subcommand_detector`) selects
detector discovery; the global `--detector` configures serving, and `--model`
or `--endpoint` combined with the subcommand `--detector` is an error. The
client sets `route_tool_names = False`, which both its own post-processing pass
and the merge pass in `discover_entities`/`discover_documents` honour (the
merge pass reads the attribute from the client, defaulting to `True`), so a
lowercase detector term is never moved to `allow` by the tool/package-name
heuristic: an allow-listed value is also exempt from detector nominations at
serving time, so the move would disable the operator's own rule. The
bridge lives in `discovery.py` so `detectors.py` stays a leaf module that
`redaction.py` can import without pulling in sources.

### Adding a Detector

1. Implement `Detector` in its own package or module and map library labels to
   canonical categories. Do not import `redaction`, `rendering`, `server`, or
   `core`.
2. Expose `factory(argument: str | None) -> Detector`; parse the single
   argument string yourself and raise `SystemExit` with an operator-facing
   message for bad arguments. Load models once in the factory, not per call.
3. Register the factory under `[project.entry-points."redacted_context_mcp.detectors"]`.
4. Check it against the engine's contract by mixing the shipped
   `redacted_context_mcp.testing.DetectorConformance` into a
   `unittest.TestCase` and implementing `make_detector` (and optionally
   `positive_texts`). The module itself depends only on the standard library
   and the leaf `detectors` and `defaults` modules, so third-party packages
   can use it directly. It is not free in import cost, though: importing
   `redacted_context_mcp.testing` first imports the package root
   (`redacted_context_mcp/__init__.py`), which imports `discovery` and,
   through it, `config` (and with it `redaction`, for alias-group
   validation), `filesystem`, `documents`, and `limits`. None of the
   optional detector libraries are imported.

## Module Layout

- `core.py`: CLI commands, parser setup, and compatibility re-exports.
- `server.py`: minimal stdio MCP JSON-RPC server.
- `sources.py`: `ContextSource` protocol, `SourceRegistry`, and
  `build_sources`.
- `rendering.py`: redaction boundary for structured source records (GitHub
  issue summaries and details; mail lists, messages, threads, attachments,
  and mail retrieval through the mail redactor and its cache), shared by the
  CLI and MCP server.
- `defaults.py`: default limits, allow lists, exclude lists, and compiled
  patterns.
- `models.py`: shared dataclasses.
- `redaction.py`: text/path redaction logic.
- `detectors.py`: `Detector` protocol, `Span`, span validation, the built-in
  `patterns` detector, option and span helpers for adapters, and the detector
  registry (`load_detectors`).
- `detectors_presidio.py`: optional Presidio adapter (`--detector presidio`,
  extra `presidio`); imports `presidio_analyzer` only in its factory.
- `detectors_gliner.py`: optional GLiNER adapter (`--detector gliner`, extra
  `gliner`); imports `gliner` only in its factory.
- `regex_safety.py`: catastrophic-backtracking screen, the killable regex
  worker process, and the launch-time stress test, shared by search regexes
  and detector rules.
- `testing.py`: shipped `DetectorConformance` contract tests for detector
  authors.
- `config.py`: local TOML config loading and validation, including alias
  groups.
- `config_reload.py`: request-boundary policy change detection, stable reloads,
  and fail-closed handling of invalid or missing policy inputs.
- `paths.py`: root-constrained path resolution and opaque path ids.
- `filesystem.py`: filesystem source (`RedactedContext`): read-only
  traversal, text-file detection, and document iteration.
- `documents.py`: optional local MarkItDown extraction through explicitly
  selected format converters and a bounded worker process.
- `retrieval.py`: transient passage tokenization and ranking over redacted
  text from any source that supports document iteration.
- `discovery.py`: local Ollama discovery workflow and post-processing.
- `github.py`: GitHub source (`GitHubSource`): read-only issue fetching
  through neutral aliases, structured records, and author aliases.
- `mail.py`: mail source (`MailSource`): read-only mbox, Maildir, and `.eml`
  readers, the bounded header index, `@m_` refs, the header allow-list, HTML
  to text, quote and signature collapsing, and attachment extraction.

## Retrieval and Documents

`RedactedContext.read_text` is the shared input path for context reads. With
`--documents`, supported local binary documents are read as verified bytes and
passed to a short-lived worker. That worker invokes the selected MarkItDown
converter directly, without auto-detection, plugins, URLs, or cloud clients.
Raw extracted Markdown returns over a local pipe and is redacted before tool
output or resource caching. Source bytes, expanded OOXML size, extracted text,
and worker duration are bounded. No raw extraction cache or persistent index is
created. Plain-text reads do not import MarkItDown.

`redctx_retrieve` scans the filesystem source's documents under existing
traversal/read budgets (or, with `source` `mail`, the mail source's messages
under the mail budget), redacts whole documents while preserving line counts,
and splits the result into bounded passages. It orders matches by query-term
coverage, then BM25, with deterministic opaque-reference/line tie-breaking.
Only matching redacted passages and query statistics are retained for the
request. Result count and character limits bound the returned context;
exhausted scan budgets fail closed.

## Controlled Write Path

`redctx_submit_doc` is hidden unless the server starts with `--enable-writes`.
When enabled, it accepts generated redacted text, rebuilds the local
rehydration map from the private source root, rejects unresolved placeholders,
and writes the restored document only under `--write-subdir`. Targets that
must never be served (the config file, term files, detector protected paths
and everything under protected directories, and never-serve names such as
`.env*` or `*.key`) are refused with `Write target is protected.`, with or
without `overwrite`.

The write tool does not accept arbitrary workspace file paths. It accepts text
content directly and a relative target path. Overwrites require an explicit
`overwrite` argument. Tool results return only redacted path metadata and opaque
ids.

No-overwrite writes are published from a same-directory temporary file without
replacing an existing target where hard-link publication is available. Explicit
overwrites use same-directory `os.replace`. Directory durability fsync is
best-effort and POSIX-only.

## Redaction Model

Redaction combines configured exact terms with conservative generic patterns:

- configured clients, organizations, people, and sensitive terms;
- email addresses, URLs, phone numbers, handles, secrets, tokens, common
  personal identifiers, IP addresses, UUIDs, and domains (a short list of
  generic endings plus two-letter country codes, without the ones that are
  mostly file extensions, such as `md` or `rs`);
- organization suffix patterns;
- multi-token proper names, whose words may wrap onto the next line but never
  cross a blank line;
- names after identity labels such as `Attendees:` or `Owner:`, which keep the
  label, and speaker labels at the start of a line;
- stricter titlecase/acronym handling in `strict` mode.

Markdown heading lines are handled apart from the text around them, because
headings capitalize generic words by convention. On a heading line the
proper-name and strict title-case passes keep the built-in `HEADING_TERMS`
(for example `Next`, `Steps`, `Contact`, `Budget`) and redact everything else,
and no proper name crosses the heading's end. Heading words are kept raw, not
allow-listed, so plugged detectors can still redact them.

The allow list prevents common public technologies and generic vocabulary from
being over-redacted. Project-specific allow-list entries belong in the local
`.agent-context-redactor.toml`, not in source control.

Placeholders are deterministic 128-bit HMAC aliases derived from the local
salt, for example `[PERSON_1a2b3c4d5e6f7890a1b2c3d4e5f60718]`. The same raw
value maps to the same placeholder for one private config without exposing the
raw value. Placeholder collisions are detected and fail closed instead of
building an ambiguous rehydration map.

The built-in stages that run before configured terms (secrets, URLs, emails,
ids, IP addresses, card and phone numbers, domains, handles, plus the extended
profile's identifiers) are listed in pipeline order in two tables,
`EARLY_BASELINE_STAGES` and `EXTENDED_BASELINE_STAGES` in `redaction.py`,
which `Redactor` walks in turn.

### Alias Groups

`[redaction.aliases]` maps a canonical value to the other forms of one entity.
`config.py` validates the groups against the final term lists and resolves
each group's category: the first of clients, organizations, people, and terms
that holds the canonical value, which is the category the configured-term
stage already gives it. Every check fails closed with a message that names the
group by position only. The canonical value must reach the configured-term
stage intact, so a value that a default-profile early stage matches (an email
address, say) is refused as a canonical value.

`Redactor` turns the groups into two things. The aliases join their group's
category in the configured-term stage, so they are redacted in their own right
with the usual boundaries and longest-match ordering. And `alias_links` maps
each normalized alias to the group's entity hex (the canonical value's
ordinary placeholder hex) and its form suffix, the first 32 bits of
`HMAC(salt, "alias-form:" + normalized alias)`. `Redactor.placeholder` is the
single place where placeholders are minted, so whichever stage or plugged
detector redacts an alias, in whatever category, the result is
`[<CATEGORY>_<entity hex>.<form suffix>]`. The canonical value has no link
entry and keeps its ordinary placeholder. A linked alias also registers the
ordinary placeholder it would have without its group, for collision checks
and in the rehydration map (never in output), so documents redacted before
the group was declared still rehydrate. Collision checks, rehydration maps,
and receipts otherwise work on these placeholders unchanged; every
placeholder matcher (`PLACEHOLDER_RE` and the patterns built from it,
including path redaction, truncation, retrieval tokens, and rehydration)
accepts the optional suffix.

Discovery can propose groups. `DiscoveryResult.aliases` carries proposals
whose values all occur in the sampled source (model suggestions under an
`aliases` key must occur as whole words in their own file), and
`DiscoveryResult.dropped_aliases` counts what was dropped; `as_dict()` stays
the term buckets only. `propose_alias_groups` in `discovery.py` adds the
deterministic proposals (standalone, unambiguous first names and email local
parts that spell one known name). `config.merge_alias_proposals` is the
lenient twin of the loader's validation: it applies the same rules but drops
and counts instead of failing, keeps existing groups exactly, and only
appends. `discover` runs it against the draft's own lists so the draft loads
as written; `discover-update` runs it against the merged lists, for the seed's
groups always and for discovered groups only with
`--include-discovered-aliases`, then `write_alias_additions` rewrites only the
entries that grew, appends new groups, and parses the result back. It does
not read the vault salt, so the form-suffix check stays with config loading.

## Configuration

The local `.agent-context-redactor.toml` file is intentionally ignored by git.
It may contain exact client names, stakeholder names, project codenames, private
repo names, and token environment variable names.

If a config or environment salt is not supplied, the loader creates or reuses a
random 256-bit vault salt in user-local state. Missing state creates a new
random salt. Existing empty, malformed, or root-contained state fails closed
instead of rotating aliases silently. `redctx doctor` reports the salt source.

`redctx discover` can draft that file with a local Ollama model. It is a setup
command for a human operator, not an MCP tool, because its output intentionally
contains raw sensitive terms.

The MCP server probes config and term-file metadata before tool execution and
resource listing/reads. Unchanged requests keep the existing policy and cache.
Changed inputs are loaded twice around dependency snapshots, including newly
referenced term files. A validated policy replaces the source registry and
redactor together and clears cached content, path indexes, and rehydration
state. Adding or removing `[github.repos.<alias>]` or `[mail.sources.<alias>]`
tables therefore adds or removes the GitHub or mail source on the next request;
a reload also drops the mail indexes and the cached mail redactor.
Invalid, unreadable, unstable, or removed previously loaded inputs block
context requests and clear the content cache; the next request retries. Public
protocol discovery and tool schemas remain available during recovery.

Live reload refuses salt rotation to avoid silently invalidating references.
Environment, launch-option, and external salt-state changes require a restart.
Metadata checks are a local workflow guardrail, not a concurrent-mutation
sandbox, and do not revoke content already returned to a client.

## GitHub Issue Access

GitHub repositories are configured by neutral aliases under
`[github.repos.<alias>]`. The alias is what the agent sees. Raw owner/repo names
and author logins are not printed in tool output. Author aliases are HMACs over
the local vault salt, repo alias, and login so they are not linkable across
vaults or repo aliases.

The GitHub source is read-only and uses the token environment variable
named in local config. It returns structured issue records with raw,
untrusted text and opaque author aliases; `rendering.py` redacts titles,
bodies, labels, states, and timestamps when formatting them for the CLI and
MCP tools, which share the same code path. Issue numbers and comment counts
are kept only when upstream sends non-negative integers (otherwise they print
as `?` and `0`). Each upstream response body is capped at 8 MiB; larger
responses fail with an input-free error.

## Mail Access

The mail source (`mail.py`, `MailSource`, registry name `"mail"`) serves local
mailbox exports read-only: mbox files, Maildir directories, and loose `.eml`
files. There is no IMAP, OAuth, network access, or send capability. It is
additive: without `[mail.sources.*]` tables nothing is registered, and file
and GitHub output is byte-identical whether or not mail is configured.

### Configuration

```toml
[mail.sources.inbox]
path = "exports/inbox.mbox"   # absolute, ~-relative, or relative to the root
format = "mbox"               # mbox | maildir | eml
max_messages = 50000          # optional index cap per mailbox
max_message_bytes = 26214400  # optional per-message read cap (25 MiB)
```

The table key is the neutral mailbox alias that the agent sees; it must match
`[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. `format` is required (no sniffing). `eml`
accepts one `.eml` file or a directory walked recursively for `*.eml`.
Invalid tables fail closed with messages that never echo a path. A mailbox
path inside the served root is added to `protected_paths`, so file tools never
list, read, search, or bundle the raw export; a mailbox path equal to the root
is refused. Mailbox paths are never printed, so they are not added as terms.

### Reading

Parsing uses the stdlib `email` package (`BytesParser`, `policy.default`,
`headerregistry`). The stdlib `mailbox` classes are not used for I/O:
`mailbox.mbox` opens the file `rb+`, and neither class can charge a budget
before reading or refuse symlinks. Instead a small reader opens files `rb`
only and never locks, renames, flags, or writes anything (Maildir `new/`
messages are not moved to `cur/`):

- mbox: messages split at `From ` lines like the stdlib reader; `>From `
  body lines are unescaped one level.
- Maildir: regular files directly in `cur/` and `new/` (never `tmp/`),
  sorted by name. A missing `cur/` or `new/` counts as empty.
- eml: the file, or `*.eml` files under the directory, sorted by relative
  path.

Directory readers skip dot-entries, symlinks, and reparse points, and a
mailbox path that is itself a symlink or reparse point is refused with
`Mailbox could not be read.`.

Each mailbox has an in-memory header index built by reading at most 256 KiB
of each message's header block. An entry holds the raw storage locator
(offset and length, or file path), size, parsed date, Message-ID,
In-Reply-To, References, address pairs, and subject. Building it charges one
entry per message against `max_messages`, the header bytes against a 1 GiB
total, and a 120 s deadline (plus the caller's deadline, if any), and fails
closed with `Mailbox message limit exceeded.`, `Mailbox header byte limit
exceeded.`, or `Operation deadline exceeded.` rather than indexing part of a
mailbox. The index is cached on the source under a metadata fingerprint (mbox
size and mtime; Maildir and eml entry names, sizes, and mtimes), rebuilt when
the fingerprint changes, and dropped with the source on policy reload. It is
never persisted. Every operation probes the fingerprint of every configured
mailbox first, because identity harvesting needs all of them, so any
unreadable mailbox fails every mail call. Reading a message re-checks that
file's size, mtime, and identity before and after the read and refuses
messages over `max_message_bytes`.

### References

- Message: `@m_<12 hex>` = `HMAC(salt, "mail-message:" + Message-ID)`, with
  the Message-ID stripped of whitespace and angle brackets. A message without
  a usable Message-ID uses `HMAC(salt, "mail-message-headers:" +
  sha256(header block))` instead, with CRLF line endings normalized to LF
  first, so the same message stored with either line ending keeps its ref.
  The same message in two mailboxes has one ref and resolves to the first in
  config order, then storage order. Two Message-IDs with one ref fail closed
  with `Mail reference collision.`.
- Threads: `In-Reply-To` and `References` are rendered as `@m_` refs through
  the same HMAC, whether or not the target message is in a mailbox. At most
  256 ids are kept per header (the first 255 and the last, so the root and
  the direct parent survive). `thread: @m_<hex>` is the ref of the thread
  root as the message records it (first References id, else In-Reply-To,
  else its own id). `redctx_mail_thread` returns the connected component of
  Message-ID, In-Reply-To, and References links in the index, ordered by date
  then ref, with undated messages last.
- Attachment: `@m_<12 hex>/<n>`, the 1-based position among the message's
  attachment parts in MIME walk order. An attachment ref resolves by reading
  its message and checking that the part exists.
- Nested attachment: a forwarded message's attachments extend the path.
  `@m_<hex>/2/1` is attachment 1 of the forwarded message that is attachment
  2 of `@m_<hex>`; a ref holds one to four segments (three nested levels plus
  a leaf). Every segment but the last must name a readable nested message
  within range, and anything else is `Unknown source reference.`. Listing and
  numbering are unchanged, so top-level attachment refs stay stable.
- A nested message gets no `@m_` message ref. Its Message-ID, In-Reply-To,
  and References are never hashed into refs or rendered, and it never enters
  the header index, lists, threads, or retrieval; it is addressed only by its
  attachment ref. A forwarded copy is sender-controlled: minting refs from
  its Message-ID would let a forwarder make the copy pose as, or thread
  into, an indexed message.

Raw Message-IDs, mailbox paths, storage keys, and filenames never appear in
refs or errors. Refs are keyed by the vault salt, so they are unlinkable
across vaults.

### Header Policy

Only an allow-list is rendered: `Date`, `From`, `Sender`, `Reply-To`, `To`,
`Cc`, `Bcc`, and `Subject`. Every other header is dropped, including
`Received`, `Return-Path`, `DKIM-Signature`, `ARC-*`,
`Authentication-Results`, `Delivered-To`, `List-*` (including
`List-Unsubscribe`), and all `X-*` headers. `Message-ID`, `In-Reply-To`, and
`References` appear only as refs.

- `Date` is parsed and printed as generated UTC ISO 8601
  (`2026-10-01T08:15:00Z`), so neither the raw string nor the sender's UTC
  offset is shown; unparseable dates print `?`.
- Address headers are redacted structurally. Each display name and address
  becomes a placeholder minted directly with `Redactor.placeholder`, not by
  pattern matching, whether or not it is configured and whether or not an
  e-mail pattern would match it (`root@localhost` included). A display name
  that is a configured term keeps that term's category and placeholder;
  others are `PERSON`. Group names are display names. A header that does not
  parse prints `[unparsed]` and is not harvested. Because the stdlib parser
  recovers from malformed input differently across Python versions, a header
  counts as parsed only when it reports no defects other than obsolete
  syntax and every address has a local part and a domain; group labels such
  as `undisclosed-recipients:;` still parse.
- `Subject` is decoded (RFC 2047), redacted as content, and labelled
  `untrusted_subject`.

Nested (forwarded) messages go through the same allow-list: index entries
and nested records take their fields from one helper (`header_fields`), so
the two cannot drift apart.

### Identity Harvesting and Linking

Every mail operation redacts with a mail redactor derived from the active
`Redactor` (`Redactor.for_mail`). It keeps the config, mode, and detectors,
shares the receipt counters, and has its own placeholder caches, so mail
never changes what file or GitHub tools print. On top of the base pipeline it
adds:

- The `(display name, address)` pairs from `From`, `Sender`, `Reply-To`,
  `To`, `Cc`, and `Bcc` of every indexed message in every configured mailbox.
  Harvesting the whole index rather than the messages a call returns makes
  the result a function of the mailboxes, config, and salt, and redacts a
  correspondent's name in every message body, not only in their own
  messages. Harvested values live only in memory.
- Harvested names join the configured-term stage as `PERSON` terms, with
  "Last, First" also added as "First Last". A name is not harvested as a
  body term when it is already configured, allow-listed, reserved, longer
  than the alias limits (256 characters or 16 words), claimed by an early
  baseline stage (it contains an address or URL), or a single token shorter
  than three characters or in the common-word lists. It is still redacted
  structurally in headers. A harvested name that contains a configured
  client or organization term ("Jordan Brightwater" with the organization
  "Brightwater") is matched in its own `PERSON` pattern before the
  configured terms, so that term cannot split it and leave the rest raw.
- Harvested addresses join the same stage as `EMAIL` terms, so an address
  that the e-mail pattern misses is still caught in bodies. A redactor with
  such extra terms compiles each term pattern with a first-character
  dispatch (alternatives grouped behind a lookahead on their first
  character), which keeps thousands of identities fast; redactors without
  extra terms compile exactly as before. Building a mail redactor for
  thousands of identities still takes a noticeable fraction of a second, so
  the MCP server caches one per policy and identity set (`MailRedactorCache`
  in `rendering.py`) and drops it on reload; the CLI builds one per call.
- Links are anchored on the address. The entity of an unconfigured harvested
  name is its address's ordinary `EMAIL` hex (or that address's configured
  group entity), and its form suffix is `alias_form_suffix(salt, name)`, so
  `From: Jordan Lee <jordan@example.com>` renders as `[PERSON_<e>.<f>]
  <[EMAIL_<e>]>`, and "Jordan Lee" in any body is the same `[PERSON_<e>.<f>]`.
  Addresses are never re-anchored: they keep their ordinary placeholder
  unless a configured alias group links them, configured people keep their
  configured placeholder, and configured links always win. A name seen with
  more than one address is not linked; it is still redacted as a `PERSON`
  term.
- Mail stages run before the early baseline, in this order: full URLs,
  including every query string, redacted whole as `URL` exactly as the `URL`
  stage would, so no later mail stage can split one; scheme-less links with a
  path or query (`example.com/reset?token=...`) as `URL`; one-time codes after
  a code keyword on the same line (`code`, `passcode`, `OTP`, `PIN`,
  `verification`, `2FA`, ...), redacted as `SECRET` without the keyword;
  opaque tokens of 24 or more `[A-Za-z0-9_-]` characters that mix letters
  and digits as `SECRET`; and prompt-injection phrases as
  `PROMPT_INJECTION`, whatever the detector profile.

Nested message headers never join the global harvest:
`MailSource.identities()` covers top-level header blocks only. Walking every
attachment would mean reading every full message, and a forwarded copy is
sender-controlled, so it must not alter the links every other call uses.
Instead, a call whose ref passes through nested messages (rendering one, or
reading a leaf attachment inside one) collects the address-header pairs of
every nested message on the ref's path and redacts with a call-local mail
redactor (`Redactor.for_mail(identities, unlinked=pairs)`): names and
addresses are harvested from both sets, links from the global pairs only. So
the forwarded sender's name in the forwarded body gets the same placeholder
as in its nested header, a globally linked name keeps its global
`[PERSON_<e>.<f>]`, and a name seen only in forwarded copies gets its plain
`PERSON` placeholder. The call-local redactor is never cached, and when the
nested pairs add nothing new the cached mail redactor is used, so a nested
read never changes another call's output.

Anchoring on the address rather than the name is deliberate. Addresses are
the unique, stable key of a mail identity, while display names vary between
clients and messages; a name-anchored entity would give one address a
different placeholder from message to message and a different placeholder
from the one files and GitHub produce. Rehydration for controlled writes
still scans only the private root, so mail-only placeholders are not
restorable there.

### Bodies and Attachments

- `multipart/alternative` prefers `text/plain`. HTML-only bodies are
  converted with a `html.parser.HTMLParser` subclass: `script`, `style`,
  `head`, `title`, `template`, `noscript`, comments, and elements hidden with
  the `hidden` attribute or an inline `display:none` or `visibility:hidden`
  are dropped; block elements become line breaks, `li` becomes `- `, links
  keep their text plus an `http(s)` or `mailto` target in angle brackets,
  images keep their `alt` text, and `blockquote` and quote containers become
  `> ` lines. Parts are decoded with their declared charset and
  `errors="replace"`. Invisible characters (`U+00AD`, `U+034F`, `U+061C`,
  `U+115F`, `U+1160`, `U+17B4`, `U+17B5`, `U+180E`, `U+180F`,
  `U+200B`-`U+200F`, `U+202A`-`U+202E`, `U+2060`-`U+206F`, `U+3164`,
  `U+FE00`-`U+FE0F`, `U+FEFF`, `U+FFA0`, `U+FFF9`-`U+FFFB`, and the tag and
  supplementary variation-selector blocks `U+E0000`-`U+E007F` and
  `U+E0100`-`U+E01EF`) are removed during extraction so they cannot hide
  text or split a name or address. The converter stays linear on hostile
  markup: unmatched end tags cost O(1), text goes only to the innermost open
  link (a link that contains another link always shows its target), and at
  most 32 `> ` quote prefixes are rendered per line.
- Quoted replies and signatures are collapsed by default: runs of `>` lines
  with the attribution line before them ("... wrote:"), and Outlook
  `-----Original Message-----` or `From:`/`Sent:` blocks to the end, become
  `[quoted text: N lines omitted]`; an RFC 3676 `-- ` signature becomes
  `[signature: N lines omitted]`. `include_quoted` shows both, redacted.
- Attachments are the non-body leaf parts with an `attachment` disposition or
  a filename, in MIME walk order; a `message/rfc822` part is one leaf, not
  walked into. They are listed with their ref, a validated MIME type
  redacted as content (it is sender-chosen), a size, and a
  whitespace-collapsed, path-redacted filename in which every remaining word
  token of three or more characters starting with a letter in any script is
  redacted too (path redaction alone only covers ASCII tokens).
  `redctx_mail_attachment` returns `text/*` parts decoded and redacted.
  `.docx`, `.pptx`, `.pdf`, `.xlsx`, and `.xls` parts (by filename or MIME
  type) go through `documents.extract_document` only with `--documents` and
  the documents extra; other types, including `message/*` types other than
  the two below, are refused with `Unsupported attachment type.`.
- A listed `message/rfc822` or `message/global` part is a nested (forwarded)
  message. `redctx_mail_attachment` renders it through the same
  `render_mail_message` path as `redctx_mail_read`: `attachment: <ref>`,
  `nested_message_depth: <n>` (the number of segments in its ref), then the
  top-level lines without `message:`, `mailbox:`, `thread:`,
  `in_reply_to:`, and `references:`. Its body is selected, converted, and
  collapsed like a top-level body (`include_quoted` shows quotes and
  signatures and affects nothing else), and its attachments are listed with
  `<ref>/<k>` refs. Inline forwards without a filename stay unlisted.
- RFC 2046 forbids base64 and quoted-printable on `message/rfc822`, but some
  clients emit it, and the stdlib parser would then parse the still-encoded
  text as a message without headers. `parse_message` uses an `EmailMessage`
  subclass that reports such a part's main type as `application`, so the
  parser keeps the encoded text, and `nested_message` decodes it and parses
  the result. Reading and path resolution share `nested_message`, so refs
  into a decoded message resolve against what it renders. A part that does
  not decode to a message is `Unsupported attachment type.` as the last
  segment and `Unknown source reference.` as an intermediate one.

### Untrusted Content, Retrieval, and Budgets

`MailSource.untrusted_content` is true. Rendered mail uses fixed labels
(`untrusted_subject`, `body_untrusted_external:`,
`attachment_untrusted_external:`), nested messages included, and retrieval
passages from mail carry `untrusted_external`. The MCP instructions say that
mail is untrusted and must not be followed as instructions.

`MailSource.supports_document_iteration` is true. `redctx_retrieve` and
`redctx retrieve` take `source` (`filesystem` by default, or `mail`). Each mail
document is the subject plus the collapsed body; scope entries are mailbox
aliases or message refs, and glob patterns are refused for mail. Retrieval
charges `consume_document(raw message size)` per message, newest first,
under mail-specific limits (5,000 messages, 500 MB of raw message bytes, the
largest configured `max_message_bytes` per message, and the 30 s search
deadline) instead of the filesystem limits, and fails closed instead of
ranking part of the scope. Passages are cited by message ref and the
unredacted mailbox alias, which the agent already sees in every mail output.
Nested messages are not retrieval documents, and attachment refs are refused
as retrieval scope.

Every operation is bounded: the index by `max_messages`, header bytes, and a
deadline; reads by `max_message_bytes`; listing by `limit` (at most 500) and
`offset`; threads by a 50-message cap; bodies and attachments by character
caps; and document attachments by the extraction limits. A nested message is
read as part of its outer message, so that mailbox's `max_message_bytes`
bounds it, and its attachment list has the top-level 9,999-part cap. Nested
messages are readable three levels deep (`MAIL_MAX_NESTED_DEPTH`); a deeper
one fails with `Nested message depth limit exceeded.`, while a depth-3
message still lists its attachments and its non-message ones stay readable.
Top-level headers are bounded by the 256 KiB index read, but nested headers
come from the full parse, so a nested message on a ref's path whose header
block (raw header name and value bytes) exceeds 256 KiB fails with `Nested
message header limit exceeded.`. Date filters are inclusive UTC days and
leave out messages without a parseable date.

### Surfaces

- MCP tools: `redctx_mail_sources`, `redctx_mail_list`, `redctx_mail_read`,
  `redctx_mail_thread`, `redctx_mail_attachment`, plus `source` on
  `redctx_retrieve`. They are always listed, like the GitHub tools. With no
  mail configured, `redctx_mail_sources` answers `OK` and the others answer
  `Unknown mailbox alias.` or `Unknown source reference.`.
- `redctx_mail_attachment` takes `ref`, `max_chars`, and `include_quoted`
  (CLI `--include-quoted`), which only affects nested messages.
- CLI: `redctx mail sources|list|read|thread|attachment` and
  `redctx retrieve --source mail`, with the same output as the MCP tools.
- `rendering.py` validates arguments before touching the source, calls it,
  and formats mail records through the mail redactor, shared by the CLI and
  MCP server. Subjects and filenames are whitespace-collapsed before
  redaction so one record stays one line. Every content field goes through
  the mail redactor, never the base redactor; because the mail redactor
  shares the base redactor's counters, MCP receipts include mail
  redactions.
- `redctx doctor` reports `mail_sources` and per-format counts, never aliases
  or paths.

## Security Posture

This project is a privacy guardrail, not a hard isolation boundary. If the agent
process can read the private source folder directly, prompts and MCP routing
are not enough. For stronger enforcement, run the agent as a separate OS user or
inside a container that cannot access the private folder directly, and expose
only the redacted MCP server.
