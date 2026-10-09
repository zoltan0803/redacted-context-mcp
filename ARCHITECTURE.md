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
  <- redacted text plus opaque references
```

The agent should start from a neutral workspace that does not contain the raw
private context files. The MCP server receives tool calls: file tools use the
filesystem source directly, which resolves paths inside the configured root and
reads allowed text files, and GitHub tools call the GitHub source, which
fetches issues for configured aliases. Sources return raw text plus opaque
references, and the server or CLI redacts every content field before returning
only the redacted result. If controlled writes are enabled, generated redacted text
can be rehydrated locally and written under a configured private-root
subdirectory.

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
  and GitHub issue text are returned.

## Source Adapters

Every private data source implements the small `ContextSource` protocol in
`sources.py`. The layering rule is:

- **Sources own identity and reference opaqueness.** A source decides how its
  private identifiers become neutral references (`@p_<id>` / `redctx://p_<id>`
  path ids, `<alias>#<number>` issue refs, `user_<hex>` author aliases) and
  enforces its own containment, exclusion, and never-serve policy.
- **The redaction boundary owns content redaction.** Sources never redact.
  Everything a source yields (file text, file paths used as locators, issue
  titles, bodies, labels, timestamps) is raw and is redacted by the CLI/MCP
  layer (`Redactor`, `rendering.py`, the command functions in `core.py`)
  before it leaves the process.

The protocol surface is deliberately small:

- `name`: stable registry key (`"filesystem"`, `"github"`).
- `untrusted_content`: true for text outside the operator's control, such as
  GitHub issues. Ranked retrieval appends `untrusted_external` to the passage
  header of every passage from such a source. GitHub rendering does not read
  the flag; it labels issue text with fixed field names (`untrusted_title=`,
  `body_untrusted_external:`, `comment_untrusted_external:`).
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
crawled by ranked retrieval. `build_sources` assembles a `SourceRegistry`:
the filesystem source is always present and GitHub appears only when the
config defines `[github.repos.<alias>]`. The MCP server rebuilds the registry
together with the `Redactor` on every accepted policy reload.

Ranked retrieval consumes `iter_documents` from any source, so it does not
walk the filesystem itself. The controlled-write rehydration scan and Ollama
discovery remain filesystem-specific because they need directory entries,
write-subdirectory pruning, and operator-only raw output.

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
   (the in-memory test source uses it); the filesystem source uses
   `consume_file`. GitHub does not iterate documents: its fetches are bounded
   by the response-size cap and per-request page and result limits rather than
   `OperationBudget`.
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
categories are already covered by the baseline regexes). Only the discover
subcommands' own `--detector` (argparse dest `subcommand_detector`) selects
detector discovery; the global `--detector` configures serving, and `--model`
or `--endpoint` combined with the subcommand `--detector` is an error. The
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
   through it, `config`, `filesystem`, `documents`, and `limits`. None of
   the optional detector libraries are imported.

## Module Layout

- `core.py`: CLI commands, parser setup, and compatibility re-exports.
- `server.py`: minimal stdio MCP JSON-RPC server.
- `sources.py`: `ContextSource` protocol, `SourceRegistry`, and
  `build_sources`.
- `rendering.py`: redaction boundary for structured source records (GitHub
  issue summaries and details), shared by the CLI and MCP server.
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
- `config.py`: local TOML config loading and validation.
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
traversal/read budgets, redacts whole documents while preserving line counts, and splits the result
into bounded passages. It orders matches by query-term coverage, then BM25,
with deterministic opaque-reference/line tie-breaking. Only matching redacted
passages and query statistics are retained for the request. Result count and
character limits bound the returned context; exhausted scan budgets fail closed.

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
  personal identifiers, IP addresses, UUIDs, and domains;
- organization suffix patterns;
- multi-token proper names;
- stricter titlecase/acronym handling in `strict` mode.

The allow list prevents common public technologies and generic vocabulary from
being over-redacted. Project-specific allow-list entries belong in the local
`.agent-context-redactor.toml`, not in source control.

Placeholders are deterministic 128-bit HMAC aliases derived from the local
salt, for example `[PERSON_1a2b3c4d5e6f7890a1b2c3d4e5f60718]`. The same raw
value maps to the same placeholder for one private config without exposing the
raw value. Placeholder collisions are detected and fail closed instead of
building an ambiguous rehydration map.

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
state. Adding or removing `[github.repos.<alias>]` tables therefore adds or
removes the GitHub source on the next request.
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

## Security Posture

This project is a privacy guardrail, not a hard isolation boundary. If the agent
process can read the private source folder directly, prompts and MCP routing
are not enough. For stronger enforcement, run the agent as a separate OS user or
inside a container that cannot access the private folder directly, and expose
only the redacted MCP server.
