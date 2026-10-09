"""Pluggable detectors that nominate sensitive spans for the redaction engine.

Detection and transformation are separate jobs. The built-in baseline in
``redaction.Redactor`` always runs and is unchanged. A plugged detector only
*nominates* character spans over the original text, each with a canonical
placeholder category; the engine validates the spans and, after every
baseline stage, redacts whatever the baseline left of each nominated span (by
position) and of the other occurrences of each nominated value, through the
existing placeholder, collision, and rehydration machinery. Detectors never
see or produce placeholders and never run on path strings. Request-time
volume is bounded by the ``MAX_*`` limits below.

This module is a leaf: it must not import ``redaction``, ``rendering``,
``server``, ``core``, or ``discovery``, so the engine can depend on it without
pulling in sources or the CLI. The discovery bridge (``DetectorDiscoveryClient``)
lives in ``discovery.py`` for the same reason.

Detectors are enabled at launch with ``--detector NAME`` or
``--detector NAME=ARGUMENT``. ``NAME`` resolves to a built-in factory or to an
installed entry point in the ``redacted_context_mcp.detectors`` group; the
factory receives the single free-form ``ARGUMENT`` string (or ``None``) and
returns a ``Detector``. The built-ins are ``patterns`` and the optional
``presidio`` and ``gliner`` adapters, whose modules and libraries are imported
only when their factory runs, so importing this module stays dependency-free.
"""

from __future__ import annotations

import itertools
import operator
import re
import tomllib
import unicodedata
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Callable, Iterable, Mapping, Protocol, Sequence, runtime_checkable

from .defaults import PLACEHOLDER_CATEGORIES
from .models import (
    DETECTOR_CATEGORY_MESSAGE,
    DETECTOR_FAILED_MESSAGE,
    DETECTOR_LIMIT_MESSAGE,
    DETECTOR_SPAN_MESSAGE,
    UNKNOWN_DETECTOR_MESSAGE,
)
from .regex_safety import (
    REGEX_STRESS_GROWTH_LIMIT,
    REGEX_STRESS_INPUT_CHARS,
    REGEX_STRESS_SECONDS,
    REGEX_STRESS_SMALL_CHARS,
    REGEX_STRESS_SUPERLINEAR,
    UNSAFE_REGEX_MESSAGE,
    regex_backtracking_violation,
    regex_stress_report,
)


ENTRY_POINT_GROUP = "redacted_context_mcp.detectors"
DETECTOR_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

# Request-time nomination limits. Exceeding a count limit fails closed with
# DETECTOR_LIMIT_MESSAGE. A span over a per-value size limit is still redacted
# where it was nominated, but its value stays out of the alternation that
# redacts other occurrences; such spans are counted as ``positional`` in the
# receipt. The alternation also has a total size budget: beyond it the
# longest values leave the alternation first and become positional too.
MAX_DETECTOR_SPANS = 20_000  # spans returned by one detector for one text
MAX_NOMINATED_VALUES = 2_000  # distinct nominated values per text, all detectors
MAX_NOMINATED_VALUE_CHARS = 256
MAX_NOMINATED_VALUE_TOKENS = 16  # whitespace-separated tokens per value
MAX_NOMINATED_PATTERN_CHARS = 32_768  # summed length of the alternation's values

# Canonical category strings, so a ``str`` subclass returned by a detector is
# never used to build a placeholder.
_CANONICAL_CATEGORIES = {category: category for category in PLACEHOLDER_CATEGORIES}
# Validation messages that ``run_detector`` relays, keyed by object identity:
# only the engine's own constant string objects qualify, so neither an equal
# ``str`` subclass nor an unhashable payload raised by a detector is relayed.
# Anything else a detector raises becomes DETECTOR_FAILED_MESSAGE.
_RELAYED_DETECTOR_MESSAGES = {
    id(message): message
    for message in (DETECTOR_CATEGORY_MESSAGE, DETECTOR_FAILED_MESSAGE, DETECTOR_LIMIT_MESSAGE, DETECTOR_SPAN_MESSAGE)
}


@dataclass(frozen=True)
class Span:
    """A half-open character range ``[start, end)`` over the analyzed text.

    ``category`` must be one of the canonical placeholder categories
    (``defaults.PLACEHOLDER_CATEGORIES``), for example ``PERSON``, ``ORG``,
    ``CLIENT``, ``SENSITIVE``, ``EMAIL``, or ``ID``. The placeholder HMAC key
    includes the category, so mapping library labels to canonical categories
    is the detector's job; unknown categories fail closed.
    """

    start: int
    end: int
    category: str


@runtime_checkable
class Detector(Protocol):
    """Contract for a plugged detector.

    - ``name`` and ``version`` are non-empty strings recorded in receipts and
      shown by ``redctx doctor``. They must not contain private data.
    - ``detect(text)`` returns spans whose offsets index into exactly the
      string it was given, with ``0 <= start < end <= len(text)`` and a
      canonical category. Offsets may be any integer type (``operator.index``
      is applied). At most ``MAX_DETECTOR_SPANS`` spans per call.
    - Detectors must run locally (no network calls, no remote model APIs) and
      must be deterministic: identical input yields identical spans. Read-back
      redaction, the controlled-write rehydration scan, and round-trip
      verification all depend on finding the same values again.
    - Detectors must not mutate, log, persist, or retain the text.
    - Errors may be raised freely; the engine converts every failure
      (anything but ``KeyboardInterrupt``) into the input-free message
      ``"Detector failed."`` and never relays exception text.

    Optionally, a detector may expose ``protected_paths`` (an iterable of
    filesystem paths it reads, such as rule files or a directory of them).
    Paths that fall under the served root, and everything below a protected
    directory, are then never listed, read, or served, like term files.
    """

    name: str
    version: str

    def detect(self, text: str) -> Sequence[Span]: ...


DetectorFactory = Callable[[str | None], Detector]


class DetectorError(SystemExit):
    """Request-time detector failure carrying only a safe, input-free message."""


def _span_offset(value: object) -> int:
    """Return ``value`` as a plain ``int`` (``operator.index``), rejecting bools."""

    if isinstance(value, bool):
        raise DetectorError(DETECTOR_SPAN_MESSAGE)
    try:
        return int.__index__(operator.index(value))  # type: ignore[arg-type]
    except TypeError:
        raise DetectorError(DETECTOR_SPAN_MESSAGE) from None


def validate_span(span: object, text_length: int) -> Span:
    """Return ``span`` as a plain ``Span`` or fail closed with a safe message.

    Offsets may be any type implementing ``__index__`` (for example NumPy
    integers); they are normalized to ``int``. The category is replaced by the
    canonical string object, so detector-supplied ``str`` subclasses never
    reach placeholder construction.
    """

    start = _span_offset(getattr(span, "start", None))
    end = _span_offset(getattr(span, "end", None))
    if not 0 <= start < end <= text_length:
        raise DetectorError(DETECTOR_SPAN_MESSAGE)
    category = getattr(span, "category", None)
    canonical = _CANONICAL_CATEGORIES.get(category) if isinstance(category, str) else None
    if canonical is None:
        raise DetectorError(DETECTOR_CATEGORY_MESSAGE)
    return Span(start, end, canonical)


def run_detector(detector: Detector, text: str) -> tuple[Span, ...]:
    """Run one detector over ``text`` and validate its spans.

    Detection, iteration of the returned spans, and span validation all run
    under one guard: any exception except ``KeyboardInterrupt`` (including
    ``SystemExit`` or ``asyncio.CancelledError`` raised by a library, and
    errors raised by span attributes) becomes ``DetectorError("Detector
    failed.")``, so no library, model, or input text can reach agent-visible
    output and the stdio server survives. Only the engine's own validation
    messages are relayed. More than ``MAX_DETECTOR_SPANS`` spans fail closed
    with ``"Detector nomination limit exceeded."``. A ``DetectorError`` is
    relayed only when its payload is one of the engine's constant message
    objects (an identity check, never equality or hashing), and the constant
    itself is raised again.
    """

    try:
        spans = tuple(itertools.islice(detector.detect(text), MAX_DETECTOR_SPANS + 1))
        if len(spans) > MAX_DETECTOR_SPANS:
            raise DetectorError(DETECTOR_LIMIT_MESSAGE)
        text_length = len(text)
        return tuple(validate_span(span, text_length) for span in spans)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        raise DetectorError(_relayed_message(exc)) from None


def _relayed_message(exc: BaseException) -> str:
    """The constant safe message to raise for ``exc``; never text taken from ``exc``."""

    try:
        if issubclass(type(exc), DetectorError):
            code = exc.code
            relayed = _RELAYED_DETECTOR_MESSAGES.get(id(code))
            if relayed is not None and relayed is code:
                return relayed
    except Exception:
        pass
    return DETECTOR_FAILED_MESSAGE


def detector_protected_paths(detectors: Iterable[Detector]) -> tuple[Path, ...]:
    """Collect the optional ``protected_paths`` declared by detectors."""

    paths: list[Path] = []
    for detector in detectors:
        for value in getattr(detector, "protected_paths", ()) or ():
            paths.append(Path(value))
    return tuple(paths)


# Built-in ``patterns`` detector ---------------------------------------------

PATTERNS_MAX_RULES = 256
PATTERNS_MAX_REGEX_CHARS = 2_000
PATTERNS_RULE_KEYS = frozenset({"category", "regex", "ignore_case"})


class PatternsDetector:
    """Nominate matches of operator-supplied regexes with canonical categories.

    Rules come from a TOML file of ``[[patterns]]`` tables, each with a
    ``category`` and a ``regex`` (plus optional ``ignore_case = true``). Rules
    are operator-trusted configuration, like the term list: every regex passes
    the static catastrophic-backtracking screen and a launch-time stress test
    in a killable process, is compiled once, and then runs in-process at
    request time. A pathological rule that slips past both checks can still
    stall the operator's own server, so rules should be anchored and simple.
    The rules file is a protected path: like a term file, it is never served
    when it lies under the served root.
    """

    name = "patterns"
    version = "1"

    def __init__(
        self,
        rules: Sequence[tuple[str, re.Pattern[str]]],
        *,
        protected_paths: Sequence[Path] = (),
    ) -> None:
        self.rules = tuple(rules)
        self.protected_paths = tuple(protected_paths)

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for category, pattern in self.rules:
            for match in pattern.finditer(text):
                if match.end() > match.start():
                    spans.append(Span(match.start(), match.end(), category))
        return spans


def compile_pattern_rules(data: object) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Validate parsed patterns TOML, compile its rules, and stress-test them.

    After the static screen, every compiled rule is timed over synthetic
    stress inputs derived from its own character classes and literals, at
    two sizes, in a killable child process (``regex_stress_report``). A rule
    is rejected as too slow when one run needs more than
    ``REGEX_STRESS_SECONDS``, or as superlinear when its time grows more than
    ``REGEX_STRESS_GROWTH_LIMIT`` times from the smaller to the larger
    input. Error messages name the rule number and the reason only; they
    never echo regexes, which may themselves contain private terms.
    """

    if not isinstance(data, dict) or set(data) != {"patterns"}:
        raise SystemExit("The patterns detector file must contain only [[patterns]] tables.")
    raw_rules = data["patterns"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise SystemExit("The patterns detector file must define at least one [[patterns]] table.")
    if len(raw_rules) > PATTERNS_MAX_RULES:
        raise SystemExit(f"The patterns detector file defines more than {PATTERNS_MAX_RULES} rules.")
    rules: list[tuple[str, re.Pattern[str]]] = []
    for number, rule in enumerate(raw_rules, start=1):
        prefix = f"patterns rule {number}"
        if not isinstance(rule, dict):
            raise SystemExit(f"{prefix}: expected a table.")
        unknown = set(rule) - PATTERNS_RULE_KEYS
        if unknown:
            raise SystemExit(f"{prefix}: unsupported keys {', '.join(sorted(unknown))}.")
        category = rule.get("category")
        if not isinstance(category, str) or category not in PLACEHOLDER_CATEGORIES:
            raise SystemExit(
                f"{prefix}: category must be one of {', '.join(sorted(PLACEHOLDER_CATEGORIES))}."
            )
        regex = rule.get("regex")
        if not isinstance(regex, str) or not regex:
            raise SystemExit(f"{prefix}: regex must be a non-empty string.")
        if len(regex) > PATTERNS_MAX_REGEX_CHARS:
            raise SystemExit(f"{prefix}: regex exceeds {PATTERNS_MAX_REGEX_CHARS} characters.")
        ignore_case = rule.get("ignore_case", False)
        if not isinstance(ignore_case, bool):
            raise SystemExit(f"{prefix}: ignore_case must be true or false.")
        if regex_backtracking_violation(regex) is not None:
            raise SystemExit(f"{prefix}: {UNSAFE_REGEX_MESSAGE}")
        try:
            pattern = re.compile(regex, re.IGNORECASE if ignore_case else 0)
        except re.error:
            raise SystemExit(f"{prefix}: invalid regex.") from None
        if pattern.fullmatch("") is not None:
            raise SystemExit(f"{prefix}: regex must not match the empty string.")
        rules.append((category, pattern))
    try:
        report = regex_stress_report([(pattern.pattern, pattern.flags) for _category, pattern in rules])
    except SystemExit:
        raise SystemExit("The patterns detector could not stress-test its rules.") from None
    if report is not None:
        index, reason = report
        if reason == REGEX_STRESS_SUPERLINEAR:
            detail = (
                f"regex is superlinear: its time grew more than {REGEX_STRESS_GROWTH_LIMIT:g}x from a "
                f"{REGEX_STRESS_SMALL_CHARS:,}- to a {REGEX_STRESS_INPUT_CHARS:,}-character stress input"
            )
        else:
            detail = (
                f"regex is too slow: it took longer than {REGEX_STRESS_SECONDS:g} seconds on a "
                f"stress input of up to {REGEX_STRESS_INPUT_CHARS:,} characters"
            )
        raise SystemExit(
            f"patterns rule {index + 1}: {detail}; anchor it with literal text and avoid repeats "
            "that can rescan the same characters."
        )
    return tuple(rules)


def patterns_detector_factory(argument: str | None) -> PatternsDetector:
    """Factory for ``--detector patterns=/path/to/patterns.toml``."""

    if argument is None or not argument.strip():
        raise SystemExit("The patterns detector requires a rules file: --detector patterns=PATH.")
    path = Path(argument.strip()).expanduser().resolve()
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        raise SystemExit("The patterns detector rules file could not be read.") from None
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError:
        raise SystemExit("The patterns detector rules file is not valid TOML.") from None
    return PatternsDetector(compile_pattern_rules(data), protected_paths=(path,))


# Helpers for adapters --------------------------------------------------------

OPTION_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
TRUE_VALUES = frozenset({"true", "yes", "1", "on"})
FALSE_VALUES = frozenset({"false", "no", "0", "off"})


def parse_detector_options(argument: str | None, *, detector: str, allowed: Iterable[str]) -> dict[str, str]:
    """Parse a factory argument of comma-separated ``key=value`` pairs.

    Empty items are ignored. Malformed items, unknown keys, and repeated keys
    raise ``SystemExit`` with operator-facing messages that name the key (keys
    are restricted to short lowercase identifiers) but never echo a value.
    Values are returned stripped and otherwise verbatim.
    """

    allowed_keys = frozenset(allowed)
    options: dict[str, str] = {}
    if argument is None:
        return options
    for item in argument.split(","):
        if not item.strip():
            continue
        key, separator, value = item.partition("=")
        key = key.strip()
        if not separator or not OPTION_KEY_RE.fullmatch(key):
            raise SystemExit(
                f"Invalid {detector} detector option; expected comma-separated key=value pairs "
                f"(supported keys: {', '.join(sorted(allowed_keys))})."
            )
        if key not in allowed_keys:
            raise SystemExit(
                f"Unknown {detector} detector option '{key}'. Supported: {', '.join(sorted(allowed_keys))}."
            )
        if key in options:
            raise SystemExit(f"The {detector} detector option '{key}' was given more than once.")
        options[key] = value.strip()
    return options


def parse_bool_option(value: str, *, detector: str, key: str) -> bool:
    lowered = value.strip().lower()
    if lowered in TRUE_VALUES:
        return True
    if lowered in FALSE_VALUES:
        return False
    raise SystemExit(f"The {detector} detector option '{key}' must be true or false.")


def parse_float_option(value: str, *, detector: str, key: str, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except ValueError:
        number = float("nan")
    if not minimum <= number <= maximum:  # also rejects NaN
        raise SystemExit(f"The {detector} detector option '{key}' must be a number from {minimum:g} to {maximum:g}.")
    return number


def parse_int_option(value: str, *, detector: str, key: str, minimum: int, maximum: int) -> int:
    text = value.strip()
    if not text.isascii() or not text.isdigit() or not minimum <= int(text) <= maximum:
        raise SystemExit(f"The {detector} detector option '{key}' must be a whole number from {minimum} to {maximum}.")
    return int(text)


def installed_version(distribution: str) -> str:
    """Return the installed version of ``distribution``, or ``"unknown"``."""

    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return "unknown"


def parse_category_pairs(
    value: str,
    *,
    detector: str,
    key: str,
    left_name: str,
    normalize: Callable[[str], str | None],
    echo_duplicates: bool = False,
) -> dict[str, str]:
    """Parse ``|``-separated ``LEFT:CATEGORY`` pairs into an ordered dict.

    ``normalize`` receives the stripped left-hand side and returns it in its
    canonical form, or ``None`` when it is malformed. Categories must be
    canonical placeholder categories. Messages never echo a value, except
    that a repeated left-hand side is named when ``echo_duplicates`` is set
    (for public identifiers such as Presidio entity types).
    """

    pairs: dict[str, str] = {}
    malformed = f"The {detector} detector option '{key}' expects {left_name}:CATEGORY pairs separated by |."
    for item in value.split("|"):
        left, separator, category = item.partition(":")
        normalized = normalize(left.strip()) if separator else None
        if normalized is None:
            raise SystemExit(malformed)
        category = category.strip()
        if category not in PLACEHOLDER_CATEGORIES:
            raise SystemExit(
                f"The {detector} detector option '{key}' must use canonical categories: "
                f"{', '.join(sorted(PLACEHOLDER_CATEGORIES))}."
            )
        if normalized in pairs:
            named = normalized if echo_duplicates else f"a {left_name}"
            raise SystemExit(f"The {detector} detector option '{key}' names {named} more than once.")
        pairs[normalized] = category
    return pairs


def drop_contained_spans(candidates: Iterable[tuple[Span, float]]) -> list[Span]:
    """Resolve duplicate and nested spans deterministically.

    ``candidates`` are ``(span, score)`` pairs. Spans with an identical range
    collapse to one: the higher score wins, then the alphabetically first
    category. A span lying strictly inside a kept span *of the same category*
    is dropped, because the engine already redacts the containing value and
    the inner one adds nothing the category does not already say. A nested
    span of a different category (a person inside an organization name, a
    domain inside an email address) is kept: the engine redacts every
    occurrence of each nominated value, so its other occurrences must still
    be found. Partially overlapping spans are all kept. The result is sorted
    by position and does not depend on the input order.
    """

    ordered = sorted(
        candidates,
        key=lambda item: (item[0].start, -item[0].end, -item[1], item[0].category),
    )
    kept: list[Span] = []
    furthest_end: dict[str, int] = {}
    previous_range: tuple[int, int] | None = None
    for span, _score in ordered:
        current_range = (span.start, span.end)
        if current_range == previous_range:
            continue  # an identical range: the first (best) one already decided
        previous_range = current_range
        # Every earlier span starts at or before this one, so ending at or
        # before the furthest kept end of its category means it is contained.
        if span.end <= furthest_end.get(span.category, -1):
            continue
        kept.append(span)
        furthest_end[span.category] = span.end
    return kept


def extend_over_combining_marks(text: str, end: int) -> int:
    """Move ``end`` past combining marks that belong to the character before it.

    In decomposed (NFD) text an accent follows its base letter as a separate
    code point; a span that stops before it would cut ``José`` to ``Jose``.
    """

    length = len(text)
    while end < length and unicodedata.combining(text[end]):
        end += 1
    return end


def collect_window_spans(
    text: str,
    windows: Iterable[tuple[int, int]],
    analyze: Callable[[str], Iterable[object]],
    read_result: Callable[[object], tuple[object, object, object, object]],
    *,
    categories: Mapping[str, str],
    threshold: float,
    library: str,
) -> list[Span]:
    """Run a library over ``text`` window by window and resolve the spans.

    ``analyze(chunk)`` returns the library's results for one window, and
    ``read_result(result)`` returns ``(label, start, end, score)`` with offsets
    relative to that window. Results whose label has no entry in
    ``categories`` or whose score is below ``threshold`` are skipped; offsets
    must be plain in-range integers (anything else raises ``ValueError``,
    which the engine reports only as ``Detector failed.``). Offsets are shifted
    back onto ``text``, span ends are extended over trailing combining marks,
    and duplicates are resolved with ``drop_contained_spans``.
    """

    candidates: list[tuple[Span, float]] = []
    for window_start, window_end in windows:
        chunk = text[window_start:window_end]
        chunk_length = len(chunk)
        for result in analyze(chunk):
            label, start, end, raw_score = read_result(result)
            category = categories.get(label) if isinstance(label, str) else None
            if category is None:
                continue
            score = float(raw_score)  # type: ignore[arg-type]
            if not score >= threshold:  # also rejects NaN
                continue
            if not (
                isinstance(start, int)
                and isinstance(end, int)
                and not isinstance(start, bool)
                and not isinstance(end, bool)
                and 0 <= start < end <= chunk_length
            ):
                raise ValueError(f"{library} returned an out-of-range span.")
            absolute_end = extend_over_combining_marks(text, window_start + end)
            candidates.append((Span(window_start + start, absolute_end, category), score))
    return drop_contained_spans(candidates)


# Registry -------------------------------------------------------------------


def presidio_detector_factory(argument: str | None) -> Detector:
    """Lazy built-in for ``--detector presidio[=OPTIONS]``.

    The adapter module and the optional ``presidio_analyzer`` library are only
    imported when the detector is requested, so importing this module never
    pulls in optional dependencies.
    """

    from .detectors_presidio import factory

    return factory(argument)


def gliner_detector_factory(argument: str | None) -> Detector:
    """Lazy built-in for ``--detector gliner[=OPTIONS]`` (see ``presidio_detector_factory``)."""

    from .detectors_gliner import factory

    return factory(argument)


BUILTIN_DETECTORS: dict[str, DetectorFactory] = {
    "patterns": patterns_detector_factory,
    "presidio": presidio_detector_factory,
    "gliner": gliner_detector_factory,
}


def _detector_entry_points() -> list[metadata.EntryPoint]:
    try:
        return list(metadata.entry_points(group=ENTRY_POINT_GROUP))
    except Exception:
        return []


def available_detector_names() -> tuple[str, ...]:
    names = set(BUILTIN_DETECTORS)
    names.update(entry_point.name for entry_point in _detector_entry_points())
    return tuple(sorted(names))


def parse_detector_spec(spec: str) -> tuple[str, str | None]:
    """Split ``NAME`` or ``NAME=ARGUMENT``; the argument is passed verbatim."""

    name, separator, argument = str(spec).partition("=")
    name = name.strip()
    if not DETECTOR_NAME_RE.fullmatch(name):
        raise SystemExit("Invalid --detector value; expected NAME or NAME=ARGUMENT.")
    return name, (argument if separator else None)


def resolve_detector_factory(name: str) -> DetectorFactory:
    """Return the factory for ``name``; built-ins cannot be shadowed."""

    builtin = BUILTIN_DETECTORS.get(name)
    if builtin is not None:
        return builtin
    candidates = [entry_point for entry_point in _detector_entry_points() if entry_point.name == name]
    if not candidates:
        available = ", ".join(available_detector_names())
        raise SystemExit(f"{UNKNOWN_DETECTOR_MESSAGE} Name: {name}. Available: {available}.")
    if len({entry_point.value for entry_point in candidates}) > 1:
        raise SystemExit(f"Detector '{name}' is provided by more than one installed package.")
    try:
        factory = candidates[0].load()
    except Exception as exc:
        raise SystemExit(f"Detector '{name}' could not be imported ({type(exc).__name__}).") from None
    if not callable(factory):
        raise SystemExit(f"Detector '{name}' entry point is not a factory.")
    return factory


def validate_detector(detector: object, name: str) -> Detector:
    if not isinstance(detector, Detector):
        raise SystemExit(f"Detector '{name}' factory did not return a detector.")
    for attribute in ("name", "version"):
        value = getattr(detector, attribute, None)
        if not isinstance(value, str) or not value.strip():
            raise SystemExit(f"Detector '{name}' must define a non-empty {attribute} string.")
    return detector


def load_detectors(specs: Sequence[str] | None) -> tuple[Detector, ...]:
    """Load detectors once at launch from ``--detector`` values.

    Errors are operator-facing ``SystemExit`` messages. They name the detector
    but never echo its argument, which may be a private path.
    """

    detectors: list[Detector] = []
    seen: set[str] = set()
    for spec in specs or ():
        name, argument = parse_detector_spec(spec)
        if name in seen:
            raise SystemExit(f"Detector '{name}' was given more than once.")
        seen.add(name)
        factory = resolve_detector_factory(name)
        try:
            detector = factory(argument)
        except SystemExit as exc:
            if exc.code is None or exc.code == 0:
                # A successful exit status would end the launch silently.
                raise SystemExit(f"Detector '{name}' factory exited without creating a detector.") from None
            raise
        except Exception as exc:
            raise SystemExit(f"Detector '{name}' could not be initialized ({type(exc).__name__}).") from None
        detectors.append(validate_detector(detector, name))
    return tuple(detectors)
