"""Text and path redaction primitives."""

from __future__ import annotations

import bisect
import hashlib
import hmac
import re
import string
import threading
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .defaults import (
    ACRONYM_RE,
    ALIAS_FORM_SEPARATOR,
    ALIAS_FORM_SUFFIX_HEX,
    COMMON_CAPITALIZED_WORDS,
    CONNECTION_STRING_RE,
    CREDIT_CARD_RE,
    DEFAULT_ALLOW_TERMS,
    DOB_RE,
    DOMAIN_RE,
    DRIVER_ID_RE,
    EMAIL_RE,
    GENERIC_ORG_WORDS,
    GENERIC_SECRET_RE,
    HANDLE_RE,
    HEX_SECRET_RE,
    IBAN_RE,
    IDENTITY_LINE_RE,
    IP_RE,
    IPV6_RE,
    MAC_RE,
    MAX_MAIL_ADDRESS_CHARS,
    MONTHS_AND_DAYS,
    MULTI_PROPER_RE,
    NON_PERSON_NAME_WORDS,
    ONE_TIME_CODE_RE,
    OPAQUE_TOKEN_RE,
    ORG_SUFFIX_RE,
    PASSPORT_RE,
    PATH_ALLOW_TERMS,
    PATH_TOKEN_RE,
    PEM_PRIVATE_KEY_RE,
    PHONE_RE,
    PLACEHOLDER_CATEGORIES,
    PLACEHOLDER_RE,
    PROMPT_INJECTION_RE,
    RESERVED_PLACEHOLDER_WORDS,
    SALT_ASSIGNMENT_RE,
    SCHEMELESS_LINK_RE,
    SERVICE_ACCOUNT_RE,
    SPEAKER_LABEL_RE,
    SSN_RE,
    TITLECASE_TOKEN_RE,
    UNICODE_CONTROL_RE,
    URL_RE,
    UUID_RE,
)
from .detectors import (
    MAX_NOMINATED_PATTERN_CHARS,
    MAX_NOMINATED_VALUE_CHARS,
    MAX_NOMINATED_VALUE_TOKENS,
    MAX_NOMINATED_VALUES,
    Detector,
    DetectorError,
    run_detector,
)
from .models import DETECTOR_LIMIT_MESSAGE, RedactionConfig


LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")
PUA_RADIX = 1024
PUA_BLOCK_SIZE = PUA_RADIX + 2
PUA_MIN = 0xE000
PUA_MAX = 0xF8FF
# Snapshot keys for per-detector nomination counts. Placeholder categories are
# upper-case words, so this prefix can never collide with a category.
DETECTOR_COUNT_PREFIX = "detector#"
# Snapshot keys for per-detector counts of spans redacted only by position
# (over the per-value size limits or beyond the alternation budget).
DETECTOR_POSITIONAL_PREFIX = f"{DETECTOR_COUNT_PREFIX}positional#"
# Category for a nominated match whose category cannot be looked up (a case
# variant that only the regex engine's case folding equates). Never skipped.
NOMINATION_FALLBACK_CATEGORY = "SENSITIVE"
# Kinds of segments in a tracked session's intermediate text.
SEGMENT_RAW = 0
SEGMENT_PLACEHOLDER = 1
SEGMENT_ALLOWED = 2
# Characters trimmed from the edges of a nominated remnant: ASCII whitespace
# and ASCII punctuation only. Everything else (letters, digits, combining
# marks, private-use characters, emoji) is redacted.
REMNANT_TRIM_CHARS = frozenset(string.whitespace + string.punctuation)
# HMAC key used when a config carries no salt (load_config always sets one).
DEFAULT_PLACEHOLDER_SALT = "redacted-context-mcp-v1"
# Built-in stages that run before configured terms, in pipeline order, with
# the category each one redacts as. The extended stages follow the default
# ones only under the extended detector profile.
EARLY_BASELINE_STAGES: tuple[tuple[re.Pattern[str], str], ...] = (
    (PEM_PRIVATE_KEY_RE, "SECRET"),
    (SALT_ASSIGNMENT_RE, "SECRET"),
    (GENERIC_SECRET_RE, "SECRET"),
    (HEX_SECRET_RE, "SECRET"),
    (URL_RE, "URL"),
    (EMAIL_RE, "EMAIL"),
    (UUID_RE, "ID"),
    (IP_RE, "IP"),
    (SSN_RE, "SSN"),
    (CREDIT_CARD_RE, "CARD"),
    (PHONE_RE, "PHONE"),
    (DOMAIN_RE, "DOMAIN"),
    (HANDLE_RE, "HANDLE"),
)
EXTENDED_BASELINE_STAGES: tuple[tuple[re.Pattern[str], str], ...] = (
    (SERVICE_ACCOUNT_RE, "SERVICE_ACCOUNT"),
    (CONNECTION_STRING_RE, "CONNECTION"),
    (IBAN_RE, "IBAN"),
    (IPV6_RE, "IP"),
    (MAC_RE, "MAC"),
    (DOB_RE, "DOB"),
    (PASSPORT_RE, "PASSPORT"),
    (DRIVER_ID_RE, "DRIVER_ID"),
    (UNICODE_CONTROL_RE, "UNICODE_CONTROL"),
    (PROMPT_INJECTION_RE, "PROMPT_INJECTION"),
)
# Stages a mail redactor (``Redactor.for_mail``) runs before the early
# baseline. Full URLs come first, exactly as the URL stage would redact them,
# so no mail stage can split a URL; then scheme-less links, one-time codes
# (only their ``value`` group), opaque tokens, and prompt-injection phrases,
# whatever the detector profile.
MAIL_STAGES: tuple[tuple[re.Pattern[str], str], ...] = (
    (URL_RE, "URL"),
    (SCHEMELESS_LINK_RE, "URL"),
    (ONE_TIME_CODE_RE, "SECRET"),
    (OPAQUE_TOKEN_RE, "SECRET"),
    (PROMPT_INJECTION_RE, "PROMPT_INJECTION"),
)
# The configured-term stage's categories, in pipeline order.
CONFIGURED_TERM_CATEGORIES = ("CLIENT", "ORG", "PERSON", "SENSITIVE")
# Casefolded single words that never become harvested mail-name body terms.
MAIL_NAME_STOPWORDS = frozenset(
    word.casefold() for word in (*COMMON_CAPITALIZED_WORDS, *NON_PERSON_NAME_WORDS, *GENERIC_ORG_WORDS)
)
# Path redaction keeps whole placeholders (including linked alias forms,
# whose suffix starts after a non-word separator) and redacts the
# remaining path tokens.
PATH_REDACTION_RE = re.compile(rf"({PLACEHOLDER_RE.pattern})|{PATH_TOKEN_RE.pattern}")


class RedactionCollisionError(RuntimeError):
    """Raised when two distinct raw values would share one placeholder."""


def preserved_line_breaks(value: str) -> str:
    return "".join(LINE_BREAK_RE.findall(value))


class RedactionSession:
    """Internal markers for one redaction call.

    With ``track=True`` (only used when plugged detectors nominated spans),
    the session also records, for every marker, how many characters of the
    original text it stands for, so ``segments`` can map the marker-bearing
    intermediate text back onto original-text offsets.
    """

    def __init__(self, source: str, *, track: bool = False) -> None:
        source_chars = set(source)
        for codepoint in range(PUA_MIN, PUA_MAX - PUA_BLOCK_SIZE + 2, PUA_BLOCK_SIZE):
            block = [chr(value) for value in range(codepoint, codepoint + PUA_BLOCK_SIZE)]
            if not source_chars.intersection(block):
                self.prefix = block[0]
                self.suffix = block[1]
                self.digit_base = codepoint + 2
                digit_start = re.escape(chr(self.digit_base))
                digit_end = re.escape(chr(self.digit_base + PUA_RADIX - 1))
                self.restore_re = re.compile(
                    re.escape(self.prefix) + f"([{digit_start}-{digit_end}]+)" + re.escape(self.suffix)
                )
                break
        else:
            raise ValueError("Could not allocate internal redaction markers.")
        self.replacements: list[str] = []
        self.track = track
        # Per marker, when tracking: (original length, trailer, allowed). The
        # trailer is the text that follows the marker in the intermediate
        # text and is already counted in its original length: the marker's
        # own preserved line breaks, then any orphaned trailer of an inner
        # marker that the stashed value ended on (see ``_measure``).
        self.records: list[tuple[int, str, bool]] = []

    def stash_allowed(self, value: str) -> str:
        if self.track:
            length, orphan = self._measure(value)
            self.records.append((length, orphan, True))
        return self._stash(value)

    def stash_placeholder(self, placeholder: str, source_text: str, *, preserve_line_count: bool) -> str:
        # The suffix keeps the value's line breaks so line numbers survive. A
        # lone "\r" suffix followed by a "\n" in the text reads as one "\r\n"
        # break afterwards; that known edge case is left as it is.
        suffix = preserved_line_breaks(source_text) if preserve_line_count else ""
        if self.track:
            length, orphan = self._measure(source_text)
            self.records.append((length, suffix + orphan, False))
        return self._stash(placeholder) + suffix

    def _measure(self, value: str) -> tuple[int, str]:
        """Original length that ``value`` (which may hold markers) stands for, and its orphan.

        An inner marker's trailer normally follows it inside ``value``. When
        a later stage matched up to (or into) that trailer, ``value`` ends
        with the marker and at most a prefix of its trailer, and the rest of
        the trailer stays in the text right after the new marker. That
        orphaned rest is already counted in the inner marker's original
        length, so it is returned for the new marker's trailer.
        """
        length = len(value)
        orphan = ""
        for match in self.restore_re.finditer(value):
            original, trailer, _allowed = self.records[self.decode_marker_index(match.group(1))]
            length += original - len(match.group(0))
            if not trailer:
                continue
            end = match.end()
            if value.startswith(trailer, end):
                length -= len(trailer)
            else:
                rest = value[end:]
                if trailer.startswith(rest):
                    length -= len(rest)
                    orphan = trailer[len(rest) :]
        return length, orphan

    def segments(self, text: str, original: str) -> list[tuple[int, int, int, int, int]] | None:
        """Map a tracked intermediate ``text`` onto offsets in ``original``.

        Returns ``(original_start, original_end, text_start, text_end, kind)``
        tuples in order, where ``kind`` is ``SEGMENT_RAW`` for untouched
        original characters, ``SEGMENT_PLACEHOLDER`` for a redaction marker
        (with its trailer of preserved line breaks), or ``SEGMENT_ALLOWED``
        for an allow-listed term or existing placeholder token. Returns ``None`` if
        the mapping does not reproduce ``original`` exactly, so callers can
        fall back instead of redacting the wrong characters.
        """
        if not self.track:
            return None
        segments: list[tuple[int, int, int, int, int]] = []
        position = 0
        offset = 0
        for match in self.restore_re.finditer(text):
            start, end = match.span()
            if start > position:
                segments.append((offset, offset + start - position, position, start, SEGMENT_RAW))
                offset += start - position
            index = self.decode_marker_index(match.group(1))
            if index >= len(self.records):
                return None
            length, trailer, allowed = self.records[index]
            if trailer:
                if not text.startswith(trailer, end):
                    return None
                end += len(trailer)
            segments.append((offset, offset + length, start, end, SEGMENT_ALLOWED if allowed else SEGMENT_PLACEHOLDER))
            offset += length
            position = end
        if position < len(text):
            segments.append((offset, offset + len(text) - position, position, len(text), SEGMENT_RAW))
            offset += len(text) - position
        if offset != len(original):
            return None
        for original_start, original_end, text_start, text_end, kind in segments:
            if kind == SEGMENT_RAW and original[original_start:original_end] != text[text_start:text_end]:
                return None
        return segments

    def restore_all(self, text: str) -> str:
        return self.restore_re.sub(lambda match: self.replacements[self.decode_marker_index(match.group(1))], text)

    def _stash(self, value: str) -> str:
        marker = f"{self.prefix}{self.encode_marker_index(len(self.replacements))}{self.suffix}"
        self.replacements.append(value)
        return marker

    def encode_marker_index(self, index: int) -> str:
        if index < 0:
            raise ValueError("Marker index must be non-negative.")
        digits: list[str] = []
        while True:
            digits.append(chr(self.digit_base + (index % PUA_RADIX)))
            index //= PUA_RADIX
            if index == 0:
                break
        return "".join(reversed(digits))

    def decode_marker_index(self, value: str) -> int:
        index = 0
        for char in value:
            digit = ord(char) - self.digit_base
            if digit < 0 or digit >= PUA_RADIX:
                raise ValueError("Invalid marker digit.")
            index = index * PUA_RADIX + digit
        return index


@dataclass
class Redactor:
    config: RedactionConfig
    mode: str = "strict"
    counters: dict[str, int] = field(default_factory=dict)
    aliases: dict[tuple[str, str], str] = field(default_factory=dict)
    raw_aliases: dict[str, str] = field(default_factory=dict)
    placeholder_keys: dict[str, tuple[str, str]] = field(default_factory=dict)
    detectors: tuple[Detector, ...] = ()
    # Extra ``(pattern, category)`` stages run before the early baseline,
    # right after existing placeholders are stashed. A pattern with a named
    # group ``value`` redacts only that group and keeps the rest of the match.
    pre_stages: tuple[tuple[re.Pattern[str], str], ...] = field(default=(), repr=False)
    # Extra ``(category, terms)`` literal terms for the configured-term stage.
    # Terms of a configured-term category join that category's pattern;
    # terms of any other category run first, in the order given. They never
    # count as configured terms (``configured_categories``).
    extra_terms: tuple[tuple[str, tuple[str, ...]], ...] = field(default=(), repr=False)
    # Extra ``(normalized value, entity hex, form suffix)`` alias links.
    # Links from the config's alias groups always win.
    extra_links: tuple[tuple[str, str, str], ...] = field(default=(), repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        allow_terms = set(DEFAULT_ALLOW_TERMS) | set(MONTHS_AND_DAYS) | set(self.config.allow)
        self.allow_terms = {term for term in allow_terms if term}
        self.allow_lookup = {term.casefold() for term in self.allow_terms}
        self.allow_pattern = compile_terms_pattern(self.allow_terms)
        # Declared aliases of an alias group: each normalized alias maps to
        # its group's entity hex (the hex of the canonical value's ordinary
        # placeholder) and its own keyed form suffix. The canonical value
        # needs no entry; its placeholder is never changed. Aliases also
        # join their group's category in the configured-term stage, so each
        # is redacted in its own right.
        self.alias_links: dict[str, tuple[str, str]] = {}
        # Per redacted alias key, the ordinary placeholder it would have
        # without its group; rehydration still restores it.
        self.superseded_placeholders: dict[tuple[str, str], str] = {}
        alias_terms: dict[str, list[str]] = {}
        for group in self.config.alias_groups:
            entity = placeholder_digest(self.config.salt, group.category, normalize_alias(group.canonical))
            for alias in group.aliases:
                normalized = normalize_alias(alias)
                self.alias_links.setdefault(normalized, (entity, alias_form_suffix(self.config.salt, normalized)))
            alias_terms.setdefault(group.category, []).extend(group.aliases)
        # The config's own links, before any extra link joins them.
        self.configured_alias_links: dict[str, tuple[str, str]] = dict(self.alias_links)
        for normalized, entity, suffix in self.extra_links:
            self.alias_links.setdefault(normalized, (entity, suffix))
        extra_terms: dict[str, list[str]] = {}
        for category, terms in self.extra_terms:
            extra_terms.setdefault(category, []).extend(terms)
        configured_terms = (
            ("CLIENT", self.config.clients),
            ("ORG", self.config.organizations),
            ("PERSON", self.config.people),
            ("SENSITIVE", self.config.terms),
        )
        leading_terms = [(category, ()) for category in extra_terms if category not in CONFIGURED_TERM_CATEGORIES]
        self.literal_patterns: list[tuple[str, re.Pattern[str]]] = []
        for category, terms in (*leading_terms, *configured_terms):
            terms = (*terms, *alias_terms.get(category, ()), *extra_terms.get(category, ()))
            filtered = [term for term in terms if term.casefold() not in RESERVED_PLACEHOLDER_WORDS]
            pattern = compile_terms_pattern(filtered, dispatch=bool(extra_terms))
            if pattern is not None:
                self.literal_patterns.append((category, pattern))
        self._configured_categories: dict[str, str] | None = None
        self.detectors = tuple(self.detectors)
        self.detector_counts = [0] * len(self.detectors)
        self.detector_positional = [0] * len(self.detectors)

    def configured_categories(self) -> dict[str, str]:
        """Each normalized configured value mapped to the category it is redacted as.

        Configured terms take the first configured-term category that holds
        them (the literal stage's order); alias-group canonical values and
        aliases take their group's category. Extra terms are not included.
        """
        if self._configured_categories is None:
            categories: dict[str, str] = {}
            for category, terms in (
                ("CLIENT", self.config.clients),
                ("ORG", self.config.organizations),
                ("PERSON", self.config.people),
                ("SENSITIVE", self.config.terms),
            ):
                for term in terms:
                    categories.setdefault(normalize_alias(term), category)
            for group in self.config.alias_groups:
                for value in (group.canonical, *group.aliases):
                    categories.setdefault(normalize_alias(value), group.category)
            self._configured_categories = categories
        return self._configured_categories

    def for_mail(self, identities: Iterable[tuple[str, str]]) -> Redactor:
        """A mail redactor derived from this one, with identities harvested from mail headers.

        ``identities`` are raw ``(display name, address)`` pairs (either may
        be empty). The result keeps this redactor's config, mode, and
        detectors, and shares its receipt counters, detector counts, and
        lock, so receipts taken on this redactor include mail redactions.
        Its placeholder caches are its own: mail never changes what this
        redactor prints. On top of the usual pipeline it runs
        ``MAIL_STAGES`` before the early baseline, redacts harvested names as
        ``PERSON`` terms and harvested addresses as ``EMAIL`` terms, and links
        each unconfigured name seen with exactly one address to that
        address's entity (see ``harvest_mail_identities``). The result is a
        function of the set of pairs, not their order.
        """
        names, addresses, links = harvest_mail_identities(self, identities)
        mail = Redactor(
            self.config,
            mode=self.mode,
            counters=self.counters,
            detectors=self.detectors,
            pre_stages=MAIL_STAGES,
            extra_terms=(("EMAIL", addresses), ("PERSON", names)),
            extra_links=links,
        )
        mail.detector_counts = self.detector_counts
        mail.detector_positional = self.detector_positional
        mail._lock = self._lock
        return mail

    def mail_name_placeholder(self, name: str) -> str:
        """The structural header rendering of a display name.

        Always a placeholder for a name that is not empty once cleaned
        (``clean_mail_name``), whether or not a pattern would match it or the
        allow list holds it. A name containing ``@`` is an ``EMAIL``; a
        configured value keeps its configured category; anything else is a
        ``PERSON``. Alias links (configured or harvested) apply as usual.
        """
        cleaned = clean_mail_name(name)
        if not cleaned:
            return ""
        if "@" in cleaned:
            return self.placeholder("EMAIL", cleaned)
        category = self.configured_categories().get(normalize_alias(cleaned), "PERSON")
        return self.placeholder(category, cleaned)

    def mail_address_placeholder(self, address: str) -> str:
        """The structural header rendering of an address: always its ``EMAIL`` placeholder."""
        if not address.strip():
            return ""
        return self.placeholder("EMAIL", address)

    def redact(self, text: str, *, preserve_line_count: bool = False) -> str:
        return self._redact(text, preserve_line_count=preserve_line_count, detect=True)

    def _redact(self, text: str, *, preserve_line_count: bool, detect: bool) -> str:
        if not text:
            return text

        # Plugged detectors see only the original text, before any stage
        # inserts internal markers or placeholders. Their nominations are
        # substituted last (see below).
        nominations = self._nominations(text) if detect and self.detectors else None
        original = text
        session = RedactionSession(text, track=nominations is not None)

        def stash(category: str, value: str) -> str:
            return session.stash_placeholder(
                self.placeholder(category, value),
                value,
                preserve_line_count=preserve_line_count,
            )

        text = PLACEHOLDER_RE.sub(lambda match: session.stash_allowed(match.group(0)), text)
        for pattern, category in self.pre_stages:
            text = apply_stage(pattern, category, text, stash)
        for pattern, category in EARLY_BASELINE_STAGES:
            text = pattern.sub(lambda match, cat=category: stash(cat, match.group(0)), text)

        if self.config.detector_profile == "extended":
            for pattern, category in EXTENDED_BASELINE_STAGES:
                text = pattern.sub(lambda match, cat=category: stash(cat, match.group(0)), text)

        for category, pattern in self.literal_patterns:
            text = pattern.sub(lambda match, cat=category: stash(cat, match.group(0)), text)

        if self.allow_pattern is not None:
            text = self.allow_pattern.sub(lambda match: session.stash_allowed(match.group(0)), text)

        text = ORG_SUFFIX_RE.sub(lambda match: stash("ORG", match.group(0)), text)
        text = MULTI_PROPER_RE.sub(
            lambda match: self._replace_multi_proper(match, session, preserve_line_count),
            text,
        )
        text = SPEAKER_LABEL_RE.sub(lambda match: stash("PERSON", match.group(1)), text)
        text = IDENTITY_LINE_RE.sub(
            lambda match: self._redact_identity_line(match, session, preserve_line_count),
            text,
        )

        if self.mode == "strict":
            text = ACRONYM_RE.sub(
                lambda match: self._replace_acronym(match, session, preserve_line_count),
                text,
            )
            text = TITLECASE_TOKEN_RE.sub(
                lambda match: self._replace_titlecase(match, session, preserve_line_count),
                text,
            )

        # Plugged-detector nominations apply after every baseline stage, so
        # they only redact what the baseline left: they can never split a
        # value the baseline would have caught, and the baseline chooses the
        # category for everything it redacts.
        if nominations is not None:
            text = self._apply_nominations(original, text, session, nominations, stash)

        return session.restore_all(text)

    def _apply_nominations(
        self,
        original: str,
        text: str,
        session: RedactionSession,
        nominations: Nominations,
        stash: Callable[[str, str], str],
    ) -> str:
        """Redact whatever the baseline left of every nominated span and value occurrence.

        Coverage is the union, in original-text offsets, of every nominated
        span (by position, with no boundary guard) and every occurrence of
        every value in the alternation (overlaps allowed; overlapping and
        adjacent occurrences of one value merge into one range), mapped onto
        the marker-bearing intermediate text. Characters inside allow-listed
        terms, existing placeholder tokens, and baseline placeholders are
        never touched, so the allow list and the baseline win. Covers are
        resolved longest first (a merged range ranks as its longest
        occurrence; ties by detector order, then span order) and each claims
        the characters no earlier cover claimed. A span or single occurrence
        that claims its whole range inside one raw segment becomes one
        placeholder for the whole value, as for configured terms. Every
        other claimed raw run, including a merged range of several
        occurrences, is a remnant (for example the digits strict mode's
        acronym pass leaves of ``TICKET-12345``, or the words around an
        allow-listed word inside a nominated name): it is trimmed of ASCII
        whitespace and ASCII punctuation at its edges and redacted in the
        claiming cover's category, so nothing else of a nominated span
        survives.

        If the intermediate text cannot be mapped back exactly,
        ``_apply_unmapped_nominations`` redacts conservatively instead.
        """
        segments = session.segments(text, original)
        if segments is None:
            return self._apply_unmapped_nominations(original, text, session, nominations, stash)
        covers = list(nominations.spans)
        covers.extend(nominations.occurrences(original))
        segment_starts = [segment[0] for segment in segments]
        pieces: list[tuple[int, int, str, bool]] = []
        for start, end, category, gaps, *size in claim_covers(covers):
            index = max(bisect.bisect_right(segment_starts, start) - 1, 0)
            original_start, original_end, text_start, _text_end, kind = segments[index]
            single = not size or size[0] == end - start
            if (
                single
                and kind == SEGMENT_RAW
                and gaps == [(start, end)]
                and original_start <= start
                and end <= original_end
            ):
                offset = text_start - original_start
                pieces.append((start + offset, end + offset, category, False))
                continue
            for gap_start, gap_end in gaps:
                index = max(bisect.bisect_right(segment_starts, gap_start) - 1, 0)
                while index < len(segments) and segments[index][0] < gap_end:
                    original_start, original_end, text_start, _text_end, kind = segments[index]
                    index += 1
                    if kind != SEGMENT_RAW:
                        continue
                    piece_start = max(gap_start, original_start)
                    piece_end = min(gap_end, original_end)
                    if piece_start < piece_end:
                        offset = text_start - original_start
                        pieces.append((piece_start + offset, piece_end + offset, category, True))
        return substitute_pieces(text, pieces, stash)

    def _apply_unmapped_nominations(
        self,
        original: str,
        text: str,
        session: RedactionSession,
        nominations: Nominations,
        stash: Callable[[str, str], str],
    ) -> str:
        """Conservative fallback for an intermediate text that cannot be mapped back.

        Works on the intermediate text directly, so it never touches a
        marker or what the baseline redacted. Every occurrence of every
        alternation value is a cover, as in the mapped path. Every exact
        occurrence of a nominated span's text is a cover. Because the span's
        own position may be partly consumed by the baseline (what is left
        then sits in a raw run next to a marker), each raw run between
        markers whose token next to a marker overlaps the span's text is
        also a cover as a whole (trimmed), even when exact occurrences exist
        elsewhere; this may redact more than the span. Other occurrences of
        an alternation value can be partly consumed the same way, so a run
        whose token next to a marker overlaps a value (both
        whitespace-collapsed and case-folded) is a cover too. Covers are then
        resolved as in the mapped path.
        """
        covers = list(nominations.occurrences(text))
        runs: list[tuple[int, int, bool, bool]] = []
        position = 0
        follows_marker = False
        for match in session.restore_re.finditer(text):
            if match.start() > position:
                runs.append((position, match.start(), follows_marker, True))
            position = match.end()
            follows_marker = True
        if position < len(text):
            runs.append((position, len(text), follows_marker, False))
        # Exact span texts compare as they are; alternation values compare
        # whitespace-collapsed and case-folded, as their occurrences match.
        candidates: list[tuple[str, str, int, bool]] = []
        for start, end, category, rank in nominations.spans:
            value = original[start:end]
            found = text.find(value)
            while found != -1:
                covers.append((found, found + len(value), category, rank))
                found = text.find(value, found + 1)
            candidates.append((value, category, rank, False))
        for value, (category, rank) in nominations.entries():
            candidates.append((fold_for_overlap(value), category, rank, True))
        for value, category, rank, folded in candidates:
            for run_start, run_end, after_marker, before_marker in runs:
                run = text[run_start:run_end]
                if not (
                    (after_marker and leading_token_overlaps(run, value, fold=folded))
                    or (before_marker and trailing_token_overlaps(run, value, fold=folded))
                ):
                    continue
                while run_start < run_end and text[run_start] in REMNANT_TRIM_CHARS:
                    run_start += 1
                while run_end > run_start and text[run_end - 1] in REMNANT_TRIM_CHARS:
                    run_end -= 1
                if run_start < run_end:
                    covers.append((run_start, run_end, category, rank))
        pieces: list[tuple[int, int, str, bool]] = []
        for start, end, category, gaps, *size in claim_covers(covers):
            if (not size or size[0] == end - start) and gaps == [(start, end)]:
                pieces.append((start, end, category, False))
            else:
                pieces.extend((gap_start, gap_end, category, True) for gap_start, gap_end in gaps)
        return substitute_pieces(text, pieces, stash)

    def redact_path(self, path: str) -> str:
        # Paths are redacted by the built-in baseline only; detectors never
        # run on path strings.
        redacted = self._redact(path, preserve_line_count=False, detect=False)
        return PATH_REDACTION_RE.sub(self._replace_path_token, redacted)

    def placeholder(self, category: str, value: str) -> str:
        normalized = normalize_alias(value)
        key = (category, normalized)
        with self._lock:
            self.counters[category] = self.counters.get(category, 0) + 1
            if key not in self.aliases:
                ordinary = f"[{category}_{placeholder_digest(self.config.salt, category, normalized)}]"
                link = self.alias_links.get(normalized)
                if link is None:
                    placeholder = ordinary
                else:
                    # A declared alias keeps the category of whichever stage
                    # or detector redacted it and shares its group's entity
                    # hex, whatever that category is. Its ordinary
                    # placeholder, which documents redacted before the alias
                    # was declared carry, stays in the rehydration map.
                    entity, suffix = link
                    placeholder = f"[{category}_{entity}{ALIAS_FORM_SEPARATOR}{suffix}]"
                    existing_key = self.placeholder_keys.get(ordinary)
                    if existing_key is not None and existing_key != key:
                        raise RedactionCollisionError(f"Placeholder collision for {category}.")
                    self.placeholder_keys[ordinary] = key
                    self.superseded_placeholders[key] = ordinary
                existing_key = self.placeholder_keys.get(placeholder)
                if existing_key is not None and existing_key != key:
                    raise RedactionCollisionError(f"Placeholder collision for {category}.")
                self.placeholder_keys[placeholder] = key
                self.aliases[key] = placeholder
            placeholder = self.aliases[key]
            existing_value = self.raw_aliases.get(placeholder)
            if existing_value is not None and existing_value != value and normalize_alias(existing_value) != normalized:
                raise RedactionCollisionError(f"Placeholder collision for {category}.")
            self.raw_aliases.setdefault(placeholder, value)
            superseded = self.superseded_placeholders.get(key)
            if superseded is not None:
                self.raw_aliases.setdefault(superseded, value)
            return placeholder

    def rehydration_map(self) -> dict[str, str]:
        with self._lock:
            return dict(self.raw_aliases)

    def stats_snapshot(self) -> dict[str, int]:
        with self._lock:
            snapshot = dict(self.counters)
            for index, count in enumerate(self.detector_counts):
                snapshot[f"{DETECTOR_COUNT_PREFIX}{index}"] = count
            for index, count in enumerate(self.detector_positional):
                snapshot[f"{DETECTOR_POSITIONAL_PREFIX}{index}"] = count
            return snapshot

    def receipt(self, before: dict[str, int] | None = None) -> dict[str, object]:
        after = self.stats_snapshot()
        if before is not None:
            categories = set(before) | set(after)
            counts = {
                category: after.get(category, 0) - before.get(category, 0)
                for category in categories
                if after.get(category, 0) - before.get(category, 0)
            }
        else:
            counts = after
        receipt: dict[str, object] = {
            "detector_profile": self.config.detector_profile,
            "counts_by_category": dict(
                sorted((key, value) for key, value in counts.items() if not key.startswith(DETECTOR_COUNT_PREFIX))
            ),
        }
        if self.detectors:
            # Names and versions only; detector arguments may be private paths.
            receipt["detectors"] = [
                {
                    "name": detector.name,
                    "version": detector.version,
                    "nominated": counts.get(f"{DETECTOR_COUNT_PREFIX}{index}", 0),
                    "positional": counts.get(f"{DETECTOR_POSITIONAL_PREFIX}{index}", 0),
                }
                for index, detector in enumerate(self.detectors)
            ]
        return receipt

    def _nominations(self, text: str) -> Nominations | None:
        """Run plugged detectors and collect their nominations.

        Spans are validated against the original text and trimmed of
        surrounding whitespace. Spans that are empty or whitespace-only, and
        spans whose whole value is a reserved placeholder word or in the
        allow list, are ignored. Every other span is redacted by position.
        Its value (whitespace-collapsed, case kept) also joins one
        alternation that redacts the value's other occurrences, unless the
        span overlaps an existing placeholder token, exceeds
        ``MAX_NOMINATED_VALUE_CHARS`` characters or
        ``MAX_NOMINATED_VALUE_TOKENS`` tokens, or its value falls outside the
        ``MAX_NOMINATED_PATTERN_CHARS`` alternation budget (longest values
        leave first); spans kept out for size or budget are counted as
        positional. Values are deduplicated on their exact text, so every
        case variant stays in the alternation; a value nominated under
        several categories keeps the first, in detector order then span
        order. More than ``MAX_NOMINATED_VALUES`` distinct values fail closed.
        """
        placeholder_ranges = [match.span() for match in PLACEHOLDER_RE.finditer(text)]
        placeholder_starts = [start for start, _end in placeholder_ranges]
        values: dict[str, tuple[str, int]] = {}
        positions: dict[tuple[int, int], tuple[str, int]] = {}
        value_counts: list[dict[str, int]] = []
        positional_counts: list[int] = []
        rank = 0
        for detector in self.detectors:
            counts: dict[str, int] = {}
            positional = 0
            for span in run_detector(detector, text):
                start, end = span.start, span.end
                while start < end and text[start].isspace():
                    start += 1
                while end > start and text[end - 1].isspace():
                    end -= 1
                if start == end:
                    continue
                tokens = text[start:end].split()
                value = " ".join(tokens)
                folded = value.casefold()
                if folded in RESERVED_PLACEHOLDER_WORDS or folded in self.allow_lookup:
                    continue
                rank += 1
                # Identical ranges keep the first nomination, which also
                # wins the category tie for that range.
                positions.setdefault((start, end), (span.category, rank))
                # Placeholder ranges are sorted and disjoint: only the last
                # one starting before the span's end can overlap it. Such a
                # span is redacted by position outside the token, but
                # placeholder text never joins the alternation.
                index = bisect.bisect_left(placeholder_starts, end)
                if index and placeholder_ranges[index - 1][1] > start:
                    continue
                if end - start > MAX_NOMINATED_VALUE_CHARS or len(tokens) > MAX_NOMINATED_VALUE_TOKENS:
                    positional += 1
                    continue
                counts[value] = counts.get(value, 0) + 1
                if value not in values:
                    if len(values) >= MAX_NOMINATED_VALUES:
                        raise DetectorError(DETECTOR_LIMIT_MESSAGE)
                    values[value] = (span.category, rank)
            value_counts.append(counts)
            positional_counts.append(positional)
        over_budget = alternation_overflow(values)
        nominated_counts: list[int] = []
        for index, counts in enumerate(value_counts):
            nominated_counts.append(sum(1 for value in counts if value not in over_budget))
            positional_counts[index] += sum(count for value, count in counts.items() if value in over_budget)
        with self._lock:
            for index, count in enumerate(nominated_counts):
                self.detector_counts[index] += count
            for index, count in enumerate(positional_counts):
                self.detector_positional[index] += count
        if not positions:
            return None
        for value in over_budget:
            del values[value]
        spans = [(start, end, category, order) for (start, end), (category, order) in positions.items()]
        return Nominations(compile_nominated_pattern(values), values, spans)

    def _redact_identity_line(
        self,
        match: re.Match[str],
        session: RedactionSession,
        preserve_line_count: bool,
    ) -> str:
        def replace_name(name_match: re.Match[str]) -> str:
            value = name_match.group(0)
            return session.stash_placeholder(
                self.placeholder("PERSON", value),
                value,
                preserve_line_count=preserve_line_count,
            )

        return f"{match.group(1)}{match.group(2)}:{match.group(3)}{TITLECASE_TOKEN_RE.sub(replace_name, match.group(4))}"

    def _replace_multi_proper(
        self,
        match: re.Match[str],
        session: RedactionSession,
        preserve_line_count: bool,
    ) -> str:
        value = match.group(0)
        if value.casefold() in self.allow_lookup:
            return value
        return session.stash_placeholder(
            self.placeholder("PERSON", value),
            value,
            preserve_line_count=preserve_line_count,
        )

    def _replace_acronym(
        self,
        match: re.Match[str],
        session: RedactionSession,
        preserve_line_count: bool,
    ) -> str:
        value = match.group(0)
        if value.casefold() in self.allow_lookup:
            return value
        return session.stash_placeholder(
            self.placeholder("ENTITY", value),
            value,
            preserve_line_count=preserve_line_count,
        )

    def _replace_titlecase(
        self,
        match: re.Match[str],
        session: RedactionSession,
        preserve_line_count: bool,
    ) -> str:
        value = match.group(0)
        if value.casefold() in self.allow_lookup or value in COMMON_CAPITALIZED_WORDS:
            return value
        return session.stash_placeholder(
            self.placeholder("ENTITY", value),
            value,
            preserve_line_count=preserve_line_count,
        )

    def _replace_path_token(self, match: re.Match[str]) -> str:
        value = match.group(0)
        if match.group(1) is not None:
            return value
        key = value.casefold()
        if (
            key in self.allow_lookup
            or key in PATH_ALLOW_TERMS
            or value in PLACEHOLDER_CATEGORIES
        ):
            return value
        return self.placeholder("ENTITY", value)


def normalize_alias(value: str) -> str:
    stripped = value.strip()
    # Fast path: without tabs, line breaks, or double spaces the
    # substitution below would change nothing.
    if "\t" in stripped or "\n" in stripped or "\r" in stripped or "  " in stripped:
        stripped = re.sub(r"[ \t\r\n]+", " ", stripped)
    return stripped.casefold()


def placeholder_digest(salt: str, category: str, normalized: str) -> str:
    """The 128-bit hex of the ordinary placeholder for a normalized value."""
    return hmac.new(
        (salt or DEFAULT_PLACEHOLDER_SALT).encode("utf-8"),
        f"{category}:{normalized}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]


def alias_form_suffix(salt: str, normalized: str) -> str:
    """Keyed form suffix of a declared alias: the first 32 bits of an HMAC.

    Like a placeholder digest it is keyed by the vault salt, so a suffix can
    be neither computed nor checked without the salt. The message is
    domain-separated from placeholder digests (categories are upper-case
    words, never ``alias-form``).
    """
    return hmac.new(
        (salt or DEFAULT_PLACEHOLDER_SALT).encode("utf-8"),
        f"alias-form:{normalized}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:ALIAS_FORM_SUFFIX_HEX]


def claimed_before_configured_terms(value: str) -> bool:
    """Whether a value standing alone would lose characters before the configured-term stage.

    True when an existing placeholder token or any default-profile built-in
    stage that runs before configured terms (secrets, URLs, emails, ids, IP
    addresses, card and phone numbers, domains, handles) matches inside it.
    Such a value cannot reach the configured-term stage intact.
    """
    if PLACEHOLDER_RE.search(value):
        return True
    return any(pattern.search(value) for pattern, _category in EARLY_BASELINE_STAGES)


def apply_stage(
    pattern: re.Pattern[str],
    category: str,
    text: str,
    stash: Callable[[str, str], str],
) -> str:
    """Redact every match of one stage pattern in ``text``.

    With a named group ``value``, only that group becomes a placeholder and
    the rest of the match is kept as it is (a match whose ``value`` did not
    take part is kept whole); otherwise the whole match does.
    """
    if "value" not in pattern.groupindex:
        return pattern.sub(lambda match: stash(category, match.group(0)), text)

    def replace(match: re.Match[str]) -> str:
        whole = match.group(0)
        start, end = match.span("value")
        if start < 0 or start == end:
            return whole
        offset = match.start()
        return whole[: start - offset] + stash(category, match.group("value")) + whole[end - offset :]

    return pattern.sub(replace, text)


def clean_mail_name(name: str) -> str:
    """A display name stripped, without one pair of surrounding double quotes, whitespace-collapsed."""
    value = name.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return " ".join(value.split())


def mail_name_variants(name: str) -> tuple[str, ...]:
    """A cleaned display name, plus "First Last" for a "Last, First" name.

    The reordering applies only with exactly one comma and both sides
    non-empty and free of ``@``.
    """
    if name.count(",") == 1:
        last, first = (part.strip() for part in name.split(","))
        if last and first and "@" not in last and "@" not in first:
            return (name, f"{first} {last}")
    return (name,)


def harvest_mail_identities(
    redactor: Redactor,
    identities: Iterable[tuple[str, str]],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[tuple[str, str, str], ...]]:
    """Body terms and alias links harvested from raw ``(display name, address)`` pairs.

    Returns ``(names, addresses, links)``: names to redact as ``PERSON``
    terms, addresses to redact as ``EMAIL`` terms, and
    ``(normalized name, entity hex, form suffix)`` links. Pairs are
    deduplicated and processed sorted, so the result depends only on the set
    of pairs.

    Names are cleaned with ``clean_mail_name``; an empty name, one containing
    ``@``, or one equal to its own address is no name, and "Last, First" also
    yields "First Last". A name stays out of the body terms (it is still
    redacted structurally in headers) when it is configured, allow-listed,
    a reserved placeholder word, over the alias limits, claimed by an early
    baseline stage, or a single token shorter than three characters or in the
    common-word lists. Addresses of at most ``MAX_MAIL_ADDRESS_CHARS``
    characters become body terms unless reserved or allow-listed.

    Links are anchored on the address: an unconfigured name paired with
    exactly one distinct address (across all pairs) gets that address's
    configured group entity, or else the hex of its ordinary ``EMAIL``
    placeholder, with the form suffix ``alias_form_suffix(salt, name)``.
    Addresses themselves are never linked, so a name equal to a harvested
    address is not linked either. A link whose ``(entity, suffix)`` a
    configured link or an earlier name (in sorted order) already holds is
    dropped rather than failing.
    """
    salt = redactor.config.salt
    configured = redactor.configured_categories()
    configured_links = redactor.configured_alias_links
    names: dict[str, str] = {}
    addresses: dict[str, str] = {}
    address_keys: set[str] = set()
    paired: dict[str, set[str]] = {}
    for raw_name, raw_address in sorted({(str(name), str(address)) for name, address in identities}):
        address = raw_address.strip()
        address_key = normalize_alias(address)
        if address_key:
            address_keys.add(address_key)
            if (
                len(address) <= MAX_MAIL_ADDRESS_CHARS
                and address_key not in RESERVED_PLACEHOLDER_WORDS
                and address_key not in redactor.allow_lookup
            ):
                addresses.setdefault(address_key, address)
        name = clean_mail_name(raw_name)
        if not name or "@" in name or normalize_alias(name) == address_key:
            continue
        for variant in mail_name_variants(name):
            key = normalize_alias(variant)
            names.setdefault(key, variant)
            bucket = paired.setdefault(key, set())
            if address_key:
                bucket.add(address_key)

    body_names = tuple(
        value
        for key, value in sorted(names.items())
        if key not in configured and harvested_name_is_body_term(redactor, key, value)
    )

    used = set(configured_links.values())
    links: list[tuple[str, str, str]] = []
    for key in sorted(paired):
        linked = paired[key]
        if len(linked) != 1 or key in configured or key in address_keys:
            continue
        (address_key,) = linked
        configured_link = configured_links.get(address_key)
        if configured_link is not None:
            entity = configured_link[0]
        else:
            entity = placeholder_digest(salt, "EMAIL", address_key)
        link = (entity, alias_form_suffix(salt, key))
        if link in used:
            continue
        used.add(link)
        links.append((key, *link))
    return body_names, tuple(addresses[key] for key in sorted(addresses)), tuple(links)


def harvested_name_is_body_term(redactor: Redactor, key: str, value: str) -> bool:
    """Whether an unconfigured harvested name (``key`` normalized) joins the body terms."""
    if key in redactor.allow_lookup or key in RESERVED_PLACEHOLDER_WORDS:
        return False
    tokens = value.split()
    if len(value) > MAX_NOMINATED_VALUE_CHARS or len(tokens) > MAX_NOMINATED_VALUE_TOKENS:
        return False
    if len(tokens) == 1 and (len(value) < 3 or key in MAIL_NAME_STOPWORDS):
        return False
    return not claimed_before_configured_terms(value)


def compile_literal_pattern(term: str) -> re.Pattern[str] | None:
    return compile_terms_pattern([term])


def compile_terms_pattern(terms: object, *, dispatch: bool = False) -> re.Pattern[str] | None:
    """Compile one case-insensitive, word-bounded matcher for literal terms, longest first.

    With ``dispatch``, alternatives are grouped by the lower-case form of
    their first character behind a lookahead on those characters, so each
    position tries only the alternatives that can start there. That keeps
    thousands of terms (harvested mail identities) fast; the regex engine
    otherwise enters every case-insensitive alternative at every position.
    Within a group the longest-first order is kept, so the matches are the
    same except where case-insensitive matching equates first characters
    whose lower-case forms differ (``ſ`` and ``s``): another term may then
    win there, and the text is redacted either way.
    """
    parts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for term in terms:
        cleaned = str(term).strip()
        if not cleaned:
            continue
        key = re.sub(r"[ \t_-]+", " ", cleaned).casefold()
        if key in seen:
            continue
        seen.add(key)
        raw_tokens = [part for part in re.split(r"[ \t_-]+", cleaned) if part]
        if raw_tokens:
            parts.append((r"[ \t_-]+".join(re.escape(token) for token in raw_tokens), raw_tokens[0][0]))
    if not parts:
        return None
    parts.sort(key=lambda part: len(part[0]), reverse=True)
    if dispatch:
        groups: dict[str, tuple[set[str], list[str]]] = {}
        for part, first in parts:
            starts, members = groups.setdefault(first.lower(), (set(), []))
            starts.add(first)
            members.append(part)
        body = "|".join(
            f"(?=(?:{'|'.join(re.escape(first) for first in sorted(starts))}))"
            f"(?:{'|'.join(f'(?:{part})' for part in members)})"
            for starts, members in groups.values()
        )
    else:
        body = "|".join(f"(?:{part})" for part, _first in parts)
    return re.compile(rf"(?<![A-Za-z0-9])(?:{body})(?![A-Za-z0-9])", re.IGNORECASE)


WHITESPACE_RUN_PATTERN = r"\s+"


# Rank of an alternation match whose value cannot be looked up: it loses
# every tie against a real nomination.
NOMINATION_FALLBACK_RANK = 1 << 62


class Nominations:
    """Detector nominations for one text: positional spans plus one alternation.

    ``spans`` are ``(start, end, category, rank)`` over the original text,
    where ``rank`` orders nominations by detector, then span. ``pattern``
    (or ``None``) finds every occurrence of the alternation values.
    ``lookup`` maps a matched string back to its nominated category and
    rank: by the whitespace-collapsed ``lower()`` form, then the
    ``casefold()`` form, then ``NOMINATION_FALLBACK_CATEGORY``, so every
    match is redacted even when the regex engine's case-insensitive matching
    equates strings that neither normal form does.
    """

    __slots__ = ("pattern", "spans", "_by_lower", "_by_fold")

    def __init__(
        self,
        pattern: re.Pattern[str] | None,
        values: dict[str, tuple[str, int]],
        spans: list[tuple[int, int, str, int]],
    ) -> None:
        self.pattern = pattern
        self.spans = tuple(spans)
        self._by_lower: dict[str, tuple[str, int]] = {}
        self._by_fold: dict[str, tuple[str, int]] = {}
        for value, entry in values.items():
            self._by_lower.setdefault(value.lower(), entry)
            self._by_fold.setdefault(value.casefold(), entry)

    def lookup(self, matched: str) -> tuple[str, int]:
        value = nominated_value_key(matched)
        entry = self._by_lower.get(value.lower())
        if entry is None:
            entry = self._by_fold.get(value.casefold(), (NOMINATION_FALLBACK_CATEGORY, NOMINATION_FALLBACK_RANK))
        return entry

    def category(self, matched: str) -> str:
        return self.lookup(matched)[0]

    def entries(self) -> list[tuple[str, tuple[str, int]]]:
        """Each alternation value's ``lower()`` form with its category and rank."""
        return list(self._by_lower.items())

    def occurrences(self, text: str) -> list[tuple[int, int, str, int, int]]:
        """Every occurrence of every alternation value in ``text``, as covers.

        Each search restarts one character after the previous match's start,
        so every position is tried and occurrences may overlap; at each
        start position the longest value wins, and a shorter value starting
        there lies inside it. (This finds exactly what a zero-width
        lookahead ``finditer`` would, about twice as fast under
        ``re.IGNORECASE``.) Overlapping and adjacent occurrences of the same
        value (the same looked-up category and rank) merge into one cover,
        so a value that overlaps itself (``éé`` in a run of ``é``) yields
        one cover per run, not one per position. Covers are ``(start, end, category, rank, size)``,
        where ``size`` is the length of the longest merged occurrence; a
        cover whose ``size`` equals its length is exactly one occurrence.
        """
        if self.pattern is None:
            return []
        covers: list[tuple[int, int, str, int, int]] = []
        latest: dict[tuple[str, int], int] = {}
        entries: dict[str, tuple[str, int]] = {}
        search = self.pattern.search
        match = search(text)
        while match is not None:
            start, end = match.span(1)
            match = search(text, start + 1)
            matched = text[start:end]
            entry = entries.get(matched)
            if entry is None:
                entry = entries[matched] = self.lookup(matched)
            index = latest.get(entry)
            if index is not None:
                merged_start, merged_end, category, rank, size = covers[index]
                if start <= merged_end:
                    covers[index] = (merged_start, max(merged_end, end), category, rank, max(size, end - start))
                    continue
            latest[entry] = len(covers)
            covers.append((start, end, entry[0], entry[1], end - start))
        return covers


def claim_covers(
    covers: list[tuple],
) -> list[tuple]:
    """Resolve overlapping covers: longest first, then by rank, then by position.

    Each cover ``(start, end, category, rank)`` claims the parts of its range
    that no earlier cover claimed. A cover may carry a fifth field, ``size``,
    that replaces ``end - start`` as its length in the ordering and is passed
    through to its result (merged occurrence runs rank as their longest
    occurrence). Returns ``(start, end, category, gaps)`` (plus ``size`` when
    given) for every cover that claimed something, where ``gaps`` are its
    claimed ranges in order, adjacent claimed parts merged.

    Every claim boundary is a cover endpoint, so the elementary intervals
    between consecutive distinct endpoints are each claimed whole or not at
    all. A union-find array with path compression maps each elementary
    interval to the first unclaimed one at or after it, so after the sort
    each interval is claimed once and skipped in near-constant amortized
    time: O(n log n) overall, dominated by the sort.
    """
    if not covers:
        return []
    points = sorted({point for cover in covers for point in (cover[0], cover[1])})
    point_index = {point: index for index, point in enumerate(points)}
    # parent[k] == k while elementary interval k is unclaimed. The last point
    # is a sentinel that is never claimed, so every find terminates.
    parent = list(range(len(points)))

    def find(index: int) -> int:
        root = index
        while parent[root] != root:
            root = parent[root]
        while parent[index] != root:
            parent[index], index = root, parent[index]
        return root

    def order(cover: tuple) -> tuple[int, int, int]:
        size = cover[4] if len(cover) > 4 else cover[1] - cover[0]
        return (-size, cover[3], cover[0])

    resolved: list[tuple] = []
    for cover in sorted(covers, key=order):
        start, end, category = cover[0], cover[1], cover[2]
        last = point_index[end]
        index = point_index[start]
        gaps: list[tuple[int, int]] = []
        while index < last:
            if parent[index] != index:
                index = find(index)
                continue
            gap_start = points[index]
            parent[index] = index + 1
            index += 1
            while index < last and parent[index] == index:
                parent[index] = index + 1
                index += 1
            gaps.append((gap_start, points[index]))
        if gaps:
            resolved.append((start, end, category, gaps, *cover[4:]))
    return resolved


def substitute_pieces(
    text: str,
    pieces: list[tuple[int, int, str, bool]],
    stash: Callable[[str, str], str],
) -> str:
    """Replace disjoint ``(start, end, category, trim)`` pieces of ``text`` with placeholders.

    Remnant pieces (``trim``) lose ASCII whitespace and ASCII punctuation at
    their edges first; a piece with nothing else is left as it is.
    """
    if not pieces:
        return text
    pieces.sort(key=lambda piece: (piece[0], piece[1]))
    parts: list[str] = []
    position = 0
    for start, end, category, trim in pieces:
        start = max(start, position)
        if trim:
            while start < end and text[start] in REMNANT_TRIM_CHARS:
                start += 1
            while end > start and text[end - 1] in REMNANT_TRIM_CHARS:
                end -= 1
        if start >= end:
            continue
        parts.append(text[position:start])
        parts.append(stash(category, text[start:end]))
        position = end
    parts.append(text[position:])
    return "".join(parts)


def fold_for_overlap(value: str) -> str:
    """``value`` with every whitespace run collapsed to one ASCII space, case-folded."""
    return re.sub(WHITESPACE_RUN_PATTERN, " ", value).casefold()


def _edge_token(run: str, *, leading: bool) -> str:
    """The first (or last) maximal run of characters outside ``REMNANT_TRIM_CHARS`` in ``run``."""
    characters = run if leading else reversed(run)
    token: list[str] = []
    for char in characters:
        if char in REMNANT_TRIM_CHARS:
            if token:
                break
            continue
        token.append(char)
    return "".join(token if leading else reversed(token))


def leading_token_overlaps(run: str, value: str, *, fold: bool = False) -> bool:
    """Whether the first token of ``run`` lies inside ``value`` or starts with a suffix of it.

    With ``fold``, the token is compared after ``fold_for_overlap``.
    """
    token = _edge_token(run, leading=True)
    if not token:
        return False
    if fold:
        token = fold_for_overlap(token)
    return token in value or any(value.endswith(token[:size]) for size in range(min(len(token), len(value)), 0, -1))


def trailing_token_overlaps(run: str, value: str, *, fold: bool = False) -> bool:
    """Whether the last token of ``run`` lies inside ``value`` or ends with a prefix of it.

    With ``fold``, the token is compared after ``fold_for_overlap``.
    """
    token = _edge_token(run, leading=False)
    if not token:
        return False
    if fold:
        token = fold_for_overlap(token)
    return token in value or any(value.startswith(token[-size:]) for size in range(min(len(token), len(value)), 0, -1))


def alternation_overflow(values: dict[str, object]) -> set[str]:
    """Values left out of the alternation so its total length fits the budget.

    Values leave longest first (ties in sorted order) until the summed
    length of the rest is at most ``MAX_NOMINATED_PATTERN_CHARS``; their
    spans are then redacted only where they were nominated.
    """
    total = sum(len(value) for value in values)
    over: set[str] = set()
    if total <= MAX_NOMINATED_PATTERN_CHARS:
        return over
    for value in sorted(values, key=lambda value: (-len(value), value)):
        over.add(value)
        total -= len(value)
        if total <= MAX_NOMINATED_PATTERN_CHARS:
            break
    return over


def nominated_value_key(value: str) -> str:
    """Deduplication key for a detector-nominated value: whitespace runs collapsed, case kept."""
    return " ".join(value.split())


def compile_nominated_pattern(values: object) -> re.Pattern[str] | None:
    """Compile one matcher for detector-nominated values of every category.

    Sibling of ``compile_terms_pattern`` for configured terms, which is left
    unchanged. Values are deduplicated on their exact whitespace-collapsed
    text (every case variant is kept, because case-insensitive matching and
    ``casefold`` disagree on characters such as ``ß`` and ``ﬁ``). Any
    whitespace run is tolerated when matching; matching is case-insensitive
    with word-boundary guards on ASCII letters and digits. The guards are
    scoped case-sensitive (``(?-i:...)``) so that, unlike the guards of
    configured terms, they do not also match ``İ``, ``ı``, ``ſ``, or the
    Kelvin sign, which case-insensitive ``[A-Za-z0-9]`` equates with ASCII
    letters. Group 1 is the matched value. ``Nominations.occurrences``
    restarts each search one character after the previous match's start, so
    every position is tried and overlapping occurrences are found; longest
    values come first, so at each position the longest matching value wins.
    The alternation is built from sorted values, so identical nomination
    sets yield an identical pattern string and reuse ``re``'s
    compiled-pattern cache.
    """
    keys = {nominated_value_key(str(value)) for value in values}
    keys.discard("")
    if not keys:
        return None
    ordered = sorted(keys, key=lambda key: (-len(key), key))
    parts = [WHITESPACE_RUN_PATTERN.join(re.escape(token) for token in key.split(" ")) for key in ordered]
    body = "|".join(f"(?:{part})" for part in parts)
    return re.compile(rf"(?<!(?-i:[A-Za-z0-9]))({body})(?!(?-i:[A-Za-z0-9]))", re.IGNORECASE)
