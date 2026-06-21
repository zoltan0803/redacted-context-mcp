"""Text and path redaction primitives."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from dataclasses import dataclass, field

from .defaults import (
    ACRONYM_RE,
    COMMON_CAPITALIZED_WORDS,
    CONNECTION_STRING_RE,
    CREDIT_CARD_RE,
    DEFAULT_ALLOW_TERMS,
    DOB_RE,
    DOMAIN_RE,
    DRIVER_ID_RE,
    EMAIL_RE,
    GENERIC_SECRET_RE,
    HANDLE_RE,
    IBAN_RE,
    IDENTITY_LINE_RE,
    IP_RE,
    IPV6_RE,
    MAC_RE,
    MONTHS_AND_DAYS,
    MULTI_PROPER_RE,
    ORG_SUFFIX_RE,
    PASSPORT_RE,
    PATH_ALLOW_TERMS,
    PATH_TOKEN_RE,
    PEM_PRIVATE_KEY_RE,
    PHONE_RE,
    PLACEHOLDER_RE,
    PROMPT_INJECTION_RE,
    RESERVED_PLACEHOLDER_WORDS,
    SPEAKER_LABEL_RE,
    SSN_RE,
    TITLECASE_TOKEN_RE,
    UNICODE_CONTROL_RE,
    URL_RE,
    UUID_RE,
)
from .models import RedactionConfig


LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")


class RedactionCollisionError(RuntimeError):
    """Raised when two distinct raw values would share one placeholder."""


def preserved_line_breaks(value: str) -> str:
    return "".join(LINE_BREAK_RE.findall(value))


class RedactionSession:
    def __init__(self, source: str) -> None:
        for codepoint in range(0xE000, 0xF8FE, 2):
            prefix = chr(codepoint)
            suffix = chr(codepoint + 1)
            if prefix not in source and suffix not in source:
                self.prefix = prefix
                self.suffix = suffix
                break
        else:
            raise ValueError("Could not allocate internal redaction markers.")
        self.replacements: list[str] = []
        self.restore_re = re.compile(
            re.escape(self.prefix) + r"(\d+)" + re.escape(self.suffix)
        )

    def stash_allowed(self, value: str) -> str:
        return self._stash(value)

    def stash_placeholder(self, placeholder: str, source_text: str, *, preserve_line_count: bool) -> str:
        suffix = preserved_line_breaks(source_text) if preserve_line_count else ""
        return self._stash(placeholder) + suffix

    def restore_all(self, text: str) -> str:
        return self.restore_re.sub(lambda match: self.replacements[int(match.group(1))], text)

    def _stash(self, value: str) -> str:
        marker = f"{self.prefix}{len(self.replacements)}{self.suffix}"
        self.replacements.append(value)
        return marker


@dataclass
class Redactor:
    config: RedactionConfig
    mode: str = "strict"
    counters: dict[str, int] = field(default_factory=dict)
    aliases: dict[tuple[str, str], str] = field(default_factory=dict)
    raw_aliases: dict[str, str] = field(default_factory=dict)
    placeholder_keys: dict[str, tuple[str, str]] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        allow_terms = set(DEFAULT_ALLOW_TERMS) | set(MONTHS_AND_DAYS) | set(self.config.allow)
        self.allow_terms = {term for term in allow_terms if term}
        self.allow_lookup = {term.casefold() for term in self.allow_terms}
        self.allow_pattern = compile_terms_pattern(self.allow_terms)
        self.literal_patterns: list[tuple[str, re.Pattern[str]]] = []
        for category, terms in (
            ("CLIENT", self.config.clients),
            ("ORG", self.config.organizations),
            ("PERSON", self.config.people),
            ("SENSITIVE", self.config.terms),
        ):
            filtered = [term for term in terms if term.casefold() not in RESERVED_PLACEHOLDER_WORDS]
            pattern = compile_terms_pattern(filtered)
            if pattern is not None:
                self.literal_patterns.append((category, pattern))

    def redact(self, text: str, *, preserve_line_count: bool = False) -> str:
        if not text:
            return text

        session = RedactionSession(text)

        def stash(category: str, value: str) -> str:
            return session.stash_placeholder(
                self.placeholder(category, value),
                value,
                preserve_line_count=preserve_line_count,
            )

        text = PLACEHOLDER_RE.sub(lambda match: session.stash_allowed(match.group(0)), text)
        text = PEM_PRIVATE_KEY_RE.sub(lambda match: stash("SECRET", match.group(0)), text)
        text = GENERIC_SECRET_RE.sub(lambda match: stash("SECRET", match.group(0)), text)
        text = URL_RE.sub(lambda match: stash("URL", match.group(0)), text)
        text = EMAIL_RE.sub(lambda match: stash("EMAIL", match.group(0)), text)
        text = UUID_RE.sub(lambda match: stash("ID", match.group(0)), text)
        text = IP_RE.sub(lambda match: stash("IP", match.group(0)), text)
        text = SSN_RE.sub(lambda match: stash("SSN", match.group(0)), text)
        text = CREDIT_CARD_RE.sub(lambda match: stash("CARD", match.group(0)), text)
        text = PHONE_RE.sub(lambda match: stash("PHONE", match.group(0)), text)
        text = DOMAIN_RE.sub(lambda match: stash("DOMAIN", match.group(0)), text)
        text = HANDLE_RE.sub(lambda match: stash("HANDLE", match.group(0)), text)

        if self.config.detector_profile == "extended":
            text = CONNECTION_STRING_RE.sub(lambda match: stash("CONNECTION", match.group(0)), text)
            text = IBAN_RE.sub(lambda match: stash("IBAN", match.group(0)), text)
            text = IPV6_RE.sub(lambda match: stash("IP", match.group(0)), text)
            text = MAC_RE.sub(lambda match: stash("MAC", match.group(0)), text)
            text = DOB_RE.sub(lambda match: stash("DOB", match.group(0)), text)
            text = PASSPORT_RE.sub(lambda match: stash("PASSPORT", match.group(0)), text)
            text = DRIVER_ID_RE.sub(lambda match: stash("DRIVER_ID", match.group(0)), text)
            text = UNICODE_CONTROL_RE.sub(lambda match: stash("UNICODE_CONTROL", match.group(0)), text)
            text = PROMPT_INJECTION_RE.sub(lambda match: stash("PROMPT_INJECTION", match.group(0)), text)

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

        return session.restore_all(text)

    def redact_path(self, path: str) -> str:
        redacted = self.redact(path)
        return PATH_TOKEN_RE.sub(self._replace_path_token, redacted)

    def placeholder(self, category: str, value: str) -> str:
        normalized = normalize_alias(value)
        key = (category, normalized)
        with self._lock:
            self.counters[category] = self.counters.get(category, 0) + 1
            if key not in self.aliases:
                salt = self.config.salt or "redacted-context-mcp-v1"
                digest = hmac.new(
                    salt.encode("utf-8"),
                    f"{category}:{normalized}".encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()[:32]
                placeholder = f"[{category}_{digest}]"
                existing_key = self.placeholder_keys.get(placeholder)
                if existing_key is not None and existing_key != key:
                    raise RedactionCollisionError(f"Placeholder collision for {category}.")
                self.placeholder_keys[placeholder] = key
                self.aliases[key] = placeholder
            placeholder = self.aliases[key]
            existing_value = self.raw_aliases.get(placeholder)
            if existing_value is not None and normalize_alias(existing_value) != normalized:
                raise RedactionCollisionError(f"Placeholder collision for {category}.")
            self.raw_aliases.setdefault(placeholder, value)
            return placeholder

    def rehydration_map(self) -> dict[str, str]:
        with self._lock:
            return dict(self.raw_aliases)

    def stats_snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self.counters)

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
        return {
            "detector_profile": self.config.detector_profile,
            "counts_by_category": dict(sorted(counts.items())),
        }

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

        return f"{match.group(1)}: {TITLECASE_TOKEN_RE.sub(replace_name, match.group(2))}"

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
        key = value.casefold()
        if (
            key in self.allow_lookup
            or key in PATH_ALLOW_TERMS
            or value
            in {
                "CLIENT",
                "ORG",
                "PERSON",
                "SENSITIVE",
                "ENTITY",
                "EMAIL",
                "PHONE",
                "URL",
                "HANDLE",
                "SECRET",
                "SSN",
                "CARD",
                "IP",
                "ID",
                "DOMAIN",
            }
        ):
            return value
        return self.placeholder("ENTITY", value)


def normalize_alias(value: str) -> str:
    return re.sub(r"[ \t\r\n]+", " ", value.strip()).casefold()


def compile_literal_pattern(term: str) -> re.Pattern[str] | None:
    return compile_terms_pattern([term])


def compile_terms_pattern(terms: object) -> re.Pattern[str] | None:
    parts: list[str] = []
    seen: set[str] = set()
    for term in terms:
        cleaned = str(term).strip()
        if not cleaned:
            continue
        key = re.sub(r"[ \t_-]+", " ", cleaned).casefold()
        if key in seen:
            continue
        seen.add(key)
        tokens = [re.escape(part) for part in re.split(r"[ \t_-]+", cleaned) if part]
        if tokens:
            parts.append(r"[ \t_-]+".join(tokens))
    if not parts:
        return None
    parts.sort(key=len, reverse=True)
    body = "|".join(f"(?:{part})" for part in parts)
    return re.compile(rf"(?<![A-Za-z0-9])(?:{body})(?![A-Za-z0-9])", re.IGNORECASE)
