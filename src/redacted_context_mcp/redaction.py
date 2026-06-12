"""Text and path redaction primitives."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .defaults import (
    ACRONYM_RE,
    COMMON_CAPITALIZED_WORDS,
    DEFAULT_ALLOW_TERMS,
    EMAIL_RE,
    HANDLE_RE,
    IDENTITY_LINE_RE,
    MONTHS_AND_DAYS,
    MULTI_PROPER_RE,
    ORG_SUFFIX_RE,
    PATH_ALLOW_TERMS,
    PATH_TOKEN_RE,
    PHONE_RE,
    PLACEHOLDER_RE,
    RESERVED_PLACEHOLDER_WORDS,
    SPEAKER_LABEL_RE,
    TITLECASE_TOKEN_RE,
    URL_RE,
)
from .models import RedactionConfig

@dataclass
class Redactor:
    config: RedactionConfig
    mode: str = "strict"
    counters: dict[str, int] = field(default_factory=dict)
    aliases: dict[tuple[str, str], str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        allow_terms = set(DEFAULT_ALLOW_TERMS) | set(MONTHS_AND_DAYS) | set(self.config.allow)
        self.allow_terms = {term for term in allow_terms if term}
        self.allow_lookup = {term.casefold() for term in self.allow_terms}
        self.literal_patterns: list[tuple[str, re.Pattern[str]]] = []
        for category, terms in (
            ("CLIENT", self.config.clients),
            ("ORG", self.config.organizations),
            ("PERSON", self.config.people),
            ("SENSITIVE", self.config.terms),
        ):
            for term in sorted(set(terms), key=len, reverse=True):
                if term.casefold() in RESERVED_PLACEHOLDER_WORDS:
                    continue
                pattern = compile_literal_pattern(term)
                if pattern is not None:
                    self.literal_patterns.append((category, pattern))

    def redact(self, text: str) -> str:
        if not text:
            return text

        text = URL_RE.sub(lambda match: self.placeholder("URL", match.group(0)), text)
        text = EMAIL_RE.sub(lambda match: self.placeholder("EMAIL", match.group(0)), text)
        text = PHONE_RE.sub(lambda match: self.placeholder("PHONE", match.group(0)), text)
        text = HANDLE_RE.sub(lambda match: self.placeholder("HANDLE", match.group(0)), text)

        for category, pattern in self.literal_patterns:
            text = pattern.sub(lambda match, cat=category: self.placeholder(cat, match.group(0)), text)

        text, protected = self._protect_allowed(text)
        text = ORG_SUFFIX_RE.sub(lambda match: self.placeholder("ORG", match.group(0)), text)
        text = MULTI_PROPER_RE.sub(self._replace_multi_proper, text)
        text = SPEAKER_LABEL_RE.sub(lambda match: self.placeholder("PERSON", match.group(1)), text)
        text = IDENTITY_LINE_RE.sub(self._redact_identity_line, text)

        if self.mode == "strict":
            text, placeholders = self._protect_placeholders(text)
            text = ACRONYM_RE.sub(self._replace_acronym, text)
            text = TITLECASE_TOKEN_RE.sub(self._replace_titlecase, text)
            text = self._restore_allowed(text, placeholders)

        return self._restore_allowed(text, protected)

    def redact_path(self, path: str) -> str:
        redacted = self.redact(path)
        return PATH_TOKEN_RE.sub(self._replace_path_token, redacted)

    def placeholder(self, category: str, value: str) -> str:
        normalized = normalize_alias(value)
        key = (category, normalized)
        if key not in self.aliases:
            next_value = self.counters.get(category, 0) + 1
            self.counters[category] = next_value
            self.aliases[key] = f"[{category}_{next_value:02d}]"
        return self.aliases[key]

    def _protect_allowed(self, text: str) -> tuple[str, dict[str, str]]:
        protected: dict[str, str] = {}
        for index, term in enumerate(sorted(self.allow_terms, key=len, reverse=True)):
            pattern = compile_literal_pattern(term)
            if pattern is None:
                continue

            def replace(match: re.Match[str], *, i: int = index) -> str:
                marker = f"\uE000{i}_{len(protected)}\uE001"
                protected[marker] = match.group(0)
                return marker

            text = pattern.sub(replace, text)
        return text, protected

    @staticmethod
    def _restore_allowed(text: str, protected: dict[str, str]) -> str:
        for marker, value in protected.items():
            text = text.replace(marker, value)
        return text

    @staticmethod
    def _protect_placeholders(text: str) -> tuple[str, dict[str, str]]:
        protected: dict[str, str] = {}

        def replace(match: re.Match[str]) -> str:
            marker = f"\uE002{len(protected)}\uE003"
            protected[marker] = match.group(0)
            return marker

        return PLACEHOLDER_RE.sub(replace, text), protected

    def _redact_identity_line(self, match: re.Match[str]) -> str:
        return f"{match.group(1)}: {TITLECASE_TOKEN_RE.sub(lambda m: self.placeholder('PERSON', m.group(0)), match.group(2))}"

    def _replace_multi_proper(self, match: re.Match[str]) -> str:
        value = match.group(0)
        if value.casefold() in self.allow_lookup:
            return value
        return self.placeholder("PERSON", value)

    def _replace_acronym(self, match: re.Match[str]) -> str:
        value = match.group(0)
        if value.casefold() in self.allow_lookup:
            return value
        return self.placeholder("ENTITY", value)

    def _replace_titlecase(self, match: re.Match[str]) -> str:
        value = match.group(0)
        if value.casefold() in self.allow_lookup or value in COMMON_CAPITALIZED_WORDS:
            return value
        return self.placeholder("ENTITY", value)

    def _replace_path_token(self, match: re.Match[str]) -> str:
        value = match.group(0)
        key = value.casefold()
        if (
            key in self.allow_lookup
            or key in PATH_ALLOW_TERMS
            or value in {"CLIENT", "ORG", "PERSON", "SENSITIVE", "ENTITY", "EMAIL", "PHONE", "URL", "HANDLE"}
        ):
            return value
        return self.placeholder("ENTITY", value)


def normalize_alias(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).casefold()


def compile_literal_pattern(term: str) -> re.Pattern[str] | None:
    term = term.strip()
    if not term:
        return None
    parts = [re.escape(part) for part in re.split(r"[\s_-]+", term) if part]
    if not parts:
        return None
    separator = r"[\s_-]+"
    body = separator.join(parts)
    return re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])", re.IGNORECASE)
