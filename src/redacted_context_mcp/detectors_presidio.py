"""Optional Microsoft Presidio detector adapter.

Enable with ``--detector presidio`` or ``--detector presidio=OPTIONS`` after
``pip install "redacted-context-mcp[presidio]"`` and installing a spaCy model.
``OPTIONS`` is a comma-separated ``key=value`` list:

- ``model``: installed spaCy model package (default ``en_core_web_lg``, the
  Presidio default). Missing models are never downloaded automatically.
- ``language``: analysis language code (default ``en``).
- ``threshold``: minimum Presidio score from 0 to 1 (default ``0.5``).
- ``entities``: ``|``-separated allowlist of Presidio entity types.
- ``include_dates``: ``true`` to also redact ``DATE_TIME`` results (default
  ``false``; dates map to ``SENSITIVE`` unless ``map`` says otherwise).
- ``map``: ``|``-separated ``ENTITY_TYPE:CATEGORY`` overrides of the default
  label mapping, with canonical placeholder categories.

The library is imported only inside ``factory``, so importing this module (or
``detectors``) never imports Presidio or spaCy. The analyzer is built once at
startup; calls are serialized with a lock because Presidio does not document
thread safety. Inference is local and deterministic for identical input:

- spaCy is pinned to the CPU (``PRESIDIO_DEVICE=cpu`` unless the operator set
  it), so an importable CUDA build of torch cannot move inference to a GPU.
- Presidio's email recognizer uses ``tldextract``, which by default downloads
  the Public Suffix List on first use and caches it under the home directory.
  The factory replaces tldextract's shared extractor with one that uses only
  the snapshot bundled with tldextract, never fetches, and never writes a
  cache, and the start-up check analyzes an email address and a phone number
  so the pattern recognizers run before the first request.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, NamedTuple, Sequence

from .defaults import PLACEHOLDER_CATEGORIES
from .detectors import (
    Span,
    collect_window_spans,
    installed_version as distribution_version,
    parse_bool_option,
    parse_category_pairs,
    parse_detector_options,
    parse_float_option,
)


DETECTOR_NAME = "presidio"
INSTALL_MESSAGE = (
    "The presidio detector requires Presidio. Install it with: "
    'pip install "redacted-context-mcp[presidio]"'
)
DISTRIBUTION = "presidio-analyzer"
TLDEXTRACT_MESSAGE = (
    "The presidio detector requires tldextract, a Presidio dependency, to parse email domains offline. "
    'Reinstall it with: pip install "redacted-context-mcp[presidio]"'
)
DEVICE_ENV_VAR = "PRESIDIO_DEVICE"
WARM_UP_TEXT = "Warm-up check: write to warm.up@example.com or call +1 415 555 0133 about the detector."
DEFAULT_MODEL = "en_core_web_lg"
DEFAULT_LANGUAGE = "en"
DEFAULT_THRESHOLD = 0.5
DEFAULT_MAX_CHUNK_CHARS = 100_000
DEFAULT_CHUNK_OVERLAP_CHARS = 1_000
DATE_ENTITY = "DATE_TIME"
DATE_DEFAULT_CATEGORY = "SENSITIVE"
OPTION_KEYS = frozenset({"model", "language", "threshold", "entities", "include_dates", "map"})
ENTITY_TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
MODEL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
LANGUAGE_RE = re.compile(r"[a-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})?")

DEFAULT_ENTITY_CATEGORIES: Mapping[str, str] = {
    "PERSON": "PERSON",
    "ORGANIZATION": "ORG",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "US_SSN": "SSN",
    "IP_ADDRESS": "IP",
    "URL": "URL",
    "CREDIT_CARD": "CARD",
    "IBAN_CODE": "IBAN",
    "US_DRIVER_LICENSE": "DRIVER_ID",
    "US_PASSPORT": "PASSPORT",
    "LOCATION": "SENSITIVE",
    "NRP": "SENSITIVE",
    "MEDICAL_LICENSE": "ID",
    "US_BANK_NUMBER": "ID",
    "US_ITIN": "ID",
    "UK_NHS": "ID",
    "CRYPTO": "SECRET",
}


def installed_version() -> str:
    return distribution_version(DISTRIBUTION)


def chunk_windows(text: str, max_chars: int, overlap_chars: int) -> list[tuple[int, int]]:
    """Split ``text`` into ``[start, end)`` windows of at most ``max_chars``.

    Cuts prefer a paragraph break, then a line break, then other whitespace,
    searched in the second half of each window; a window without whitespace is
    cut hard. Each following window starts up to ``overlap_chars`` before the
    cut (snapped forward to just after whitespace, so it does not begin
    mid-word) so a value crossing a cut is still seen whole. Offsets always
    refer to ``text`` itself; no text is rebuilt.
    """

    length = len(text)
    if length <= max_chars:
        return [(0, length)]
    windows: list[tuple[int, int]] = []
    start = 0
    while True:
        limit = start + max_chars
        if limit >= length:
            windows.append((start, length))
            return windows
        cut = _best_cut(text, start + max_chars // 2, limit)
        windows.append((start, cut))
        start = _next_window_start(text, max(cut - overlap_chars, start + 1), cut)


def _best_cut(text: str, low: int, limit: int) -> int:
    for separator in ("\n\n", "\n"):
        index = text.rfind(separator, low, limit)
        if index != -1 and index + len(separator) <= limit:
            return index + len(separator)
    for index in range(limit - 1, low - 1, -1):
        if text[index].isspace():
            return index + 1
    return limit


def _next_window_start(text: str, low: int, cut: int) -> int:
    if low >= cut or text[low - 1].isspace():
        return low
    for index in range(low, cut):
        if text[index].isspace():
            return index + 1
    return low


class PresidioDetector:
    """Nominate spans found by a Presidio ``AnalyzerEngine``.

    ``analyzer`` is any object with ``analyze(text=..., language=...,
    entities=...)`` returning results with ``start``, ``end``,
    ``entity_type``, and ``score``; tests inject a fake. Results below
    ``threshold``, entity types without a canonical category, and
    ``DATE_TIME`` (unless ``include_dates``) are skipped. Nested results of
    the same category collapse into the containing span; nested results of a
    different category are kept (see ``drop_contained_spans``).
    """

    name = DETECTOR_NAME

    def __init__(
        self,
        analyzer: Any,
        *,
        version: str | None = None,
        language: str = DEFAULT_LANGUAGE,
        threshold: float = DEFAULT_THRESHOLD,
        entities: Sequence[str] | None = None,
        include_dates: bool = False,
        mapping: Mapping[str, str] | None = None,
        max_chunk_chars: int = DEFAULT_MAX_CHUNK_CHARS,
        chunk_overlap_chars: int = DEFAULT_CHUNK_OVERLAP_CHARS,
    ) -> None:
        self.analyzer = analyzer
        self.version = version or installed_version()
        self.language = language
        self.threshold = float(threshold)
        self.entities = tuple(entities) if entities is not None else None
        self.include_dates = bool(include_dates)
        resolved = dict(DEFAULT_ENTITY_CATEGORIES if mapping is None else mapping)
        if self.include_dates:
            resolved.setdefault(DATE_ENTITY, DATE_DEFAULT_CATEGORY)
        else:
            resolved.pop(DATE_ENTITY, None)
        if any(category not in PLACEHOLDER_CATEGORIES for category in resolved.values()):
            raise ValueError("Presidio mapping targets must be canonical placeholder categories.")
        self.mapping: dict[str, str] = resolved
        if max_chunk_chars < 2 or not 0 <= chunk_overlap_chars < max_chunk_chars // 2:
            raise ValueError("Presidio chunk overlap must be smaller than half the chunk size.")
        self.max_chunk_chars = max_chunk_chars
        self.chunk_overlap_chars = chunk_overlap_chars
        # The entities allowlist also filters results (Presidio may return
        # other types), so only allowed types keep a category.
        if self.entities is None:
            self._categories: dict[str, str] = dict(self.mapping)
        else:
            allowed = set(self.entities)
            self._categories = {name: category for name, category in self.mapping.items() if name in allowed}
        self._lock = threading.Lock()

    def detect(self, text: str) -> list[Span]:
        if not text:
            return []
        requested = list(self.entities) if self.entities is not None else None

        def analyze(chunk: str) -> list[Any]:
            return list(self.analyzer.analyze(text=chunk, language=self.language, entities=requested))

        with self._lock:
            return collect_window_spans(
                text,
                chunk_windows(text, self.max_chunk_chars, self.chunk_overlap_chars),
                analyze,
                _read_result,
                categories=self._categories,
                threshold=self.threshold,
                library="Presidio",
            )


def _read_result(result: Any) -> tuple[object, object, object, object]:
    return result.entity_type, result.start, result.end, result.score


# Option parsing -------------------------------------------------------------


@dataclass(frozen=True)
class PresidioOptions:
    model: str = DEFAULT_MODEL
    language: str = DEFAULT_LANGUAGE
    threshold: float = DEFAULT_THRESHOLD
    entities: tuple[str, ...] | None = None
    include_dates: bool = False
    mapping: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_ENTITY_CATEGORIES))
    map_overrides: tuple[str, ...] = ()


def _normalize_entity_type(value: str) -> str | None:
    return value if ENTITY_TYPE_RE.fullmatch(value) else None


def _entity_type(value: str, key: str) -> str:
    entity_type = value.strip()
    if not ENTITY_TYPE_RE.fullmatch(entity_type):
        raise SystemExit(
            f"The presidio detector option '{key}' expects Presidio entity types such as PERSON or US_SSN."
        )
    return entity_type


def parse_presidio_options(argument: str | None) -> PresidioOptions:
    """Validate the ``--detector presidio=...`` argument without importing Presidio."""

    raw = parse_detector_options(argument, detector=DETECTOR_NAME, allowed=OPTION_KEYS)
    model = raw.get("model", DEFAULT_MODEL)
    if not MODEL_NAME_RE.fullmatch(model):
        raise SystemExit(
            "The presidio detector option 'model' must be an installed spaCy model package name, "
            "for example en_core_web_lg."
        )
    language = raw.get("language", DEFAULT_LANGUAGE)
    if not LANGUAGE_RE.fullmatch(language):
        raise SystemExit("The presidio detector option 'language' must be a language code such as en.")
    threshold = DEFAULT_THRESHOLD
    if "threshold" in raw:
        threshold = parse_float_option(raw["threshold"], detector=DETECTOR_NAME, key="threshold", minimum=0.0, maximum=1.0)
    include_dates = False
    if "include_dates" in raw:
        include_dates = parse_bool_option(raw["include_dates"], detector=DETECTOR_NAME, key="include_dates")
    mapping = dict(DEFAULT_ENTITY_CATEGORIES)
    overrides: dict[str, str] = {}
    if "map" in raw:
        overrides = parse_category_pairs(
            raw["map"],
            detector=DETECTOR_NAME,
            key="map",
            left_name="ENTITY_TYPE",
            normalize=_normalize_entity_type,
            echo_duplicates=True,
        )
        if DATE_ENTITY in overrides and not include_dates:
            raise SystemExit("The presidio detector option 'map' names DATE_TIME; also set include_dates=true.")
        mapping.update(overrides)
    if include_dates:
        mapping.setdefault(DATE_ENTITY, DATE_DEFAULT_CATEGORY)
    entities: tuple[str, ...] | None = None
    if "entities" in raw:
        names = [_entity_type(item, "entities") for item in raw["entities"].split("|")]
        if len(set(names)) != len(names):
            raise SystemExit("The presidio detector option 'entities' lists an entity type more than once.")
        if DATE_ENTITY in names and not include_dates:
            raise SystemExit("The presidio detector option 'entities' names DATE_TIME; also set include_dates=true.")
        unmapped = sorted(name for name in names if name not in mapping)
        if unmapped:
            raise SystemExit(
                "The presidio detector option 'entities' names types without a category mapping "
                f"({', '.join(unmapped)}); add them with map=ENTITY_TYPE:CATEGORY."
            )
        entities = tuple(names)
    return PresidioOptions(
        model=model,
        language=language,
        threshold=threshold,
        entities=entities,
        include_dates=include_dates,
        mapping=mapping,
        map_overrides=tuple(overrides),
    )


# Factory --------------------------------------------------------------------


class PresidioModules(NamedTuple):
    analyzer_engine: Any
    nlp_engine_provider: Any
    spacy_util: Any
    tldextract: Any


def _import_presidio() -> PresidioModules:
    """Import the optional libraries; isolated so tests can simulate absence."""

    try:
        import spacy.util
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ImportError:
        raise SystemExit(INSTALL_MESSAGE) from None
    try:
        import tldextract
    except ImportError:
        raise SystemExit(TLDEXTRACT_MESSAGE) from None
    return PresidioModules(AnalyzerEngine, NlpEngineProvider, spacy.util, tldextract)


def configure_offline_tldextract(tldextract: Any) -> None:
    """Make Presidio's email recognizer parse domains without network or disk.

    ``tldextract.extract`` (which Presidio calls) uses the module-level
    ``tldextract.tldextract.TLD_EXTRACTOR``. Its default fetches the Public
    Suffix List on first use and caches it under the home directory; the
    replacement uses only the snapshot bundled with tldextract. The change is
    process-wide, which is what the server wants anyway.
    """

    try:
        module = tldextract.tldextract
        if not hasattr(module, "TLD_EXTRACTOR"):
            raise AttributeError("TLD_EXTRACTOR")
        module.TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, fallback_to_snapshot=True)
    except Exception as exc:
        raise SystemExit(
            "The presidio detector could not configure tldextract for offline email parsing "
            f"({type(exc).__name__}); this tldextract version is not supported."
        ) from None


def model_version(spacy_util: Any, model: str) -> str:
    """Return the installed spaCy model package version, or ``unknown``."""

    try:
        version = spacy_util.get_package_version(model)
    except Exception:
        version = None
    return version.strip() if isinstance(version, str) and version.strip() else "unknown"


def factory(argument: str | None) -> PresidioDetector:
    """Build the Presidio detector once at startup from ``--detector presidio[=OPTIONS]``."""

    options = parse_presidio_options(argument)
    # Presidio moves spaCy to CUDA when an importable torch reports a GPU, and
    # GPU inference is not guaranteed to be deterministic. An operator's
    # explicit setting wins.
    os.environ.setdefault(DEVICE_ENV_VAR, "cpu")
    modules = _import_presidio()
    analyzer_engine_cls, provider_cls, spacy_util = modules.analyzer_engine, modules.nlp_engine_provider, modules.spacy_util
    configure_offline_tldextract(modules.tldextract)
    # Presidio's spaCy engine downloads missing models from the network; check
    # first so startup never fetches anything implicitly.
    if not spacy_util.is_package(options.model):
        raise SystemExit(
            f"The spaCy model '{options.model}' required by the presidio detector is not installed. "
            f"Install it with: python -m spacy download {options.model}"
        )
    # Presidio logs label-mapping notices at request time; keep them quiet.
    logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
    try:
        nlp_engine = provider_cls(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": options.language, "model_name": options.model}],
            }
        ).create_engine()
        analyzer = analyzer_engine_cls(nlp_engine=nlp_engine, supported_languages=[options.language])
        supported = set(analyzer.get_supported_entities(options.language))
    except Exception as exc:
        raise SystemExit(f"The presidio detector could not be initialized ({type(exc).__name__}).") from None
    if not supported:
        raise SystemExit(f"The presidio detector has no recognizers for language '{options.language}'.")
    requested = set(options.entities or ())
    unsupported = sorted(requested - supported)
    if unsupported:
        raise SystemExit(
            f"The presidio detector does not support these entity types for language "
            f"'{options.language}': {', '.join(unsupported)}."
        )
    unknown_overrides = sorted(set(options.map_overrides) - supported)
    if unknown_overrides:
        raise SystemExit(
            f"The presidio detector option 'map' names entity types that Presidio does not report for language "
            f"'{options.language}': {', '.join(unknown_overrides)}."
        )
    detector = PresidioDetector(
        analyzer,
        version=f"{installed_version()}/{options.model}-{model_version(spacy_util, options.model)}",
        language=options.language,
        threshold=options.threshold,
        entities=options.entities,
        include_dates=options.include_dates,
        mapping=options.mapping,
    )
    try:
        # Warm up once so the first request does not pay the model start-up
        # cost; the email and phone number exercise the pattern recognizers.
        detector.detect(WARM_UP_TEXT)
    except Exception as exc:
        raise SystemExit(f"The presidio detector failed its start-up check ({type(exc).__name__}).") from None
    return detector


__all__: Sequence[str] = (
    "DEFAULT_ENTITY_CATEGORIES",
    "PresidioDetector",
    "PresidioOptions",
    "chunk_windows",
    "configure_offline_tldextract",
    "factory",
    "parse_presidio_options",
)
