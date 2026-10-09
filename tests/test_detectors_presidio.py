"""Tests for the optional Presidio detector adapter.

Everything except ``RealPresidioTest`` uses a fake analyzer that mirrors the
verified ``presidio_analyzer`` result shape (objects with ``start``, ``end``,
``entity_type``, and ``score``; no ``text`` field; unsorted and overlapping).
The real-library test runs only with ``REDCTX_REAL_DETECTOR_TESTS=1`` and
``presidio_analyzer`` plus the ``en_core_web_sm`` spaCy model installed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Sequence
from unittest.mock import patch

from redacted_context_mcp import detectors, detectors_presidio
from redacted_context_mcp.defaults import PLACEHOLDER_CATEGORIES
from redacted_context_mcp.detectors import Detector, DetectorError, Span, load_detectors
from redacted_context_mcp.detectors_presidio import (
    DEFAULT_ENTITY_CATEGORIES,
    INSTALL_MESSAGE,
    TLDEXTRACT_MESSAGE,
    WARM_UP_TEXT,
    PresidioDetector,
    PresidioModules,
    chunk_windows,
    factory,
    parse_presidio_options,
)
from redacted_context_mcp.models import DETECTOR_FAILED_MESSAGE, RedactionConfig
from redacted_context_mcp.redaction import Redactor
from redacted_context_mcp.testing import DetectorConformance
from tests.fixtures import blocked_modules, spans_as_values
from tests.test_detectors import TEST_SALT


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LIBRARY_CANARY = "presidio-library-canary-text"
REAL_TESTS = os.environ.get("REDCTX_REAL_DETECTOR_TESTS") == "1"


class FakeRecognizerResult:
    """Mirror of ``presidio_analyzer.RecognizerResult``: no ``text`` attribute."""

    def __init__(self, entity_type: str, start: int, end: int, score: float) -> None:
        self.entity_type = entity_type
        self.start = start
        self.end = end
        self.score = score
        self.analysis_explanation = None
        self.recognition_metadata = {"recognizer_name": "FakeRecognizer"}


class FakeAnalyzer:
    """Find literal values and report them like Presidio would.

    ``values`` maps a literal string to ``(entity_type, score)``. Every exact
    occurrence becomes a result; results are returned in reverse order to
    mimic Presidio's unsorted output. ``calls`` records the exact strings
    analyzed and ``kwargs`` the other arguments.
    """

    def __init__(
        self,
        values: dict[str, tuple[str, float]] | None = None,
        *,
        extra: Sequence[FakeRecognizerResult] = (),
        error: BaseException | None = None,
        supported: Sequence[str] = tuple(DEFAULT_ENTITY_CATEGORIES) + ("DATE_TIME", "AGE"),
    ) -> None:
        self.values = dict(values or {})
        self.extra = tuple(extra)
        self.error = error
        self.supported = list(supported)
        self.calls: list[str] = []
        self.kwargs: list[dict[str, Any]] = []

    def analyze(self, text: str, language: str, entities: list[str] | None = None, **kwargs: Any) -> list[FakeRecognizerResult]:
        self.calls.append(text)
        self.kwargs.append({"language": language, "entities": entities, **kwargs})
        if self.error is not None:
            raise self.error
        results: list[FakeRecognizerResult] = list(self.extra)
        for value, (entity_type, score) in self.values.items():
            start = text.find(value)
            while start != -1:
                results.append(FakeRecognizerResult(entity_type, start, start + len(value), score))
                start = text.find(value, start + 1)
        if entities is not None:
            results = [result for result in results if result.entity_type in entities]
        return list(reversed(results))

    def get_supported_entities(self, language: str | None = None) -> list[str]:
        return list(self.supported)


# Option parsing -------------------------------------------------------------


class PresidioOptionsTest(unittest.TestCase):
    def assert_rejected(self, argument: str, fragment: str) -> str:
        with self.assertRaises(SystemExit) as caught:
            parse_presidio_options(argument)
        message = str(caught.exception)
        self.assertIn(fragment, message)
        return message

    def test_defaults(self) -> None:
        for argument in (None, "", " , "):
            with self.subTest(argument=argument):
                options = parse_presidio_options(argument)
                self.assertEqual(options.model, "en_core_web_lg")
                self.assertEqual(options.language, "en")
                self.assertEqual(options.threshold, 0.5)
                self.assertIsNone(options.entities)
                self.assertFalse(options.include_dates)
                self.assertEqual(dict(options.mapping), dict(DEFAULT_ENTITY_CATEGORIES))
                self.assertNotIn("DATE_TIME", options.mapping)

    def test_every_key(self) -> None:
        options = parse_presidio_options(
            " model = en_core_web_sm , language=en, threshold=0.75, entities=PERSON|US_SSN|DATE_TIME,"
            "include_dates=TRUE, map=PERSON:CLIENT|DATE_TIME:DOB|AGE:SENSITIVE"
        )
        self.assertEqual(options.model, "en_core_web_sm")
        self.assertEqual(options.language, "en")
        self.assertEqual(options.threshold, 0.75)
        self.assertEqual(options.entities, ("PERSON", "US_SSN", "DATE_TIME"))
        self.assertTrue(options.include_dates)
        self.assertEqual(options.mapping["PERSON"], "CLIENT")
        self.assertEqual(options.mapping["DATE_TIME"], "DOB")
        self.assertEqual(options.mapping["AGE"], "SENSITIVE")
        self.assertEqual(options.mapping["US_SSN"], "SSN")
        self.assertEqual(parse_presidio_options("include_dates=true").mapping["DATE_TIME"], "SENSITIVE")
        self.assertFalse(parse_presidio_options("include_dates=no").include_dates)
        self.assertEqual(parse_presidio_options("threshold=0").threshold, 0.0)
        self.assertEqual(parse_presidio_options("threshold=1").threshold, 1.0)

    def test_malformed_values(self) -> None:
        cases = {
            "threshold=high": "'threshold' must be a number from 0 to 1",
            "threshold=1.5": "'threshold' must be a number from 0 to 1",
            "threshold=-0.1": "'threshold' must be a number from 0 to 1",
            "threshold=nan": "'threshold' must be a number from 0 to 1",
            "threshold=": "'threshold' must be a number from 0 to 1",
            "include_dates=maybe": "'include_dates' must be true or false",
            "model=../private/model": "'model' must be an installed spaCy model package name",
            "model=": "'model' must be an installed spaCy model package name",
            "language=English!": "'language' must be a language code",
            "entities=person": "'entities' expects Presidio entity types",
            "entities=PERSON||US_SSN": "'entities' expects Presidio entity types",
            "entities=PERSON|PERSON": "lists an entity type more than once",
            "entities=AGE": "without a category mapping (AGE)",
            "entities=DATE_TIME": "also set include_dates=true",
            "map=PERSON": "expects ENTITY_TYPE:CATEGORY pairs",
            "map=PERSON:HUMAN": "must use canonical categories",
            "map=person:PERSON": "'map' expects ENTITY_TYPE:CATEGORY pairs",
            "map=:PERSON": "'map' expects ENTITY_TYPE:CATEGORY pairs",
            "map=PERSON:ORG|PERSON:CLIENT": "names PERSON more than once",
            "map=DATE_TIME:DOB": "also set include_dates=true",
        }
        for argument, fragment in cases.items():
            with self.subTest(argument=argument):
                self.assert_rejected(argument, fragment)

    def test_unknown_duplicate_and_malformed_items(self) -> None:
        message = self.assert_rejected("modle=en_core_web_sm", "Unknown presidio detector option 'modle'")
        self.assertIn("include_dates", message)
        self.assert_rejected("threshold=0.4,threshold=0.6", "'threshold' was given more than once")
        secret = "C:/Users/someone/secret-notes.txt"
        message = self.assert_rejected(secret, "expected comma-separated key=value pairs")
        self.assertNotIn("secret-notes", message)
        message = self.assert_rejected(f"Bad Key={secret}", "expected comma-separated key=value pairs")
        self.assertNotIn("secret-notes", message)


# Detection behaviour --------------------------------------------------------


class PresidioMappingTest(unittest.TestCase):
    def test_default_mapping_targets_are_canonical(self) -> None:
        self.assertTrue(set(DEFAULT_ENTITY_CATEGORIES.values()) <= PLACEHOLDER_CATEGORIES)
        expected = {
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
        self.assertEqual(dict(DEFAULT_ENTITY_CATEGORIES), expected)

    def test_every_default_type_maps_and_unmapped_types_are_skipped(self) -> None:
        values = {f"value{index:02d}": (entity_type, 0.9) for index, entity_type in enumerate(DEFAULT_ENTITY_CATEGORIES)}
        values["agevalue"] = ("AGE", 0.9)
        values["datevalue"] = ("DATE_TIME", 0.9)
        values["oddvalue"] = ("SOMETHING_NEW", 0.9)
        text = " ".join(values)
        found = dict(spans_as_values(text, PresidioDetector(FakeAnalyzer(values), version="t").detect(text)))
        for value, (entity_type, _score) in values.items():
            if entity_type in DEFAULT_ENTITY_CATEGORIES:
                self.assertEqual(found.pop(value), DEFAULT_ENTITY_CATEGORIES[entity_type])
        self.assertEqual(found, {})

    def test_dates_only_with_include_dates_and_overrides_apply(self) -> None:
        analyzer = FakeAnalyzer({"Avery Lindqvist": ("PERSON", 0.85), "2026-03-14": ("DATE_TIME", 0.85)})
        text = "Avery Lindqvist on 2026-03-14"
        self.assertEqual(
            spans_as_values(text, PresidioDetector(analyzer, version="t").detect(text)),
            [("Avery Lindqvist", "PERSON")],
        )
        with_dates = PresidioDetector(analyzer, version="t", include_dates=True)
        self.assertEqual(
            spans_as_values(text, with_dates.detect(text)),
            [("Avery Lindqvist", "PERSON"), ("2026-03-14", "SENSITIVE")],
        )
        options = parse_presidio_options("include_dates=true,map=DATE_TIME:DOB|PERSON:CLIENT")
        overridden = PresidioDetector(analyzer, version="t", include_dates=True, mapping=options.mapping)
        self.assertEqual(
            spans_as_values(text, overridden.detect(text)),
            [("Avery Lindqvist", "CLIENT"), ("2026-03-14", "DOB")],
        )

    def test_non_canonical_mapping_is_rejected_at_construction(self) -> None:
        with self.assertRaises(ValueError):
            PresidioDetector(FakeAnalyzer(), version="t", mapping={"PERSON": "HUMAN"})

    def test_entities_allowlist_is_passed_and_enforced(self) -> None:
        analyzer = FakeAnalyzer(
            {"Avery": ("PERSON", 0.85)},
            extra=[FakeRecognizerResult("US_SSN", 0, 3, 0.85), FakeRecognizerResult("PERSON", 4, 9, 0.85)],
        )
        detector = PresidioDetector(analyzer, version="t", entities=("PERSON",))
        text = "536 Avery"
        self.assertEqual(spans_as_values(text, detector.detect(text)), [("Avery", "PERSON")])
        self.assertEqual(analyzer.kwargs[-1]["entities"], ["PERSON"])
        self.assertEqual(analyzer.kwargs[-1]["language"], "en")

    def test_threshold_filters_scores(self) -> None:
        values = {"alpha": ("PERSON", 0.49), "bravo": ("PERSON", 0.5), "charlie": ("PERSON", 0.85)}
        text = "alpha bravo charlie"
        self.assertEqual(
            [value for value, _ in spans_as_values(text, PresidioDetector(FakeAnalyzer(values), version="t").detect(text))],
            ["bravo", "charlie"],
        )
        strict = PresidioDetector(FakeAnalyzer(values), version="t", threshold=0.9)
        self.assertEqual(strict.detect(text), [])
        lenient = PresidioDetector(FakeAnalyzer(values), version="t", threshold=0.0)
        self.assertEqual(len(lenient.detect(text)), 3)

    def test_identical_and_same_category_nested_spans_resolve_to_the_containing_one(self) -> None:
        # Verified Presidio behaviour: an email also yields URL fragments, and
        # en_core_web_sm may label the same email ORGANIZATION.
        text = "Contact Avery Lindqvist at avery.lindqvist@example.com today"
        email_start = text.index("avery.lindqvist@")
        analyzer = FakeAnalyzer(
            extra=[
                FakeRecognizerResult("URL", email_start, email_start + 8, 0.5),
                FakeRecognizerResult("EMAIL_ADDRESS", email_start, email_start + 27, 1.0),
                FakeRecognizerResult("ORGANIZATION", email_start, email_start + 27, 0.85),
                FakeRecognizerResult("URL", email_start + 16, email_start + 27, 0.5),
                FakeRecognizerResult("PERSON", 8, 23, 0.85),
                FakeRecognizerResult("PERSON", 8, 13, 0.6),  # "Avery" inside the same-category name
            ]
        )
        spans = PresidioDetector(analyzer, version="t").detect(text)
        # The identical ORGANIZATION range loses to the higher-scoring email,
        # and the PERSON fragment collapses into the full name; the URL
        # fragments have another category and are kept, so other occurrences
        # of the domain are redacted too.
        self.assertEqual(
            spans_as_values(text, spans),
            [
                ("Avery Lindqvist", "PERSON"),
                ("avery.lindqvist@example.com", "EMAIL"),
                ("avery.li", "URL"),
                ("example.com", "URL"),
            ],
        )

    def test_inner_person_inside_an_organization_span_is_redacted_everywhere(self) -> None:
        text = "Lantern Labs CEO Avery Lindqvist signed.\nLater, avery lindqvist (lowercase, in a code comment) approved.\n"
        outer = text.index("Lantern")
        inner = text.index("Avery")
        analyzer = FakeAnalyzer(
            extra=[
                FakeRecognizerResult("ORGANIZATION", outer, inner + len("Avery Lindqvist"), 0.85),
                FakeRecognizerResult("PERSON", inner, inner + len("Avery Lindqvist"), 0.85),
            ]
        )
        detector = PresidioDetector(analyzer, version="t")
        self.assertEqual(
            spans_as_values(text, detector.detect(text)),
            [("Lantern Labs CEO Avery Lindqvist", "ORG"), ("Avery Lindqvist", "PERSON")],
        )
        output = Redactor(RedactionConfig(salt=TEST_SALT), detectors=(detector,)).redact(text)
        self.assertNotIn("lindqvist", output.lower())
        self.assertIn("[PERSON_", output)

    def test_inner_organization_inside_a_person_span_is_redacted_everywhere(self) -> None:
        text = "Signed: Avery Lindqvist of Lantern Labs.\nlantern labs approved.\n"
        outer = text.index("Avery")
        inner = text.index("Lantern")
        analyzer = FakeAnalyzer(
            extra=[
                FakeRecognizerResult("PERSON", outer, inner + 12, 0.85),
                FakeRecognizerResult("ORGANIZATION", inner, inner + 12, 0.85),
            ]
        )
        detector = PresidioDetector(analyzer, version="t")
        output = Redactor(RedactionConfig(salt=TEST_SALT), detectors=(detector,)).redact(text)
        self.assertNotIn("lantern labs", output.lower())
        self.assertIn("[ORG_", output)

    def test_out_of_range_results_fail_and_engine_hides_details(self) -> None:
        analyzer = FakeAnalyzer(extra=[FakeRecognizerResult("PERSON", 0, 999, 0.9)])
        with self.assertRaises(ValueError):
            PresidioDetector(analyzer, version="t").detect("short")
        failing = PresidioDetector(FakeAnalyzer(error=RuntimeError(LIBRARY_CANARY)), version="t")
        redactor = Redactor(RedactionConfig(salt=TEST_SALT), detectors=(failing,))
        with self.assertRaises(DetectorError) as caught:
            redactor.redact("Avery Lindqvist")
        self.assertEqual(str(caught.exception), DETECTOR_FAILED_MESSAGE)
        self.assertNotIn(LIBRARY_CANARY, str(caught.exception))

    def test_engine_redacts_nominated_values(self) -> None:
        detector = PresidioDetector(FakeAnalyzer({"Quillfeather Ostrander": ("PERSON", 0.85)}), version="2.2.364")
        redactor = Redactor(RedactionConfig(salt=TEST_SALT), detectors=(detector,))
        output = redactor.redact("Quillfeather Ostrander met quillfeather  ostrander.\n")
        self.assertNotIn("Quillfeather", output)
        self.assertNotIn("quillfeather", output)
        self.assertIn("[PERSON_", output)
        self.assertEqual(redactor.receipt()["detectors"][0]["name"], "presidio")
        self.assertEqual(redactor.receipt()["detectors"][0]["version"], "2.2.364")


class PresidioChunkingTest(unittest.TestCase):
    def test_short_text_is_a_single_window(self) -> None:
        self.assertEqual(chunk_windows("abc", 10, 2), [(0, 3)])
        self.assertEqual(chunk_windows("", 10, 2), [(0, 0)])

    def test_windows_prefer_paragraph_then_line_breaks(self) -> None:
        text = "a" * 30 + "\n" + "b" * 10 + "\n\n" + "c" * 30
        windows = chunk_windows(text, 60, 0)
        self.assertEqual(windows[0], (0, 43))  # just after the blank line
        self.assertEqual(text[windows[0][0] : windows[0][1]][-2:], "\n\n")
        text = "a" * 40 + "\n" + "b" * 40
        self.assertEqual(chunk_windows(text, 60, 0)[0], (0, 41))
        # Without any whitespace the cut is hard and the overlap still applies.
        self.assertEqual(chunk_windows("x" * 200, 60, 10), [(0, 60), (50, 110), (100, 160), (150, 200)])

    def test_windows_cover_text_and_respect_size(self) -> None:
        text = "".join(f"word{index} " + ("\n" if index % 7 == 0 else "") for index in range(400))
        windows = chunk_windows(text, 120, 30)
        self.assertEqual(windows[0][0], 0)
        self.assertEqual(windows[-1][1], len(text))
        for (start, end), (next_start, _next_end) in zip(windows, windows[1:]):
            self.assertLessEqual(end - start, 120)
            self.assertLess(start, next_start)
            self.assertLessEqual(next_start, end)  # contiguous or overlapping, never a gap

    def test_offsets_shift_back_and_straddling_value_is_found_via_overlap(self) -> None:
        filler = "".join(f"w{index:03d} " for index in range(35))
        text = f"Avery Lindqvist starts here. {filler}Quentin Marlowe-Ash {filler}{filler}Lantern Labs ends."
        max_chars, overlap = 220, 60
        windows = chunk_windows(text, max_chars, overlap)
        self.assertGreater(len(windows), 1)
        target = text.index("Quentin Marlowe-Ash")
        target_end = target + len("Quentin Marlowe-Ash")
        # Precondition: the value straddles the first cut.
        self.assertLess(target, windows[0][1])
        self.assertGreater(target_end, windows[0][1])
        analyzer = FakeAnalyzer(
            {
                "Avery Lindqvist": ("PERSON", 0.85),
                "Quentin Marlowe-Ash": ("PERSON", 0.85),
                "Quentin": ("PERSON", 0.85),  # the truncated fragment seen in the first window
                "Lantern Labs": ("ORGANIZATION", 0.85),
            }
        )
        detector = PresidioDetector(analyzer, version="t", max_chunk_chars=max_chars, chunk_overlap_chars=overlap)
        spans = detector.detect(text)
        self.assertEqual(analyzer.calls, [text[start:end] for start, end in windows])
        self.assertEqual(
            spans_as_values(text, spans),
            [("Avery Lindqvist", "PERSON"), ("Quentin Marlowe-Ash", "PERSON"), ("Lantern Labs", "ORG")],
        )
        self.assertEqual([(span.start, span.end) for span in spans][1], (target, target_end))

    def test_invalid_chunk_configuration_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PresidioDetector(FakeAnalyzer(), version="t", max_chunk_chars=100, chunk_overlap_chars=50)


class PresidioLockTest(unittest.TestCase):
    def test_calls_are_serialized_with_a_lock(self) -> None:
        detector = PresidioDetector(FakeAnalyzer(), version="t")
        self.assertIsInstance(detector._lock, type(threading.Lock()))

        class ConcurrencyProbe(FakeAnalyzer):
            active = 0
            peak = 0

            def analyze(self, text: str, language: str, entities: list[str] | None = None, **kwargs: Any) -> list[FakeRecognizerResult]:
                type(self).active += 1
                type(self).peak = max(type(self).peak, type(self).active)
                time.sleep(0.01)
                type(self).active -= 1
                return []

        detector = PresidioDetector(ConcurrencyProbe(), version="t")
        threads = [threading.Thread(target=detector.detect, args=("Avery Lindqvist",)) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(ConcurrencyProbe.peak, 1)


class PresidioConformanceTest(DetectorConformance, unittest.TestCase):
    def make_detector(self) -> Detector:
        return PresidioDetector(
            FakeAnalyzer(
                {
                    "quillfeather": ("PERSON", 0.85),
                    "Zorblax": ("ORGANIZATION", 0.85),
                    "TICKET-12345": ("US_BANK_NUMBER", 0.4),
                    "árvíz": ("LOCATION", 0.85),
                    "PERSON_0123": ("PERSON", 0.85),
                }
            ),
            version="test",
        )

    def positive_texts(self) -> Sequence[str]:
        return ("quillfeather met Zorblax\n", "Árvíz near árvíz\r\n")


# Factory --------------------------------------------------------------------


class FakeSpacyUtil:
    def __init__(self, installed: Sequence[str], version: str | None = "3.8.0") -> None:
        self.installed = set(installed)
        self.version = version

    def is_package(self, name: str) -> bool:
        return name in self.installed

    def get_package_version(self, name: str) -> str | None:
        return self.version if name in self.installed else None


class FakeTldextract:
    """Stands in for the ``tldextract`` package: records extractor construction."""

    DEFAULT = "default-extractor-that-downloads"

    def __init__(self) -> None:
        self.tldextract = SimpleNamespace(TLD_EXTRACTOR=self.DEFAULT)
        self.created: list[dict[str, Any]] = []

    def TLDExtract(self, **kwargs: Any) -> tuple[str, dict[str, Any]]:  # noqa: N802 - mirrors the library
        self.created.append(kwargs)
        return ("offline-extractor", kwargs)


class FakePresidio(SimpleNamespace):
    modules: PresidioModules
    record: dict[str, Any]
    tldextract: FakeTldextract


def fake_presidio_modules(
    *,
    installed: Sequence[str] = ("en_core_web_lg", "en_core_web_sm"),
    analyzer: FakeAnalyzer | None = None,
    error: BaseException | None = None,
) -> FakePresidio:
    record: dict[str, Any] = {}
    shared = analyzer or FakeAnalyzer({"Avery Lindqvist": ("PERSON", 0.85)})

    class FakeProvider:
        def __init__(self, nlp_configuration: dict[str, Any]) -> None:
            record["nlp_configuration"] = nlp_configuration

        def create_engine(self) -> str:
            if error is not None:
                raise error
            return "nlp-engine"

    class FakeAnalyzerEngine:
        def __new__(cls, nlp_engine: Any, supported_languages: list[str]) -> FakeAnalyzer:  # type: ignore[misc]
            record["nlp_engine"] = nlp_engine
            record["supported_languages"] = supported_languages
            return shared

    tld = FakeTldextract()
    modules = PresidioModules(FakeAnalyzerEngine, FakeProvider, FakeSpacyUtil(installed), tld)
    return FakePresidio(modules=modules, record=record, tldextract=tld)


class PresidioFactoryTest(unittest.TestCase):
    def test_missing_library_gives_install_message(self) -> None:
        blocked = ("presidio_analyzer", "presidio_analyzer.nlp_engine")
        with blocked_modules(*blocked):
            with self.assertRaises(SystemExit) as caught:
                factory("model=en_core_web_sm")
        self.assertEqual(str(caught.exception), INSTALL_MESSAGE)
        self.assertIn('pip install "redacted-context-mcp[presidio]"', str(caught.exception))
        with blocked_modules(*blocked):
            with patch.object(detectors.metadata, "entry_points", return_value=[]):
                with self.assertRaisesRegex(SystemExit, r"redacted-context-mcp\[presidio\]"):
                    load_detectors(["presidio"])

    def test_options_are_validated_before_importing(self) -> None:
        with patch.object(detectors_presidio, "_import_presidio") as importer:
            with self.assertRaisesRegex(SystemExit, "Unknown presidio detector option"):
                factory("nope=1")
        importer.assert_not_called()

    def test_missing_spacy_model_is_never_downloaded(self) -> None:
        modules = fake_presidio_modules(installed=("en_core_web_sm",))
        with patch.object(detectors_presidio, "_import_presidio", return_value=modules.modules):
            with self.assertRaises(SystemExit) as caught:
                factory(None)
        self.assertIn("python -m spacy download en_core_web_lg", str(caught.exception))
        self.assertNotIn("nlp_configuration", modules.record)

    def test_factory_builds_a_configured_detector(self) -> None:
        analyzer = FakeAnalyzer({"Avery Lindqvist": ("PERSON", 0.85), "536-22-1987": ("US_SSN", 0.85)})
        modules = fake_presidio_modules(analyzer=analyzer)
        with patch.object(detectors_presidio, "_import_presidio", return_value=modules.modules):
            with patch.object(detectors_presidio, "installed_version", return_value="2.2.364"):
                detector = factory("model=en_core_web_sm,threshold=0.6,entities=PERSON|US_SSN")
        record = modules.record
        self.assertEqual(
            record["nlp_configuration"],
            {"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]},
        )
        self.assertEqual(record["supported_languages"], ["en"])
        self.assertIsInstance(detector, PresidioDetector)
        self.assertEqual(detector.name, "presidio")
        # Public package names only: presidio-analyzer version, spaCy model package and version.
        self.assertEqual(detector.version, "2.2.364/en_core_web_sm-3.8.0")
        self.assertEqual(detector.threshold, 0.6)
        self.assertEqual(detector.entities, ("PERSON", "US_SSN"))
        self.assertEqual(analyzer.calls, [WARM_UP_TEXT], "factory warms the analyzer up once")
        text = "Avery Lindqvist has SSN 536-22-1987."
        self.assertEqual(
            spans_as_values(text, detector.detect(text)),
            [("Avery Lindqvist", "PERSON"), ("536-22-1987", "SSN")],
        )

    def test_factory_rejects_unsupported_entities_and_hides_init_errors(self) -> None:
        modules = fake_presidio_modules(analyzer=FakeAnalyzer(supported=("PERSON",)))
        with patch.object(detectors_presidio, "_import_presidio", return_value=modules.modules):
            with self.assertRaisesRegex(SystemExit, "does not support these entity types for language 'en': US_SSN"):
                factory("entities=PERSON|US_SSN")
        modules = fake_presidio_modules(error=RuntimeError(LIBRARY_CANARY))
        with patch.object(detectors_presidio, "_import_presidio", return_value=modules.modules):
            with self.assertRaises(SystemExit) as caught:
                factory(None)
        self.assertIn("could not be initialized (RuntimeError)", str(caught.exception))
        self.assertNotIn(LIBRARY_CANARY, str(caught.exception))
        modules = fake_presidio_modules(analyzer=FakeAnalyzer(supported=()))
        with patch.object(detectors_presidio, "_import_presidio", return_value=modules.modules):
            with self.assertRaisesRegex(SystemExit, "no recognizers for language 'en'"):
                factory(None)

    def test_factory_configures_tldextract_to_stay_offline_and_off_disk(self) -> None:
        modules = fake_presidio_modules()
        self.assertEqual(modules.tldextract.tldextract.TLD_EXTRACTOR, FakeTldextract.DEFAULT)
        with patch.object(detectors_presidio, "_import_presidio", return_value=modules.modules):
            factory("model=en_core_web_sm")
        self.assertEqual(
            modules.tldextract.created,
            [{"suffix_list_urls": (), "cache_dir": None, "fallback_to_snapshot": True}],
        )
        self.assertEqual(modules.tldextract.tldextract.TLD_EXTRACTOR, ("offline-extractor", modules.tldextract.created[0]))
        # The start-up check exercises the email and phone recognizers, so the
        # extractor is in use before the first request.
        self.assertIn("@example.com", WARM_UP_TEXT)
        self.assertRegex(WARM_UP_TEXT, r"\+1 \d{3} \d{3} \d{4}")

    def test_unsupported_tldextract_is_a_startup_error(self) -> None:
        modules = fake_presidio_modules()
        broken = modules.modules._replace(tldextract=SimpleNamespace(tldextract=SimpleNamespace()))
        with patch.object(detectors_presidio, "_import_presidio", return_value=broken):
            with self.assertRaisesRegex(SystemExit, r"could not configure tldextract for offline email parsing \(AttributeError\)"):
                factory("model=en_core_web_sm")
        self.assertNotIn("nlp_configuration", modules.record)

    def test_missing_tldextract_is_a_startup_error(self) -> None:
        spacy = types.ModuleType("spacy")
        spacy_util = types.ModuleType("spacy.util")
        spacy.util = spacy_util  # type: ignore[attr-defined]
        presidio = types.ModuleType("presidio_analyzer")
        presidio.AnalyzerEngine = object  # type: ignore[attr-defined]
        nlp_engine = types.ModuleType("presidio_analyzer.nlp_engine")
        nlp_engine.NlpEngineProvider = object  # type: ignore[attr-defined]
        fakes = {
            "spacy": spacy,
            "spacy.util": spacy_util,
            "presidio_analyzer": presidio,
            "presidio_analyzer.nlp_engine": nlp_engine,
            "tldextract": None,
        }
        with patch.dict(sys.modules, fakes):
            with self.assertRaises(SystemExit) as caught:
                factory("model=en_core_web_sm")
        self.assertEqual(str(caught.exception), TLDEXTRACT_MESSAGE)

    def test_spacy_is_pinned_to_the_cpu_unless_the_operator_chose(self) -> None:
        seen: list[str | None] = []

        def importer() -> PresidioModules:
            seen.append(os.environ.get("PRESIDIO_DEVICE"))
            return fake_presidio_modules().modules

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PRESIDIO_DEVICE", None)
            with patch.object(detectors_presidio, "_import_presidio", side_effect=importer):
                factory("model=en_core_web_sm")
            self.assertEqual(os.environ.get("PRESIDIO_DEVICE"), "cpu")
        with patch.dict(os.environ, {"PRESIDIO_DEVICE": "cuda:1"}):
            with patch.object(detectors_presidio, "_import_presidio", side_effect=importer):
                factory("model=en_core_web_sm")
            self.assertEqual(os.environ.get("PRESIDIO_DEVICE"), "cuda:1")
        # Set before Presidio is imported, so its device detector sees it.
        self.assertEqual(seen, ["cpu", "cuda:1"])

    def test_map_keys_must_be_supported_entity_types(self) -> None:
        modules = fake_presidio_modules()
        with patch.object(detectors_presidio, "_import_presidio", return_value=modules.modules):
            with self.assertRaisesRegex(
                SystemExit, r"option 'map' names entity types that Presidio does not report for language 'en': ORGANISATION\."
            ):
                factory("map=ORGANISATION:CLIENT")
            detector = factory("map=ORGANIZATION:CLIENT|AGE:SENSITIVE")
        self.assertEqual(detector.mapping["ORGANIZATION"], "CLIENT")

    def test_unknown_model_version_is_reported_as_unknown(self) -> None:
        modules = fake_presidio_modules()
        modules.modules.spacy_util.version = None
        with patch.object(detectors_presidio, "_import_presidio", return_value=modules.modules):
            with patch.object(detectors_presidio, "installed_version", return_value="2.2.364"):
                self.assertEqual(factory("model=en_core_web_sm").version, "2.2.364/en_core_web_sm-unknown")

    def test_load_detectors_resolves_the_lazy_builtin(self) -> None:
        modules = fake_presidio_modules()
        with patch.object(detectors_presidio, "_import_presidio", return_value=modules.modules):
            with patch.object(detectors.metadata, "entry_points", return_value=[]):
                loaded = load_detectors(["presidio=model=en_core_web_sm"])
                self.assertIn("presidio", detectors.available_detector_names())
        self.assertEqual([detector.name for detector in loaded], ["presidio"])

    def test_packaging_declares_extra_and_no_redundant_entry_point(self) -> None:
        data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = data["project"]
        self.assertEqual(project["dependencies"], [])
        self.assertEqual(project["optional-dependencies"]["presidio"], ["presidio-analyzer>=2.2,<3"])
        # Built-ins always win over entry points, so registering one would be unreachable.
        group = project.get("entry-points", {}).get("redacted_context_mcp.detectors", {})
        self.assertNotIn("presidio", group)
        self.assertIn("presidio", detectors.BUILTIN_DETECTORS)


# Real library (opt-in) ------------------------------------------------------


def presidio_available() -> bool:
    try:
        return importlib.util.find_spec("presidio_analyzer") is not None
    except (ImportError, ValueError):
        return False


@unittest.skipUnless(
    REAL_TESTS and presidio_available(),
    "set REDCTX_REAL_DETECTOR_TESTS=1 with presidio-analyzer and en_core_web_sm installed",
)
class RealPresidioTest(unittest.TestCase):
    detector: PresidioDetector

    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.detector = factory("model=en_core_web_sm")
        except SystemExit as exc:  # report as an error instead of ending the run
            raise RuntimeError(str(exc)) from None

    def test_probe_sentence(self) -> None:
        text = (
            "Contact Avery Lindqvist at avery.lindqvist@example.com or +1 415 555 0133 "
            "about the Lantern Labs rollout on 2026-03-14. Her SSN is 536-22-1987 and "
            "the server is 10.0.0.12."
        )
        found = spans_as_values(text, self.detector.detect(text))
        self.assertIn(("Avery Lindqvist", "PERSON"), found)
        self.assertIn(("avery.lindqvist@example.com", "EMAIL"), found)
        self.assertIn(("536-22-1987", "SSN"), found)
        self.assertNotIn("2026-03-14", [value for value, _ in found])  # dates are opt-in
        # The email is one EMAIL value; no second EMAIL value nests inside it.
        self.assertEqual([value for value, category in found if category == "EMAIL"], ["avery.lindqvist@example.com"])
        self.assertEqual(found, spans_as_values(text, self.detector.detect(text)))

    def test_version_names_public_packages(self) -> None:
        self.assertRegex(self.detector.version, r"^\d+\.\d+\.\d+/en_core_web_sm-\d+\.\d+\.\d+$")

    def test_offline_tldextract_is_installed(self) -> None:
        import tldextract.tldextract

        extractor = tldextract.tldextract.TLD_EXTRACTOR
        self.assertEqual(extractor.suffix_list_urls, ())
        self.assertTrue(extractor.fallback_to_snapshot)

    def test_email_detection_never_touches_the_network_or_the_home_directory(self) -> None:
        # A fresh process with HOME, USERPROFILE, and the XDG cache redirected
        # to an empty directory (tldextract reads them when it is imported).
        # Outbound name lookups and connections raise from start-up on (urllib3
        # opens a loopback IPv6 socket at import time, which is not network
        # access), and creating any socket raises during detection.
        script = r"""
import json, socket
from redacted_context_mcp import detectors_presidio
attempts = []
def refuse(*args, **kwargs):
    attempts.append("lookup or connect")
    raise OSError("network disabled by test")
socket.getaddrinfo = refuse
socket.create_connection = refuse
socket.socket.connect = refuse
socket.socket.connect_ex = refuse
detector = detectors_presidio.factory("model=en_core_web_sm")
class RefusingSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        attempts.append("socket during detect")
        raise OSError("network disabled by test")
socket.socket = RefusingSocket
text = "Write to avery.lindqvist@example.com or a.b@foo.co.uk today, said Avery Lindqvist."
spans = [[text[span.start:span.end], span.category] for span in detector.detect(text)]
print(json.dumps({"spans": spans, "attempts": attempts}))
"""
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ)
            env.update(
                {
                    "HOME": home,
                    "USERPROFILE": home,
                    "XDG_CACHE_HOME": str(Path(home) / ".cache"),
                    "PYTHONPATH": str(PROJECT_ROOT / "src"),
                }
            )
            env.pop("TLDEXTRACT_CACHE", None)
            result = subprocess.run(
                [sys.executable, "-X", "utf8", "-c", script],
                cwd=PROJECT_ROOT,
                env=env,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=300,
                check=False,
            )
            written = sorted(str(path.relative_to(home)) for path in Path(home).rglob("*"))
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        report = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(report["attempts"], [])
        self.assertIn(["avery.lindqvist@example.com", "EMAIL"], report["spans"])
        self.assertIn(["a.b@foo.co.uk", "EMAIL"], report["spans"])
        self.assertEqual(written, [])
        self.assertNotIn("Traceback", result.stderr)

    def test_ssn_allowlist_path(self) -> None:
        detector = factory("model=en_core_web_sm,entities=US_SSN")
        text = "Her SSN is 536-22-1987."
        self.assertEqual(spans_as_values(text, detector.detect(text)), [("536-22-1987", "SSN")])

    def test_conformance_against_the_real_engine(self) -> None:
        detector = self.detector

        class RealConformance(DetectorConformance, unittest.TestCase):
            def make_detector(self) -> Detector:
                return detector

            def positive_texts(self) -> Sequence[str]:
                return ("Avery Lindqvist wrote to avery.lindqvist@example.com.\n",)

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(RealConformance).run(result)
        self.assertTrue(result.wasSuccessful(), result.failures + result.errors)


if __name__ == "__main__":
    unittest.main()
