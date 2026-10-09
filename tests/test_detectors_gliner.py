"""Tests for the optional GLiNER detector adapter.

Everything except ``RealGlinerTest`` uses a fake model that mirrors the
verified ``GLiNER.predict_entities`` shape (a list of dicts with exactly
``start``, ``end``, ``text``, ``label``, and ``score``; labels echoed exactly
as passed; input silently cut after ``max_len`` words or once the label prompt
plus the text reach the encoder's 512 subword tokens) and a fake tokenizer
that counts one token per four characters. The real-library test runs only
with ``REDCTX_REAL_DETECTOR_TESTS=1`` and ``gliner`` installed, and loads
``urchade/gliner_small-v2.1`` from the local cache (``offline=true``).
"""

from __future__ import annotations

import base64
import importlib.util
import os
import tempfile
import threading
import time
import tomllib
import unicodedata
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Sequence
from unittest.mock import patch

from redacted_context_mcp import detectors, detectors_gliner
from redacted_context_mcp.defaults import PLACEHOLDER_CATEGORIES
from redacted_context_mcp.detectors import Detector, DetectorError, Span, load_detectors
from redacted_context_mcp.detectors_gliner import (
    DEFAULT_LABEL_CATEGORIES,
    GLINER_WORD_RE,
    INSTALL_MESSAGE,
    LONG_WORD_CHARS,
    GlinerDetector,
    factory,
    make_token_counter,
    model_label,
    model_token_limit,
    parse_gliner_options,
    window_units,
    word_windows,
)
from redacted_context_mcp.models import DETECTOR_FAILED_MESSAGE, RedactionConfig
from redacted_context_mcp.redaction import Redactor
from redacted_context_mcp.testing import DetectorConformance
from tests.fixtures import blocked_modules, spans_as_values
from tests.test_detectors import TEST_SALT


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LIBRARY_CANARY = "gliner-library-canary-text"
REAL_TESTS = os.environ.get("REDCTX_REAL_DETECTOR_TESTS") == "1"
SAMPLE = (
    "Contact Avery Lindqvist at avery.lindqvist@example.com or +1 415 555 0133 "
    "about the Lantern Labs rollout on 2026-03-14."
)


class FakeEncoding(dict):
    """Mirror of a ``transformers`` ``BatchEncoding`` for one sequence."""

    def __init__(self, input_ids: list[int], word_ids: list[int | None]) -> None:
        super().__init__(input_ids=input_ids)
        self._word_ids = word_ids

    def word_ids(self) -> list[int | None]:
        return list(self._word_ids)


def fake_token_count(word: str) -> int:
    return max(1, -(-len(word) // 4))


class FakeTokenizer:
    """A subword tokenizer stand-in: one token per four characters of each word.

    Like GLiNER's DeBERTa tokenizer with ``is_split_into_words=True``, every
    word is tokenized on its own and ``[CLS]``/``[SEP]`` are added unless
    ``add_special_tokens=False``.
    """

    def __call__(self, words: Sequence[str], is_split_into_words: bool = False, add_special_tokens: bool = True, **kwargs: Any) -> FakeEncoding:
        assert is_split_into_words
        ids: list[int] = [1] if add_special_tokens else []
        word_ids: list[int | None] = [None] if add_special_tokens else []
        for index, word in enumerate(words):
            for _ in range(fake_token_count(word)):
                ids.append(5)
                word_ids.append(index)
        if add_special_tokens:
            ids.append(2)
            word_ids.append(None)
        return FakeEncoding(ids, word_ids)


FAKE_ENT, FAKE_SEP = "<<ENT>>", "<<SEP>>"


def fake_prompt_tokens(labels: Sequence[str]) -> int:
    return 2 + sum(fake_token_count(FAKE_ENT) + fake_token_count(label) for label in labels) + fake_token_count(FAKE_SEP)


def fake_window_tokens(text: str, labels: Sequence[str]) -> int:
    """Tokens the fake model sees for ``text``: prompt, specials, and words."""

    return fake_prompt_tokens(labels) + sum(fake_token_count(word) for word in GLINER_WORD_RE.findall(text))


class FakeGlinerModel:
    """Find literal values and report them like ``GLiNER.predict_entities``.

    ``values`` maps a literal string to ``(label, score)``. A value is only
    reported when its label was requested (compared exactly, as GLiNER does).
    Like the real model, text beyond ``max_len`` words, or beyond
    ``token_limit`` subword tokens including the label prompt, is silently
    ignored. ``calls`` records the exact strings and ``label_calls`` the label
    lists.
    """

    def __init__(
        self,
        values: dict[str, tuple[str, float]] | None = None,
        *,
        max_len: int = 384,
        token_limit: int = 512,
        honor_threshold: bool = True,
        extra: Sequence[dict[str, Any]] = (),
        error: BaseException | None = None,
        splitter: str | None = "whitespace",
        tokenizer: Any = "default",
    ) -> None:
        self.values = dict(values or {})
        self.config = SimpleNamespace(
            max_len=max_len,
            words_splitter_type=splitter,
            encoder_config=SimpleNamespace(max_position_embeddings=token_limit),
        )
        self.token_limit = token_limit
        self.data_processor = SimpleNamespace(
            transformer_tokenizer=FakeTokenizer() if tokenizer == "default" else tokenizer,
            ent_token=FAKE_ENT,
            sep_token=FAKE_SEP,
        )
        self.honor_threshold = honor_threshold
        self.extra = list(extra)
        self.error = error
        self.calls: list[str] = []
        self.label_calls: list[list[str]] = []
        self.thresholds: list[float] = []

    def predict_entities(
        self,
        text: str,
        labels: list[str],
        flat_ner: bool = True,
        threshold: float = 0.5,
        multi_label: bool = False,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        self.calls.append(text)
        self.label_calls.append(list(labels))
        self.thresholds.append(threshold)
        if self.error is not None:
            raise self.error
        words = [match.span() for match in GLINER_WORD_RE.finditer(text)]
        visible_end = words[self.config.max_len - 1][1] if len(words) > self.config.max_len else len(text)
        used = fake_prompt_tokens(labels)
        for start, end in words:
            used += fake_token_count(text[start:end])
            if used > self.token_limit:
                visible_end = min(visible_end, start)
                break
        found: list[dict[str, Any]] = list(self.extra)
        for value, (label, score) in self.values.items():
            if label not in labels or (self.honor_threshold and score < threshold):
                continue
            start = text.find(value)
            while start != -1:
                end = start + len(value)
                if end <= visible_end:
                    found.append({"start": start, "end": end, "text": value, "label": label, "score": score})
                start = text.find(value, start + 1)
        return sorted(found, key=lambda entity: entity["start"])


# Option parsing -------------------------------------------------------------


class GlinerOptionsTest(unittest.TestCase):
    def assert_rejected(self, argument: str, fragment: str) -> str:
        with self.assertRaises(SystemExit) as caught:
            parse_gliner_options(argument)
        message = str(caught.exception)
        self.assertIn(fragment, message)
        return message

    def test_defaults(self) -> None:
        for argument in (None, "", ","):
            with self.subTest(argument=argument):
                options = parse_gliner_options(argument)
                self.assertEqual(options.model, "urchade/gliner_small-v2.1")
                self.assertEqual(options.threshold, 0.5)
                self.assertEqual(dict(options.labels), {"person": "PERSON", "organization": "ORG"})
                self.assertFalse(options.offline)
                self.assertEqual(options.window_words, 300)
                self.assertEqual(options.overlap_words, 50)
                self.assertIsNone(options.revision)
                self.assertEqual(options.max_tokens, 512)
                self.assertFalse(options.local_model)

    def test_every_key(self) -> None:
        options = parse_gliner_options(
            "model=urchade/gliner_medium-v2.1, threshold=0.35, offline=true, window=200, overlap=0,"
            "labels=Person:PERSON|ORGANIZATION:ORG|project code name:SENSITIVE|client:CLIENT,"
            "revision=0123456789abcdef0123456789abcdef01234567, max_tokens=384"
        )
        self.assertEqual(options.model, "urchade/gliner_medium-v2.1")
        self.assertEqual(options.revision, "0123456789abcdef0123456789abcdef01234567")
        self.assertEqual(options.max_tokens, 384)
        self.assertEqual(options.threshold, 0.35)
        self.assertTrue(options.offline)
        self.assertEqual(options.window_words, 200)
        self.assertEqual(options.overlap_words, 0)
        self.assertEqual(
            list(options.labels.items()),
            [("Person", "PERSON"), ("ORGANIZATION", "ORG"), ("project code name", "SENSITIVE"), ("client", "CLIENT")],
        )
        self.assertFalse(parse_gliner_options("offline=false").offline)

    def test_malformed_values(self) -> None:
        cases = {
            "threshold=x": "'threshold' must be a number from 0 to 1",
            "threshold=2": "'threshold' must be a number from 0 to 1",
            "offline=sometimes": "'offline' must be true or false",
            "window=0": "'window' must be a whole number",
            "window=12.5": "'window' must be a whole number",
            "window=-3": "'window' must be a whole number",
            "overlap=x": "'overlap' must be a whole number",
            "window=50,overlap=50": "'overlap' must be smaller than half of 'window'",
            "window=100,overlap=50": "'overlap' must be smaller than half of 'window'",
            "window=40": "'overlap' must be smaller than half of 'window'",
            "max_tokens=10": "'max_tokens' must be a whole number from 64 to 8192",
            "max_tokens=99999": "'max_tokens' must be a whole number from 64 to 8192",
            "revision=..": "'revision' must be a Hub branch, tag, or commit id",
            "revision=main branch": "'revision' must be a Hub branch, tag, or commit id",
            "revision=-x": "'revision' must be a Hub branch, tag, or commit id",
            "model=": "'model' must not be empty",
            "labels=person": "expects label:CATEGORY pairs",
            "labels=:PERSON": "expects label:CATEGORY pairs",
            "labels=person:HUMAN": "must use canonical categories",
            "labels=person:PERSON||organization:ORG": "expects label:CATEGORY pairs",
            "labels=person:PERSON|person:CLIENT": "names a label more than once",
        }
        for argument, fragment in cases.items():
            with self.subTest(argument=argument):
                self.assert_rejected(argument, fragment)

    def test_unknown_duplicate_and_malformed_items(self) -> None:
        message = self.assert_rejected("windows=10", "Unknown gliner detector option 'windows'")
        self.assertIn("overlap", message)
        self.assert_rejected("offline=true,offline=false", "'offline' was given more than once")
        message = self.assert_rejected("/home/someone/private-model", "expected comma-separated key=value pairs")
        self.assertNotIn("private-model", message)

    def test_local_looking_model_values_must_be_absolute_existing_directories(self) -> None:
        cases = [
            "../gliner",
            "./gliner",
            ".gliner",
            "~/no-such-redctx-model-dir",
            "/no/such/redctx/model/dir",
            "C:models\\private",
            "C:/no/such/redctx/model/dir",
            "models\\private-client",
            str(PROJECT_ROOT / "no-such-private-model"),
        ]
        try:
            cases.append(os.path.relpath(Path(__file__).resolve().parent))  # an existing relative directory
        except ValueError:  # on another drive than the working directory
            pass
        for value in cases:
            with self.subTest(model=value):
                message = self.assert_rejected(f"model={value}", "looks like a local path")
                self.assertIn("absolute path to an existing model directory", message)
                self.assertNotIn("private", message)
                self.assertNotIn("no-such", message)

    def test_other_model_values_must_be_hub_ids(self) -> None:
        for value in ("gliner-local", "a/b/c", "org name/model", "org/", "-org/model", "org/mödel"):
            with self.subTest(model=value):
                message = self.assert_rejected(f"model={value}", "must be a Hugging Face model id")
                self.assertNotIn(value, message.replace("urchade/gliner_small-v2.1", ""))
        # "org/.." is rejected either as a Hub id or, where the platform
        # collapses it to an existing directory, as a relative local path.
        with self.assertRaises(SystemExit):
            parse_gliner_options("model=org/..")
        for value in ("urchade/gliner_medium-v2.1", "knowledgator/gliner-multitask-large-v0.5", "a/b"):
            with self.subTest(model=value):
                options = parse_gliner_options(f"model={value}")
                self.assertEqual((options.model, options.local_model), (value, False))

    def test_absolute_local_directory_is_accepted_without_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            options = parse_gliner_options(f"model={directory}")
            self.assertEqual((options.model, options.local_model), (directory, True))
            self.assert_rejected(f"model={directory},revision=main", "'revision' applies only to Hugging Face model ids")

    def test_model_label_names_only_the_default_model(self) -> None:
        self.assertEqual(model_label("urchade/gliner_small-v2.1"), "urchade/gliner_small-v2.1")
        for model in (
            "urchade/gliner_medium-v2.1",
            "org/client-name-model",
            "C:/models/private-gliner",
            "/srv/private/gliner",
            "../gliner",
            "~/models/x",
            "gliner-local",
            str(PROJECT_ROOT),
        ):
            with self.subTest(model=model):
                self.assertEqual(model_label(model), "custom")


# Detection behaviour --------------------------------------------------------


class GlinerMappingTest(unittest.TestCase):
    def test_default_labels_map_to_canonical_categories(self) -> None:
        self.assertEqual(dict(DEFAULT_LABEL_CATEGORIES), {"person": "PERSON", "organization": "ORG"})
        self.assertTrue(set(DEFAULT_LABEL_CATEGORIES.values()) <= PLACEHOLDER_CATEGORIES)
        model = FakeGlinerModel({"Avery Lindqvist": ("person", 0.98), "Lantern Labs": ("organization", 0.96)})
        detector = GlinerDetector(model, version="t")
        self.assertEqual(
            spans_as_values(SAMPLE, detector.detect(SAMPLE)),
            [("Avery Lindqvist", "PERSON"), ("Lantern Labs", "ORG")],
        )
        self.assertEqual(model.label_calls, [["person", "organization"]])
        self.assertEqual(model.thresholds, [0.5])

    def test_labels_are_passed_and_matched_exactly_as_given(self) -> None:
        labels = parse_gliner_options("labels=Person:CLIENT|project code name:SENSITIVE").labels
        model = FakeGlinerModel(
            {"Avery Lindqvist": ("Person", 0.9), "Lantern Labs rollout": ("project code name", 0.8)},
            extra=[{"start": 0, "end": 7, "text": "Contact", "label": "person", "score": 0.99}],
        )
        detector = GlinerDetector(model, version="t", labels=labels)
        self.assertEqual(
            spans_as_values(SAMPLE, detector.detect(SAMPLE)),
            [("Avery Lindqvist", "CLIENT"), ("Lantern Labs rollout", "SENSITIVE")],
        )
        self.assertEqual(model.label_calls, [["Person", "project code name"]])

    def test_non_canonical_or_empty_labels_are_rejected_at_construction(self) -> None:
        for labels in ({"person": "HUMAN"}, {}):
            with self.subTest(labels=labels):
                with self.assertRaises(ValueError):
                    GlinerDetector(FakeGlinerModel(), version="t", labels=labels)

    def test_threshold_filters_scores_even_if_the_model_does_not(self) -> None:
        values = {"alpha": ("person", 0.49), "bravo": ("person", 0.5), "charlie": ("person", 0.9)}
        text = "alpha bravo charlie"
        detector = GlinerDetector(FakeGlinerModel(values, honor_threshold=False), version="t")
        self.assertEqual([value for value, _ in spans_as_values(text, detector.detect(text))], ["bravo", "charlie"])
        strict = GlinerDetector(FakeGlinerModel(values, honor_threshold=False), version="t", threshold=0.95)
        self.assertEqual(strict.detect(text), [])
        model = FakeGlinerModel(values)
        GlinerDetector(model, version="t", threshold=0.3).detect(text)
        self.assertEqual(model.thresholds, [0.3])

    def test_offsets_survive_unicode_crlf_and_leading_space(self) -> None:
        text = "  \r\nZoë Ångström 😀 met Łukasz Żółw at Lantern Labs.\r\n"
        model = FakeGlinerModel(
            {"Zoë Ångström": ("person", 0.9), "Łukasz Żółw": ("person", 0.9), "Lantern Labs": ("organization", 0.9)}
        )
        spans = GlinerDetector(model, version="t").detect(text)
        self.assertEqual(
            spans_as_values(text, spans),
            [("Zoë Ångström", "PERSON"), ("Łukasz Żółw", "PERSON"), ("Lantern Labs", "ORG")],
        )
        # The window starts at the first word, not at the leading whitespace.
        self.assertEqual(model.calls, [text.strip()])

    def test_span_ends_extend_over_trailing_combining_marks(self) -> None:
        # Decomposed (NFD) text: the accent is a separate code point that
        # GLiNER's splitter treats as its own "word".
        text = unicodedata.normalize("NFD", "Yesterday José Garcia met Renée at Lantern Labs.")
        self.assertIn("Jose\u0301", text)
        model = FakeGlinerModel(
            {"Jose": ("person", 0.9), "Rene": ("person", 0.8), "Lantern Labs": ("organization", 0.9)}
        )
        spans = GlinerDetector(model, version="t").detect(text)
        self.assertEqual(
            spans_as_values(text, spans),
            [("Jose\u0301", "PERSON"), ("Rene\u0301", "PERSON"), ("Lantern Labs", "ORG")],
        )
        for span in spans:
            self.assertFalse(span.end < len(text) and unicodedata.combining(text[span.end]))

    def test_out_of_range_results_fail_and_engine_hides_details(self) -> None:
        model = FakeGlinerModel(extra=[{"start": 0, "end": 99, "text": "x", "label": "person", "score": 0.9}])
        with self.assertRaises(ValueError):
            GlinerDetector(model, version="t").detect("short text")
        failing = GlinerDetector(FakeGlinerModel(error=RuntimeError(LIBRARY_CANARY)), version="t")
        redactor = Redactor(RedactionConfig(salt=TEST_SALT), detectors=(failing,))
        with self.assertRaises(DetectorError) as caught:
            redactor.redact("Avery Lindqvist")
        self.assertEqual(str(caught.exception), DETECTOR_FAILED_MESSAGE)
        self.assertNotIn(LIBRARY_CANARY, str(caught.exception))

    def test_engine_redacts_nominated_values_and_receipt_names_the_model(self) -> None:
        model = FakeGlinerModel({"Quillfeather Ostrander": ("person", 0.9)})
        detector = GlinerDetector(model, version="0.2.29/urchade/gliner_small-v2.1")
        redactor = Redactor(RedactionConfig(salt=TEST_SALT), detectors=(detector,))
        output = redactor.redact("Quillfeather Ostrander wrote; QUILLFEATHER OSTRANDER signed.\n")
        self.assertNotIn("quillfeather", output.lower())
        self.assertIn("[PERSON_", output)
        receipt = redactor.receipt()["detectors"][0]
        self.assertEqual((receipt["name"], receipt["version"]), ("gliner", "0.2.29/urchade/gliner_small-v2.1"))


class GlinerWindowingTest(unittest.TestCase):
    def test_word_windows_use_gliner_words_and_exact_positions(self) -> None:
        self.assertEqual(word_windows("", 5, 1), [])
        self.assertEqual(word_windows("   \r\n ", 5, 1), [])
        text = " one two, three-four (five) six "
        # GLiNER words: one two , three-four ( five ) six -> 8 words
        self.assertEqual(len(GLINER_WORD_RE.findall(text)), 8)
        self.assertEqual(word_windows(text, 8, 2), [(1, len(text) - 1)])
        windows = word_windows(text, 4, 1)
        self.assertEqual([text[start:end] for start, end in windows], ["one two, three-four", "three-four (five)", ") six"])
        self.assertEqual(word_windows(text, 3, 0), [(1, 9), (10, 26), (26, 31)])

    def test_offsets_shift_back_and_straddling_value_is_found_via_overlap(self) -> None:
        words = [f"w{index:03d}" for index in range(60)]
        words[17:19] = ["Avery", "Lindqvist"]  # crosses the first window end (word 20 is index 19)
        words[19] = "Lantern"
        words[20] = "Labs"
        words[44] = "Quillfeather"
        text = " ".join(words[:30]) + "\r\n" + " ".join(words[30:]) + "\r\n"
        model = FakeGlinerModel(
            {
                "Avery Lindqvist": ("person", 0.9),
                "Lantern Labs": ("organization", 0.9),
                "Lantern": ("organization", 0.7),  # what a window cut after "Lantern" would see
                "Quillfeather": ("person", 0.9),
            }
        )
        detector = GlinerDetector(model, version="t", window_words=20, overlap_words=5)
        windows = word_windows(text, 20, 5)
        self.assertGreater(len(windows), 2)
        straddle = text.index("Lantern Labs")
        self.assertLess(straddle, windows[0][1])
        self.assertGreater(straddle + len("Lantern Labs"), windows[0][1])
        spans = detector.detect(text)
        self.assertEqual(model.calls, [text[start:end] for start, end in windows])
        self.assertEqual(
            spans_as_values(text, spans),
            [("Avery Lindqvist", "PERSON"), ("Lantern Labs", "ORG"), ("Quillfeather", "PERSON")],
        )
        self.assertEqual(spans[1], Span(straddle, straddle + len("Lantern Labs"), "ORG"))
        # Values inside an overlap are seen by two windows but reported once.
        self.assertEqual(len(spans), len(set(spans)))

    def test_long_text_beyond_max_len_is_covered(self) -> None:
        words = [f"word{index}" for index in range(600)]
        words[450:452] = ["Avery", "Lindqvist"]
        text = " ".join(words)
        whole = FakeGlinerModel({"Avery Lindqvist": ("person", 0.9)}).predict_entities(text, labels=["person"])
        self.assertEqual(whole, [], "the fake truncates like the real model")
        model = FakeGlinerModel({"Avery Lindqvist": ("person", 0.9)})
        detector = GlinerDetector(model, version="t")
        spans = detector.detect(text)
        self.assertEqual(spans_as_values(text, spans), [("Avery Lindqvist", "PERSON")])
        self.assertGreaterEqual(len(model.calls), 3)
        self.assertTrue(all(len(GLINER_WORD_RE.findall(call)) <= 300 for call in model.calls))
        self.assertTrue(all(fake_window_tokens(call, detector.label_list) <= 512 for call in model.calls))

    def test_invalid_window_configuration_is_rejected(self) -> None:
        for window, overlap in ((10, 10), (10, 5), (1, 0)):
            with self.subTest(window=window, overlap=overlap):
                with self.assertRaises(ValueError):
                    GlinerDetector(FakeGlinerModel(), version="t", window_words=window, overlap_words=overlap)
        self.assertEqual(GlinerDetector(FakeGlinerModel(), version="t", window_words=10, overlap_words=4).overlap_words, 4)


class GlinerTokenBudgetTest(unittest.TestCase):
    """Windows are bounded by subword tokens as well as by words."""

    NAME_TAIL = " Avery Lindqvist joined Lantern Labs."
    VALUES = {"Avery Lindqvist": ("person", 0.9), "Lantern Labs": ("organization", 0.9)}

    def detect(self, text: str, **kwargs: Any) -> tuple[list[tuple[str, str]], FakeGlinerModel, GlinerDetector]:
        model = FakeGlinerModel(self.VALUES)
        detector = GlinerDetector(model, version="t", **kwargs)
        return spans_as_values(text, detector.detect(text)), model, detector

    def assert_calls_within_budget(self, model: FakeGlinerModel, detector: GlinerDetector) -> None:
        self.assertTrue(model.calls)
        for call in model.calls:
            self.assertLessEqual(fake_window_tokens(call, detector.label_list), detector.max_tokens)
            self.assertLessEqual(len(GLINER_WORD_RE.findall(call)), detector.window_words)

    def test_prompt_overhead_is_measured_once_with_the_tokenizer(self) -> None:
        detector = GlinerDetector(FakeGlinerModel(), version="t")
        self.assertEqual(detector.prompt_tokens, fake_prompt_tokens(["person", "organization"]))
        self.assertEqual(detector.token_budget, 512 - detector.prompt_tokens)

    def test_word_windows_alone_would_miss_a_name_after_token_heavy_words(self) -> None:
        words = " ".join(f"Pneumonoultramicroscopicsilicovolcanoconiosis{index}" for index in range(150))
        text = words + self.NAME_TAIL
        self.assertLess(len(GLINER_WORD_RE.findall(text)), 300)  # one word window
        self.assertGreater(fake_window_tokens(text, ["person", "organization"]), 512)
        old_style = FakeGlinerModel(self.VALUES)
        whole = old_style.predict_entities(text, labels=["person", "organization"])
        self.assertEqual(whole, [], "the fake drops text past the token limit like the real model")
        found, model, detector = self.detect(text)
        self.assertEqual(found, [("Avery Lindqvist", "PERSON"), ("Lantern Labs", "ORG")])
        self.assert_calls_within_budget(model, detector)
        self.assertGreater(len(model.calls), 1)

    def test_name_after_a_base64_blob_is_found(self) -> None:
        blob = base64.b64encode(bytes(range(256)) * 16).decode()[:4000]
        text = "config token=" + blob + self.NAME_TAIL
        found, model, detector = self.detect(text)
        self.assertEqual(found, [("Avery Lindqvist", "PERSON"), ("Lantern Labs", "ORG")])
        self.assert_calls_within_budget(model, detector)

    def test_name_after_a_huge_hex_string_is_found_and_blob_windows_are_skipped(self) -> None:
        hex_blob = ("0123456789abcdef" * 6250)[:100_000]
        text = hex_blob + self.NAME_TAIL
        found, model, detector = self.detect(text)
        self.assertEqual(found, [("Avery Lindqvist", "PERSON"), ("Lantern Labs", "ORG")])
        self.assert_calls_within_budget(model, detector)
        # Only windows that contain a natural word reach the model.
        self.assertLessEqual(len(model.calls), 3)
        for call in model.calls:
            self.assertTrue(any(len(word) <= LONG_WORD_CHARS for word in GLINER_WORD_RE.findall(call)))

    def test_window_units_split_long_words_into_exact_pieces(self) -> None:
        text = "ab " + "x" * 150 + " cd"
        units = window_units(text)
        self.assertEqual(
            units,
            [(0, 2, False), (3, 67, True), (67, 131, True), (131, 153, True), (154, 156, False)],
        )
        self.assertEqual("".join(text[start:end] for start, end, piece in units if piece), "x" * 150)

    def test_windows_respect_the_token_budget_and_map_back_exactly(self) -> None:
        counter = make_token_counter(FakeTokenizer())
        words = [("w" * (index % 70 + 1)) for index in range(400)]
        text = "  " + " ".join(words) + "\r\n"
        windows = word_windows(text, 300, 50, token_budget=100, count_tokens=counter)
        self.assertGreater(len(windows), 5)
        units = window_units(text)
        starts = {start for start, _end, _piece in units}
        ends = {end for _start, end, _piece in units}
        for (start, end), (next_start, _next_end) in zip(windows, windows[1:]):
            self.assertIn(start, starts)
            self.assertIn(end, ends)
            self.assertLess(start, next_start)
            self.assertLessEqual(next_start, end)  # overlapping or adjacent, never a gap
        for start, end in windows:
            chunk_units = [(s, e, piece) for s, e, piece in units if start <= s and e <= end]
            cost = sum(fake_token_count(text[s:e]) + (1 if piece else 0) for s, e, piece in chunk_units)
            self.assertTrue(cost <= 100 or len(chunk_units) == 1)
        self.assertEqual(windows[0][0], 2)
        self.assertEqual(windows[-1][1], len(text) - 2)

    def test_without_a_budget_windows_are_counted_in_words_only(self) -> None:
        text = " ".join(["a" * 60] * 10)
        self.assertEqual(word_windows(text, 300, 50), [(0, len(text))])
        counter = make_token_counter(FakeTokenizer())
        self.assertGreater(len(word_windows(text, 300, 50, token_budget=40, count_tokens=counter)), 1)

    def test_slow_tokenizers_without_word_ids_are_supported(self) -> None:
        class SlowTokenizer(FakeTokenizer):
            def __call__(self, words: Sequence[str], is_split_into_words: bool = False, add_special_tokens: bool = True, **kwargs: Any) -> Any:
                if is_split_into_words:
                    return {"input_ids": [5] * sum(fake_token_count(word) for word in words)}  # no word_ids()
                return {"input_ids": [[5] * fake_token_count(word) for word in words]}

        self.assertEqual(make_token_counter(SlowTokenizer())(["abcdefgh", "x"]), [2, 1])

    def test_labels_that_eat_the_budget_are_rejected(self) -> None:
        labels = {("label " + "x" * 50 + str(index)): "PERSON" for index in range(3)}
        with self.assertRaisesRegex(ValueError, r"labels take \d+ of the 64-token window budget"):
            GlinerDetector(FakeGlinerModel(), version="t", labels=labels, max_tokens=64)

    def test_models_without_a_tokenizer_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "needs the model's transformer tokenizer"):
            GlinerDetector(FakeGlinerModel(tokenizer=None), version="t")


class GlinerLockTest(unittest.TestCase):
    def test_calls_are_serialized_with_a_lock(self) -> None:
        detector = GlinerDetector(FakeGlinerModel(), version="t")
        self.assertIsInstance(detector._lock, type(threading.Lock()))

        class ConcurrencyProbe(FakeGlinerModel):
            active = 0
            peak = 0

            def predict_entities(self, text: str, labels: list[str], **kwargs: Any) -> list[dict[str, Any]]:
                type(self).active += 1
                type(self).peak = max(type(self).peak, type(self).active)
                time.sleep(0.01)
                type(self).active -= 1
                return []

        detector = GlinerDetector(ConcurrencyProbe(), version="t")
        threads = [threading.Thread(target=detector.detect, args=("Avery Lindqvist",)) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(ConcurrencyProbe.peak, 1)


class GlinerConformanceTest(DetectorConformance, unittest.TestCase):
    def make_detector(self) -> Detector:
        return GlinerDetector(
            FakeGlinerModel(
                {
                    "quillfeather": ("person", 0.9),
                    "Zorblax": ("organization", 0.8),
                    "árvíz": ("organization", 0.4),
                    "PERSON_0123": ("person", 0.9),
                }
            ),
            version="0.2.29/test",
        )

    def positive_texts(self) -> Sequence[str]:
        return (
            "quillfeather met Zorblax\n",
            " ".join(["filler"] * 500) + " quillfeather\n",
            "f" * 5000 + " quillfeather\n",
        )


# Factory --------------------------------------------------------------------


class FakeLocalEntryNotFoundError(OSError):
    """Stands in for huggingface_hub.errors.LocalEntryNotFoundError (an OSError)."""


def fake_gliner_class(model: Any = None, error: BaseException | None = None) -> tuple[Any, list[tuple[str, dict[str, Any]]]]:
    calls: list[tuple[str, dict[str, Any]]] = []

    class FakeGLiNER:
        @classmethod
        def from_pretrained(cls, model_id: str, **kwargs: Any) -> Any:
            calls.append((model_id, kwargs))
            if error is not None:
                raise error
            return model if model is not None else FakeGlinerModel({"Avery Lindqvist": ("person", 0.9)})

    return FakeGLiNER, calls


class GlinerFactoryTest(unittest.TestCase):
    def test_missing_library_gives_install_message(self) -> None:
        with blocked_modules("gliner"):
            with self.assertRaises(SystemExit) as caught:
                factory("offline=true")
        self.assertEqual(str(caught.exception), INSTALL_MESSAGE)
        self.assertIn('pip install "redacted-context-mcp[gliner]"', str(caught.exception))
        with blocked_modules("gliner"):
            with patch.object(detectors.metadata, "entry_points", return_value=[]):
                with self.assertRaisesRegex(SystemExit, r"redacted-context-mcp\[gliner\]"):
                    load_detectors(["gliner"])

    def test_options_are_validated_before_importing(self) -> None:
        with patch.object(detectors_gliner, "_import_gliner") as importer:
            with self.assertRaisesRegex(SystemExit, "Unknown gliner detector option"):
                factory("nope=1")
        importer.assert_not_called()

    def test_factory_loads_once_with_offline_flag_and_records_model_in_version(self) -> None:
        cls, calls = fake_gliner_class()
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            detector = factory("offline=true,threshold=0.4,window=100,overlap=10")
            online = factory(None)
        self.assertEqual(
            calls,
            [
                ("urchade/gliner_small-v2.1", {"local_files_only": True}),
                ("urchade/gliner_small-v2.1", {"local_files_only": False}),
            ],
        )
        self.assertIsInstance(detector, GlinerDetector)
        self.assertEqual(detector.name, "gliner")
        self.assertEqual(detector.version, "0.2.29/urchade/gliner_small-v2.1")
        self.assertEqual((detector.threshold, detector.window_words, detector.overlap_words), (0.4, 100, 10))
        self.assertEqual((online.threshold, online.window_words, online.overlap_words), (0.5, 300, 50))
        self.assertEqual(spans_as_values(SAMPLE, detector.detect(SAMPLE)), [("Avery Lindqvist", "PERSON")])

    def test_revision_is_passed_to_from_pretrained(self) -> None:
        cls, calls = fake_gliner_class()
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            factory("revision=0123456789abcdef0123456789abcdef01234567")
            factory("offline=true,revision=v2.1")
        self.assertEqual(
            calls,
            [
                ("urchade/gliner_small-v2.1", {"local_files_only": False, "revision": "0123456789abcdef0123456789abcdef01234567"}),
                ("urchade/gliner_small-v2.1", {"local_files_only": True, "revision": "v2.1"}),
            ],
        )

    def test_rejected_model_values_never_reach_from_pretrained(self) -> None:
        cls, calls = fake_gliner_class()
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            for value in ("../private-gliner", "~/no-such-redctx-model-dir", "models\\client", "gliner-local", "a/b/c"):
                with self.subTest(model=value):
                    with self.assertRaises(SystemExit) as caught:
                        factory(f"model={value},offline=true")
                    self.assertNotIn("private", str(caught.exception))
                    self.assertNotIn("client", str(caught.exception))
        self.assertEqual(calls, [])

    def test_local_model_paths_are_not_recorded(self) -> None:
        cls, calls = fake_gliner_class()
        with tempfile.TemporaryDirectory(prefix="private-gliner-model-") as private:
            with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
                detector = factory(f"model={private}")
        self.assertEqual(calls, [(private, {"local_files_only": False})])
        self.assertEqual(detector.version, "0.2.29/custom")

    def test_only_whitespace_word_splitters_are_accepted(self) -> None:
        for splitter in ("stanza", "spacy", "jieba", "mecab", "universal"):
            cls, _calls = fake_gliner_class(model=FakeGlinerModel(splitter=splitter))
            with self.subTest(splitter=splitter):
                with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
                    with self.assertRaisesRegex(SystemExit, "supports only models that split words on whitespace"):
                        factory("offline=true")
        for splitter in ("whitespace", None):
            cls, _calls = fake_gliner_class(model=FakeGlinerModel(splitter=splitter))
            with self.subTest(splitter=splitter):
                with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
                    self.assertIsInstance(factory("offline=true"), GlinerDetector)

    def test_model_without_a_tokenizer_is_a_startup_error(self) -> None:
        cls, _calls = fake_gliner_class(model=FakeGlinerModel(tokenizer=None))
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            with self.assertRaisesRegex(SystemExit, "needs the model's transformer tokenizer"):
                factory("offline=true")

    def test_max_tokens_is_bounded_by_the_encoder(self) -> None:
        self.assertEqual(model_token_limit(FakeGlinerModel(token_limit=256)), 256)
        self.assertEqual(model_token_limit(SimpleNamespace()), 512)
        cls, _calls = fake_gliner_class(model=FakeGlinerModel(token_limit=256))
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            with self.assertRaisesRegex(SystemExit, r"'max_tokens' \(512\) exceeds the model's maximum sequence length of 256"):
                factory("offline=true")
            self.assertEqual(factory("offline=true,max_tokens=256").token_budget, 256 - fake_prompt_tokens(["person", "organization"]))

    def test_labels_that_eat_the_budget_are_a_startup_error(self) -> None:
        cls, _calls = fake_gliner_class()
        labels = "|".join(f"label {'x' * 50}{index}:PERSON" for index in range(3))
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            with self.assertRaisesRegex(SystemExit, "use fewer or shorter labels"):
                factory(f"offline=true,max_tokens=64,labels={labels}")

    def test_non_default_model_ids_are_not_recorded(self) -> None:
        cls, calls = fake_gliner_class()
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            detector = factory("model=org/client-name-model,offline=true")
        self.assertEqual(calls[0][0], "org/client-name-model")
        self.assertEqual(detector.version, "0.2.29/custom")
        self.assertNotIn("client-name", detector.version)

    def test_window_larger_than_model_max_len_is_rejected(self) -> None:
        cls, _calls = fake_gliner_class(model=FakeGlinerModel(max_len=256))
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            with self.assertRaisesRegex(SystemExit, r"'window' \(300\) exceeds the model's maximum of 256 words"):
                factory(None)
            self.assertEqual(factory("window=256,overlap=20").window_words, 256)

    def test_missing_model_messages_are_operator_facing_and_input_free(self) -> None:
        cls, _calls = fake_gliner_class(error=FakeLocalEntryNotFoundError(f"{LIBRARY_CANARY} C:/Users/someone/.cache"))
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            with self.assertRaises(SystemExit) as offline:
                factory("offline=true")
            with self.assertRaises(SystemExit) as online:
                factory("offline=false")
        self.assertIn("local Hugging Face cache", str(offline.exception))
        self.assertIn("hf download", str(offline.exception))
        self.assertIn("FakeLocalEntryNotFoundError", str(offline.exception))
        self.assertIn("contacted at every startup without offline=true", str(online.exception))
        for message in (str(offline.exception), str(online.exception)):
            self.assertNotIn(LIBRARY_CANARY, message)
            self.assertNotIn("someone", message)

    def test_load_detectors_resolves_the_lazy_builtin(self) -> None:
        cls, _calls = fake_gliner_class()
        with patch.object(detectors_gliner, "_import_gliner", return_value=(cls, "0.2.29")):
            with patch.object(detectors.metadata, "entry_points", return_value=[]):
                loaded = load_detectors(["gliner=offline=true"])
                self.assertIn("gliner", detectors.available_detector_names())
        self.assertEqual([detector.name for detector in loaded], ["gliner"])

    def test_packaging_declares_extra_and_no_redundant_entry_point(self) -> None:
        data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = data["project"]
        self.assertEqual(project["optional-dependencies"]["gliner"], ["gliner>=0.2.29,<1", "protobuf>=5.29.5,<8"])
        # Built-ins always win over entry points, so registering one would be unreachable.
        group = project.get("entry-points", {}).get("redacted_context_mcp.detectors", {})
        self.assertNotIn("gliner", group)
        self.assertIn("gliner", detectors.BUILTIN_DETECTORS)


# Real library (opt-in) ------------------------------------------------------


def gliner_available() -> bool:
    try:
        return importlib.util.find_spec("gliner") is not None
    except (ImportError, ValueError):
        return False


@unittest.skipUnless(
    REAL_TESTS and gliner_available(),
    "set REDCTX_REAL_DETECTOR_TESTS=1 with gliner installed and urchade/gliner_small-v2.1 cached",
)
class RealGlinerTest(unittest.TestCase):
    detector: GlinerDetector

    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.detector = factory("offline=true")
        except SystemExit as exc:  # report as an error instead of ending the run
            raise RuntimeError(str(exc)) from None

    def test_word_regex_matches_gliner_splitter(self) -> None:
        from gliner.data_processing.tokenizer import WhitespaceTokenSplitter

        self.assertEqual(WhitespaceTokenSplitter().whitespace_pattern.pattern, GLINER_WORD_RE.pattern)

    def test_model_exposes_what_the_adapter_relies_on(self) -> None:
        model = self.detector.model
        self.assertEqual(model.config.words_splitter_type, "whitespace")
        self.assertEqual(model.config.max_len, 384)
        self.assertEqual(model_token_limit(model), 512)
        tokenizer = detectors_gliner.model_tokenizer(model)
        self.assertIsNotNone(tokenizer)
        # [CLS] <<ENT>> person <<ENT>> organization <<SEP>> [SEP]
        self.assertEqual(self.detector.prompt_tokens, 7)
        # Per-word counts plus the prompt equal what GLiNER feeds the encoder.
        words = GLINER_WORD_RE.findall(SAMPLE + " Pneumonoultramicroscopicsilicovolcanoconiosis 0f3a9c")
        prompt = detectors_gliner.prompt_words(model, self.detector.label_list)
        full = len(tokenizer(prompt + words, is_split_into_words=True)["input_ids"])
        self.assertEqual(self.detector.prompt_tokens + sum(make_token_counter(tokenizer)(words)), full)

    def assert_found_quickly(self, text: str) -> None:
        started = time.perf_counter()
        spans = self.detector.detect(text)
        elapsed = time.perf_counter() - started
        found = spans_as_values(text, spans)
        self.assertIn(("Avery Lindqvist", "PERSON"), found)
        self.assertLess(elapsed, 30.0)
        # Every window, as GLiNER splits and tokenizes it, fits the budget.
        tokenizer = detectors_gliner.model_tokenizer(self.detector.model)
        prompt = detectors_gliner.prompt_words(self.detector.model, self.detector.label_list)
        for start, end in self.detector.windows(text):
            window_words = GLINER_WORD_RE.findall(text[start:end])
            tokens = len(tokenizer(prompt + window_words, is_split_into_words=True)["input_ids"])
            self.assertLessEqual(tokens, 512)

    def test_name_after_150_token_heavy_words_is_found(self) -> None:
        words = " ".join(f"Pneumonoultramicroscopicsilicovolcanoconiosis{index}" for index in range(150))
        self.assert_found_quickly(words + " Avery Lindqvist joined Lantern Labs.")

    def test_name_after_a_4000_character_base64_blob_is_found(self) -> None:
        blob = base64.b64encode(bytes(range(256)) * 16).decode()[:4000]
        self.assert_found_quickly(blob + " Avery Lindqvist joined Lantern Labs.")

    def test_name_after_a_100000_character_hex_string_is_found(self) -> None:
        hex_blob = ("0123456789abcdef" * 6250)[:100_000]
        self.assert_found_quickly(hex_blob + " Avery Lindqvist joined Lantern Labs.")

    def test_decomposed_accents_stay_inside_spans(self) -> None:
        text = unicodedata.normalize("NFD", "Yesterday José Garcia joined Lantern Labs with Renée Dubois.")
        spans = self.detector.detect(text)
        found = spans_as_values(text, spans)
        self.assertIn((unicodedata.normalize("NFD", "José Garcia"), "PERSON"), found)
        for span in spans:
            self.assertFalse(span.end < len(text) and unicodedata.combining(text[span.end]), found)

    def test_probe_sentence(self) -> None:
        self.assertTrue(self.detector.version.endswith("/urchade/gliner_small-v2.1"), self.detector.version)
        found = spans_as_values(SAMPLE, self.detector.detect(SAMPLE))
        self.assertIn(("Avery Lindqvist", "PERSON"), found)
        self.assertIn(("Lantern Labs", "ORG"), found)
        self.assertEqual(found, spans_as_values(SAMPLE, self.detector.detect(SAMPLE)))

    def test_entity_after_word_400_is_found(self) -> None:
        sentence = "The quarterly report was reviewed again by the committee without any changes"
        filler = " ".join([sentence + "."] * 60).split(" ")
        self.assertGreaterEqual(len(filler), 600)
        text = " ".join(filler[:450]) + " Avery Lindqvist joined Lantern Labs last week. " + " ".join(filler[450:600])
        spans = self.detector.detect(text)
        people = [span for span in spans if text[span.start : span.end] == "Avery Lindqvist"]
        self.assertTrue(people, spans_as_values(text, spans))
        self.assertEqual(people[0].category, "PERSON")
        self.assertGreater(len(GLINER_WORD_RE.findall(text[: people[0].start])), 400)

    def test_conformance_against_the_real_model(self) -> None:
        detector = self.detector

        class RealConformance(DetectorConformance, unittest.TestCase):
            def make_detector(self) -> Detector:
                return detector

            def positive_texts(self) -> Sequence[str]:
                return (SAMPLE,)

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(RealConformance).run(result)
        self.assertTrue(result.wasSuccessful(), result.failures + result.errors)


if __name__ == "__main__":
    unittest.main()
