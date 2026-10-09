"""Reusable contract tests for plugged detectors.

Adapter authors (inside or outside this package) can check a detector
against the engine's contract with::

    import unittest
    from redacted_context_mcp.testing import DetectorConformance

    class MyDetectorConformance(DetectorConformance, unittest.TestCase):
        def make_detector(self):
            return my_package.factory(None)

        def positive_texts(self):
            return ("Text on which my detector finds something.\\n",)

This module imports only the standard library and the leaf ``detectors``
and ``defaults`` modules (never ``redaction``, ``rendering``, ``server``, or
``core``) and never the optional detector libraries. Importing it still runs
the package root (``redacted_context_mcp/__init__.py``), which imports
``discovery`` and through it ``config``, ``filesystem``, ``documents``, and
``limits``, so it is not free in import cost.
"""

from __future__ import annotations

import operator
from typing import Sequence

from .defaults import PLACEHOLDER_CATEGORIES
from .detectors import MAX_DETECTOR_SPANS, Detector, Span, run_detector


class DetectorConformance:
    """Contract assertions every plugged detector must satisfy.

    Mix into ``unittest.TestCase`` and implement ``make_detector`` (and
    optionally ``positive_texts``). See ARCHITECTURE.md ("Detectors").
    """

    sample_texts: tuple[str, ...] = (
        "",
        "plain text without anything notable\n",
        "Ticket TICKET-12345 mentions zorblax and quillfeather.\n",
        "Multi\nline\r\ntext with Zorblax\tand unicode árvíz.\n",
        "[PERSON_0123456789abcdef0123456789abcdef] already redacted\n",
    )

    # Subclass hooks -------------------------------------------------------

    def make_detector(self) -> Detector:
        raise NotImplementedError

    def positive_texts(self) -> Sequence[str]:
        """Texts on which the detector is expected to nominate at least one span."""
        return ()

    # Shared assertions ----------------------------------------------------

    def all_texts(self) -> tuple[str, ...]:
        return (*self.sample_texts, *self.positive_texts())

    def detect_checked(self, detector: Detector, text: str) -> list[Span]:
        spans = list(detector.detect(text))
        self.assertLessEqual(len(spans), MAX_DETECTOR_SPANS)  # type: ignore[attr-defined]
        for span in spans:
            start, end = operator.index(span.start), operator.index(span.end)
            self.assertNotIsInstance(span.start, bool)  # type: ignore[attr-defined]
            self.assertNotIsInstance(span.end, bool)  # type: ignore[attr-defined]
            self.assertTrue(0 <= start < end <= len(text), span)  # type: ignore[attr-defined]
            self.assertIn(span.category, PLACEHOLDER_CATEGORIES)  # type: ignore[attr-defined]
        return spans

    @staticmethod
    def span_tuples(spans: Sequence[Span]) -> list[tuple[int, int, str]]:
        return [(operator.index(span.start), operator.index(span.end), str(span.category)) for span in spans]

    def test_satisfies_protocol_and_declares_metadata(self) -> None:
        detector = self.make_detector()
        self.assertIsInstance(detector, Detector)  # type: ignore[attr-defined]
        for value in (detector.name, detector.version):
            self.assertIsInstance(value, str)  # type: ignore[attr-defined]
            self.assertTrue(value.strip())  # type: ignore[attr-defined]

    def test_spans_are_in_bounds_with_canonical_categories(self) -> None:
        detector = self.make_detector()
        for text in self.all_texts():
            self.detect_checked(detector, text)

    def test_positive_texts_nominate_spans(self) -> None:
        detector = self.make_detector()
        for text in self.positive_texts():
            self.assertTrue(self.detect_checked(detector, text), text)  # type: ignore[attr-defined]

    def test_is_deterministic(self) -> None:
        detector = self.make_detector()
        for text in self.all_texts():
            first = self.span_tuples(detector.detect(text))
            second = self.span_tuples(detector.detect(text))
            self.assertEqual(first, second)  # type: ignore[attr-defined]
            fresh = self.span_tuples(self.make_detector().detect(text))
            self.assertEqual(first, fresh)  # type: ignore[attr-defined]

    def test_result_is_independent_of_previous_calls(self) -> None:
        # Spans for each text must depend only on that text: a detector that
        # has already analyzed every sample (in reverse order, then each
        # earlier one again) must agree with a fresh instance. Spans must
        # also index into exactly the string passed in.
        texts = self.all_texts()
        expected = {text: self.span_tuples(self.make_detector().detect(text)) for text in texts}
        warmed = self.make_detector()
        for text in reversed(texts):
            warmed.detect(text)
        for text in texts:
            probe = "".join(text)  # equal content, possibly a different object
            spans = self.span_tuples(warmed.detect(probe))
            self.assertEqual(spans, expected[text])  # type: ignore[attr-defined]
            for start, end, _category in spans:
                self.assertEqual(probe[start:end], text[start:end])  # type: ignore[attr-defined]

    def test_handles_empty_string(self) -> None:
        self.assertEqual(list(self.make_detector().detect("")), [])  # type: ignore[attr-defined]

    def test_engine_accepts_its_spans(self) -> None:
        # ``run_detector`` is the engine's own guard: span validation,
        # canonical categories, and the per-call span limit.
        detector = self.make_detector()
        for text in self.all_texts():
            validated = run_detector(detector, text)
            self.assertEqual(  # type: ignore[attr-defined]
                [(span.start, span.end, span.category) for span in validated],
                self.span_tuples(detector.detect(text)),
            )
