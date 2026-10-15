from __future__ import annotations

import unittest

from redacted_context_mcp.defaults import HEADING_LINE_RE
from redacted_context_mcp.models import RedactionConfig
from redacted_context_mcp.paths import path_id
from redacted_context_mcp.redaction import Redactor
from tests.fixtures import FakeDetector


class RedactionBenchmarkTest(unittest.TestCase):
    def test_secret_and_identifier_leak_benchmark(self) -> None:
        raw_values = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",
            "sk-abcdefghijklmnopqrstuvwxyz123456",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "superSecret1234",
            "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
            "123-45-6789",
            "4111 1111 1111 1111",
            "10.12.30.4",
            "550e8400-e29b-41d4-a716-446655440000",
            "private.internal",
        ]
        text = f"""
AWS key: {raw_values[0]}
GitHub token: {raw_values[1]}
OpenAI token: {raw_values[2]}
Authorization: {raw_values[3]}
password = {raw_values[4]}
PEM:
{raw_values[5]}
SSN: {raw_values[6]}
Card: {raw_values[7]}
Host IP: {raw_values[8]}
Trace id: {raw_values[9]}
Domain: {raw_values[10]}
"""
        redacted = Redactor(RedactionConfig(salt="test-salt")).redact(text)

        for raw in raw_values:
            self.assertNotIn(raw, redacted)
        self.assertRegex(redacted, r"\[SECRET_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[SSN_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[CARD_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[IP_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[ID_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[DOMAIN_[0-9a-f]{32}\]")

    def test_placeholders_are_stable_for_same_salt(self) -> None:
        config = RedactionConfig(people=("Alice Example",), salt="same-salt")
        first = Redactor(config).redact("Alice Example met Alice Example.")
        second = Redactor(config).redact("Alice Example met Alice Example.")

        self.assertEqual(first, second)
        self.assertEqual(first.count("[PERSON_"), 2)

    def test_path_ids_are_salted_and_stable(self) -> None:
        rel = "context/Client Alpha notes.md"

        self.assertEqual(path_id(rel, "salt-one"), path_id(rel, "salt-one"))
        self.assertNotEqual(path_id(rel, "salt-one"), path_id(rel, "salt-two"))
        self.assertRegex(path_id(rel, "salt-one"), r"^p_[0-9a-f]{12}$")

    def test_extended_profile_redacts_service_account_identifiers(self) -> None:
        raw = "sp-lighthouse-ingest-prod"
        redacted = Redactor(
            RedactionConfig(salt="test-salt", detector_profile="extended")
        ).redact(f"Use `{raw}` for ingestion.")

        self.assertNotIn(raw, redacted)
        self.assertRegex(redacted, r"\[SERVICE_ACCOUNT_[0-9a-f]{32}\]")


class ProperNameLineBreakTest(unittest.TestCase):
    def test_blank_line_ends_a_proper_name(self) -> None:
        for newline in ("\n", "\r\n", "\r"):
            with self.subTest(newline=repr(newline)):
                redactor = Redactor(RedactionConfig(salt="test-salt"), mode="balanced")
                text = f"Avery Example{newline}{newline}Jordan Sample met here."

                self.assertEqual(
                    redactor.redact(text),
                    f"{redactor.placeholder('PERSON', 'Avery Example')}{newline}{newline}"
                    f"{redactor.placeholder('PERSON', 'Jordan Sample')} met here.",
                )

    def test_whitespace_only_line_ends_a_proper_name(self) -> None:
        redactor = Redactor(RedactionConfig(salt="test-salt"), mode="balanced")

        self.assertEqual(
            redactor.redact("Avery Example\n \t\nJordan Sample"),
            f"{redactor.placeholder('PERSON', 'Avery Example')}\n \t\n"
            f"{redactor.placeholder('PERSON', 'Jordan Sample')}",
        )

    def test_name_wrapped_onto_the_next_line_is_one_placeholder(self) -> None:
        redactor = Redactor(RedactionConfig(salt="test-salt"), mode="balanced")
        placeholder = redactor.placeholder("PERSON", "Avery\nExample")

        self.assertEqual(redactor.redact("We met Avery\nExample today."), f"We met {placeholder} today.")
        self.assertEqual(
            redactor.redact("We met Avery\nExample today.", preserve_line_count=True),
            f"We met {placeholder}\n today.",
        )


class HeadingRedactionTest(unittest.TestCase):
    def test_heading_line_pattern(self) -> None:
        for line in ("# Notes", "###### Notes", "   ## Notes", "##", "## \t", "#\tNotes"):
            with self.subTest(line=line):
                self.assertIsNotNone(HEADING_LINE_RE.fullmatch(line))
        for line in ("#Notes", "####### Notes", "    ## Notes", "\t## Notes", "text ## Notes"):
            with self.subTest(line=line):
                self.assertIsNone(HEADING_LINE_RE.fullmatch(line))
                self.assertEqual(HEADING_LINE_RE.findall(line), [])
        self.assertEqual(HEADING_LINE_RE.findall("a\r## B\r\n# C\nd ## E\n"), ["## B", "# C"])

    def test_generic_heading_words_are_kept_in_both_modes(self) -> None:
        text = "# Project Status Update\n\n## Next Steps\n\n### Open Questions\n\n## Budget\n"
        for mode in ("balanced", "strict"):
            with self.subTest(mode=mode):
                self.assertEqual(Redactor(RedactionConfig(salt="test-salt"), mode=mode).redact(text), text)

    def test_proper_name_does_not_leave_a_heading_line(self) -> None:
        for mode in ("balanced", "strict"):
            with self.subTest(mode=mode):
                redactor = Redactor(RedactionConfig(salt="test-salt"), mode=mode)
                person = redactor.placeholder("PERSON", "Avery Example")

                self.assertEqual(
                    redactor.redact("### Open Questions\nAvery Example joined late.\n"),
                    f"### Open Questions\n{person} joined late.\n",
                )

    def test_names_in_headings_are_still_redacted(self) -> None:
        for mode in ("balanced", "strict"):
            with self.subTest(mode=mode):
                redactor = Redactor(RedactionConfig(salt="test-salt"), mode=mode)
                person = redactor.placeholder("PERSON", "Avery Example")
                codename = redactor.placeholder("PERSON", "Harbor")

                self.assertEqual(redactor.redact("## Avery Example\n"), f"## {person}\n")
                self.assertEqual(redactor.redact("## Contact Avery Example\n"), f"## Contact {person}\n")
                self.assertEqual(redactor.redact("## Project Harbor Rollout\n"), f"## Project {codename} Rollout\n")

    def test_strict_mode_redacts_single_names_in_headings(self) -> None:
        redactor = Redactor(RedactionConfig(salt="test-salt"), mode="strict")
        entity = redactor.placeholder("ENTITY", "Avery")

        self.assertEqual(redactor.redact("## Notes for Avery\n"), f"## Notes for {entity}\n")

    def test_heading_words_stay_redacted_outside_headings(self) -> None:
        redactor = Redactor(RedactionConfig(salt="test-salt"), mode="balanced")
        person = redactor.placeholder("PERSON", "Next Steps")

        self.assertEqual(redactor.redact("#Next Steps\n"), f"#{person}\n")
        self.assertEqual(redactor.redact("    ## Next Steps\n"), f"    ## {person}\n")
        self.assertEqual(redactor.redact("see Next Steps below.\n"), f"see {person} below.\n")

    def test_detectors_still_redact_kept_heading_words(self) -> None:
        config = RedactionConfig(salt="test-salt")
        detector = FakeDetector({"Next Steps": "SENSITIVE", "zorvane": "PERSON"})
        redactor = Redactor(config, mode="balanced", detectors=(detector,))
        expected = Redactor(config)

        self.assertEqual(
            redactor.redact("## Next Steps\n## Contact Avery Example\nask zorvane\n"),
            f"## {expected.placeholder('SENSITIVE', 'Next Steps')}\n"
            f"## Contact {expected.placeholder('PERSON', 'Avery Example')}\n"
            f"ask {expected.placeholder('PERSON', 'zorvane')}\n",
        )


class IdentityLabelTest(unittest.TestCase):
    LABELS = (
        "Attendees",
        "Participant",
        "Stakeholders",
        "Owner",
        "Contact",
        "Authors",
        "Reviewer",
        "Approvers",
        "Speaker",
        "Presenters",
    )

    def test_capitalized_label_is_kept_and_names_after_it_are_redacted(self) -> None:
        for mode in ("balanced", "strict"):
            for label in self.LABELS:
                with self.subTest(mode=mode, label=label):
                    redactor = Redactor(RedactionConfig(salt="test-salt"), mode=mode)
                    avery = redactor.placeholder("PERSON", "Avery")
                    jordan = redactor.placeholder("PERSON", "Jordan")

                    self.assertEqual(redactor.redact(f"{label}: Avery, Jordan\n"), f"{label}: {avery}, {jordan}\n")

    def test_label_keeps_a_multi_word_name_whole(self) -> None:
        for mode in ("balanced", "strict"):
            with self.subTest(mode=mode):
                redactor = Redactor(RedactionConfig(salt="test-salt"), mode=mode)
                person = redactor.placeholder("PERSON", "Avery Example")

                self.assertEqual(redactor.redact("Owner: Avery Example\n"), f"Owner: {person}\n")

    def test_short_names_after_a_label_are_redacted(self) -> None:
        for mode in ("balanced", "strict"):
            for label in ("Attendees", "attendees"):
                with self.subTest(mode=mode, label=label):
                    redactor = Redactor(RedactionConfig(salt="test-salt"), mode=mode)
                    names = ", ".join(redactor.placeholder("PERSON", name) for name in ("Avery", "Kim", "Al"))

                    self.assertEqual(redactor.redact(f"{label}: Avery, Kim, Al\n"), f"{label}: {names}\n")

    def test_label_on_the_next_line_is_not_joined_to_a_name(self) -> None:
        for mode in ("balanced", "strict"):
            with self.subTest(mode=mode):
                redactor = Redactor(RedactionConfig(salt="test-salt"), mode=mode)
                avery = redactor.placeholder("PERSON", "Avery Example")
                kim = redactor.placeholder("PERSON", "Kim")
                jordan = redactor.placeholder("PERSON", "Jordan")

                self.assertEqual(
                    redactor.redact("Attendees: Avery Example, Kim\nOwner: Jordan\n"),
                    f"Attendees: {avery}, {kim}\nOwner: {jordan}\n",
                )
                self.assertEqual(
                    redactor.redact("Owner: Avery Example\n  contacts : Jordan\n"),
                    f"Owner: {avery}\n  contacts : {jordan}\n",
                )

    def test_label_after_other_capitalized_words_is_kept(self) -> None:
        cases = (
            ("Project Owner: Bob\n", "Owner: ", "Bob"),
            ("Primary Contact: Avery Example\n", "Contact: ", "Avery Example"),
            ("Key Stakeholders : Kim\n", "Stakeholders : ", "Kim"),
        )
        for mode in ("balanced", "strict"):
            for text, label, name in cases:
                with self.subTest(mode=mode, text=text):
                    redactor = Redactor(RedactionConfig(salt="test-salt"), mode=mode)
                    redacted = redactor.redact(text)

                    self.assertTrue(redacted.endswith(f"{label}{redactor.placeholder('PERSON', name)}\n"), redacted)

        redactor = Redactor(RedactionConfig(salt="test-salt"), mode="balanced")
        self.assertEqual(
            redactor.redact("Project Owner: Bob\n"),
            f"Project Owner: {redactor.placeholder('PERSON', 'Bob')}\n",
        )

    def test_upper_case_label_survives_strict_mode(self) -> None:
        redactor = Redactor(RedactionConfig(salt="test-salt"), mode="strict")

        self.assertEqual(
            redactor.redact("OWNER: Avery\n"),
            f"OWNER: {redactor.placeholder('PERSON', 'Avery')}\n",
        )

    def test_speaker_labels_are_still_redacted(self) -> None:
        for mode in ("balanced", "strict"):
            with self.subTest(mode=mode):
                redactor = Redactor(RedactionConfig(salt="test-salt"), mode=mode)

                self.assertEqual(
                    redactor.redact("Avery: thanks, all good\n"),
                    f"{redactor.placeholder('PERSON', 'Avery')}: thanks, all good\n",
                )


if __name__ == "__main__":
    unittest.main()
