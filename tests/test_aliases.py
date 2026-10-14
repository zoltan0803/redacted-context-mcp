from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from redacted_context_mcp import config as config_module
from redacted_context_mcp import core, server
from redacted_context_mcp.config import load_config
from redacted_context_mcp.defaults import PLACEHOLDER_RE
from redacted_context_mcp.models import AliasGroup
from redacted_context_mcp.redaction import Redactor
from redacted_context_mcp.rendering import truncate_redacted
from redacted_context_mcp.retrieval import passages, tokens
from tests.fixtures import FakeDetector


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}
SALT = "alias-test-salt"

BASE_CONFIG = """[redaction]
{salt}organizations = ["Example Lantern Labs"]
people = ["Avery Example", "Morgan Sample"]
terms = ["PROJECT-LANTERN-042"]
allow = ["Python"]
"""
ALIASES = """
[redaction.aliases]
"Avery Example" = ["Avery", "avery@example.com"]
"""
STAKEHOLDERS = "# Stakeholders\n\nAvery Example is Product owner for PROJECT-LANTERN-042.\n"
EMAIL = "Hi team,\n\nThe notes are attached; reach me at avery@example.com.\n\nThank you,\nAvery\n"
# Raw values that must never reach output, errors, resources, or paths.
RAW_VALUES = ("Avery", "avery", "example.com", "Morgan", "Sample", "Lantern", "lanternlead")
LINKED_RE = r"\[{category}_{entity}\.[0-9a-f]{{8}}\]"


def write_config(root: Path, aliases: str = ALIASES, *, salt: str | None = SALT) -> Path:
    path = root / ".agent-context-redactor.toml"
    salt_line = f'salt = "{salt}"\n' if salt else ""
    path.write_text(BASE_CONFIG.format(salt=salt_line) + aliases, encoding="utf-8")
    return path


def write_corpus(root: Path) -> None:
    # LF on every platform, so CLI output round-trips through text-mode pipes.
    (root / "stakeholders.md").write_text(STAKEHOLDERS, encoding="utf-8", newline="\n")
    (root / "email.md").write_text(EMAIL, encoding="utf-8", newline="\n")


def pre_feature_digest(salt: str, category: str, normalized: str) -> str:
    """The placeholder hex exactly as computed before alias groups existed."""
    return hmac.new(salt.encode("utf-8"), f"{category}:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]


class IsolatedEnvironment(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.state = tempfile.TemporaryDirectory()
        self.addCleanup(self.state.cleanup)
        environment = patch.dict(os.environ, {
            "REDACTED_CONTEXT_SALT": "",
            "REDACTED_CONTEXT_TERMS": "",
            "REDACTED_CONTEXT_DETECTOR_PROFILE": "",
            "REDACTED_CONTEXT_STATE_DIR": self.state.name,
        })
        environment.start()
        self.addCleanup(environment.stop)

    def load(self, aliases: str = ALIASES, *, salt: str | None = SALT):
        return load_config(self.root, write_config(self.root, aliases, salt=salt))

    def redactor(self, aliases: str = ALIASES, *, salt: str | None = SALT, mode: str = "strict", **kwargs: Any) -> Redactor:
        return Redactor(self.load(aliases, salt=salt), mode=mode, **kwargs)

    def assert_no_raw_values(self, text: str) -> None:
        for raw in RAW_VALUES:
            self.assertNotIn(raw.casefold(), text.casefold())


class AliasConfigTest(IsolatedEnvironment):
    def test_group_takes_the_category_of_its_canonical_value(self) -> None:
        config = self.load(ALIASES + '"Example Lantern Labs" = ["ELL", "Lantern Labs"]\n')
        self.assertEqual(
            config.alias_groups,
            (
                AliasGroup("PERSON", "Avery Example", ("Avery", "avery@example.com")),
                AliasGroup("ORG", "Example Lantern Labs", ("ELL", "Lantern Labs")),
            ),
        )

    def test_invalid_alias_groups_fail_closed_with_neutral_messages(self) -> None:
        cases = {
            "canonical not configured": ('"Avery Q. Example" = ["Avery"]\n', "must also be a configured"),
            "alias in two groups": (
                '"Avery Example" = ["Avery"]\n"Morgan Sample" = ["Morgan", "avery"]\n',
                "Alias group 2 repeats an alias of alias group 1.",
            ),
            "alias is another canonical": (
                '"Avery Example" = ["Morgan Sample"]\n"Morgan Sample" = ["Morgan"]\n',
                "Alias group 1 lists the canonical value of alias group 2 as an alias.",
            ),
            "alias is its own canonical": (
                '"Avery Example" = ["Avery", "avery  EXAMPLE"]\n',
                "Alias group 1 lists its canonical value as an alias.",
            ),
            "repeated canonical": (
                '"Avery Example" = ["Avery"]\n"avery example" = ["AE"]\n',
                "Alias group 2 repeats the canonical value of alias group 1.",
            ),
            "allow-listed alias": ('"Avery Example" = ["Python"]\n', "on the allow list"),
            "empty list": ('"Avery Example" = []\n', "Alias group 1 must map"),
            "blank alias": ('"Avery Example" = ["Avery", "  "]\n', "Alias group 1 must map"),
            "non-string alias": ('"Avery Example" = ["Avery", 42]\n', "Alias group 1 must map"),
            "nested table": ('"Avery Example" = { first = "Avery" }\n', "Alias group 1 must map"),
            "reserved word": ('"Avery Example" = ["Email"]\n', "reserved placeholder word"),
            "too long": (f'"Avery Example" = ["{"a" * 257}"]\n', "over 256 characters or 16 words"),
            "too many words": (f'"Avery Example" = ["{" ".join(["word"] * 17)}"]\n', "over 256 characters or 16 words"),
            "too many aliases": (
                '"Avery Example" = [' + ", ".join(f'"avery{index}"' for index in range(65)) + "]\n",
                "more than 64 aliases",
            ),
        }
        for name, (groups, expected) in cases.items():
            with self.subTest(name):
                with self.assertRaises(SystemExit) as raised:
                    self.load("\n[redaction.aliases]\n" + groups)
                message = str(raised.exception)
                self.assertIn(expected, message)
                self.assert_no_raw_values(message)

    def test_aliases_must_be_a_table(self) -> None:
        path = self.root / ".agent-context-redactor.toml"
        path.write_text(BASE_CONFIG.format(salt="") + 'aliases = ["Avery"]\n', encoding="utf-8")
        with self.assertRaises(SystemExit) as raised:
            load_config(self.root, path)
        self.assertIn("Expected [redaction.aliases]", str(raised.exception))
        self.assert_no_raw_values(str(raised.exception))

    def test_canonical_value_claimed_by_a_built_in_detector_is_refused(self) -> None:
        path = self.root / ".agent-context-redactor.toml"
        path.write_text(
            '[redaction]\nterms = ["avery@example.com"]\n\n[redaction.aliases]\n"avery@example.com" = ["Avery"]\n',
            encoding="utf-8",
        )
        with self.assertRaises(SystemExit) as raised:
            load_config(self.root, path)
        self.assertIn("a built-in detector redacts the canonical value", str(raised.exception))
        self.assert_no_raw_values(str(raised.exception))

    def test_form_suffix_clash_within_a_group_is_refused(self) -> None:
        with patch.object(config_module, "alias_form_suffix", return_value="00000000"):
            with self.assertRaises(SystemExit) as raised:
                self.load()
        self.assertIn("Alias group 1 has two aliases with the same form suffix", str(raised.exception))
        self.assert_no_raw_values(str(raised.exception))


class AliasRedactionTest(IsolatedEnvironment):
    def entity(self, salt: str = SALT) -> str:
        return pre_feature_digest(salt, "PERSON", "avery example")

    def test_two_files_share_one_entity_hex(self) -> None:
        redactor = self.redactor()
        stakeholders = redactor.redact(STAKEHOLDERS)
        email = redactor.redact(EMAIL)
        entity = self.entity()
        self.assertIn(f"[PERSON_{entity}] is", stakeholders)
        self.assertRegex(email, LINKED_RE.format(category="EMAIL", entity=entity))
        self.assertRegex(email, r"you,\n" + LINKED_RE.format(category="PERSON", entity=entity))
        self.assert_no_raw_values(stakeholders + email)

    def test_canonical_placeholder_is_byte_identical_to_pre_feature_output(self) -> None:
        with_aliases = self.redactor().redact(STAKEHOLDERS)
        without_aliases = self.redactor(aliases="").redact(STAKEHOLDERS)
        self.assertEqual(with_aliases, without_aliases)
        self.assertIn(f"[PERSON_{pre_feature_digest(SALT, 'PERSON', 'avery example')}]", with_aliases)

    def test_text_without_declared_forms_is_unchanged(self) -> None:
        text = "Morgan Sample asked Example Lantern Labs about PROJECT-LANTERN-042 at morgan@example.org."
        self.assertEqual(self.redactor().redact(text), self.redactor(aliases="").redact(text))

    def test_links_are_stable_for_a_salt_and_differ_across_salts(self) -> None:
        first = self.redactor().redact(EMAIL)
        self.assertEqual(first, self.redactor().redact(EMAIL))
        other = self.redactor(salt="another-salt").redact(EMAIL)
        self.assertRegex(other, LINKED_RE.format(category="PERSON", entity=self.entity("another-salt")))
        first_ids = set(re.findall(r"[0-9a-f]{8,}", first))
        other_ids = set(re.findall(r"[0-9a-f]{8,}", other))
        self.assertFalse(first_ids & other_ids)

    def test_email_alias_keeps_its_email_category(self) -> None:
        redacted = self.redactor().redact("write to AVERY@example.com.")
        self.assertRegex(redacted, "^write to " + LINKED_RE.format(category="EMAIL", entity=self.entity()) + r"\.$")

    def test_declared_alias_is_redacted_even_when_no_detector_would_catch_it(self) -> None:
        aliases = '\n[redaction.aliases]\n"Avery Example" = ["lanternlead"]\n'
        text = "ping lanternlead about it"
        self.assertEqual(self.redactor(aliases="", mode="balanced").redact(text), text)
        redacted = self.redactor(aliases, mode="balanced").redact(text)
        self.assertRegex(redacted, "^ping " + LINKED_RE.format(category="PERSON", entity=self.entity()) + " about it$")

    def test_lowercase_alias_in_prose_gets_the_linked_placeholder(self) -> None:
        redactor = self.redactor()
        signed = redactor.redact("thank you, Avery")
        prose = redactor.redact("avery will follow up")
        placeholder = PLACEHOLDER_RE.fullmatch(signed[len("thank you, "):]).group(0)
        self.assertEqual(prose, f"{placeholder} will follow up")
        self.assertIn(f"_{self.entity()}.", placeholder)

    def test_longest_match_wins_and_never_splits_the_canonical_value(self) -> None:
        detector = FakeDetector({"Avery": "PERSON", "Example": "ENTITY"})
        for redactor in (self.redactor(), self.redactor(detectors=(detector,))):
            with self.subTest(detectors=bool(redactor.detectors)):
                redacted = redactor.redact("Avery Example met Avery.")
                entity = self.entity()
                self.assertRegex(
                    redacted,
                    rf"^\[PERSON_{entity}\] met " + LINKED_RE.format(category="PERSON", entity=entity) + r"\.$",
                )

    def test_plugged_detector_nomination_gets_the_linked_form(self) -> None:
        detector = FakeDetector({"Avery": "ENTITY"})
        redacted = self.redactor(detectors=(detector,)).redact("ref Avery42 closed")
        self.assertRegex(redacted, "^ref " + LINKED_RE.format(category="ENTITY", entity=self.entity()) + "42 closed$")

    def test_path_redaction_keeps_linked_placeholders_whole(self) -> None:
        redactor = self.redactor()
        redacted = redactor.redact_path("notes/avery-draft.md")
        self.assertRegex(redacted, "^notes/" + LINKED_RE.format(category="PERSON", entity=self.entity()) + "-draft.md$")
        self.assertEqual(redactor.redact_path("notes/Avery Example.md"), f"notes/[PERSON_{self.entity()}].md")

    def test_truncation_and_passages_never_split_a_linked_placeholder(self) -> None:
        redacted = self.redactor().redact("x" * 10 + " Avery " + "y" * 10)
        placeholder = PLACEHOLDER_RE.search(redacted)
        self.assertIn(".", placeholder.group(0))
        for cut in range(placeholder.start() + 1, placeholder.end()):
            self.assertEqual(truncate_redacted(redacted, cut), redacted[: placeholder.start()] + "\n[TRUNCATED]\n")
        long_line = (redacted + " ") * 200
        chunks = [chunk for _start, _end, chunk in passages(long_line)]
        self.assertGreater(len(chunks), 1)
        self.assertEqual(sum(len(PLACEHOLDER_RE.findall(chunk)) for chunk in chunks), 200)
        self.assertIn(placeholder.group(0).casefold(), tokens(redacted))

    def test_existing_linked_placeholders_in_source_text_are_kept(self) -> None:
        linked = f"[PERSON_{self.entity()}.0123abcd]"
        self.assertEqual(self.redactor().redact(f"see {linked} here"), f"see {linked} here")

    def test_search_prefilter_is_skipped_for_linked_placeholder_fragments(self) -> None:
        entity = self.entity()
        for query in (f"{entity}.0123abcd", f"{entity[-4:]}.01", ".0123", entity):
            with self.subTest(query=query):
                self.assertFalse(core.can_use_raw_search_prefilter(query, regex=False, ignore_case=True))
        for query in ("policy.md", "1.2.3", "notes"):
            with self.subTest(query=query):
                self.assertTrue(core.can_use_raw_search_prefilter(query, regex=False, ignore_case=False))

    def test_documents_redacted_before_the_group_still_rehydrate(self) -> None:
        write_corpus(self.root)
        old = self.redactor(aliases="").redact(STAKEHOLDERS + EMAIL)
        redactor = self.redactor()
        self.assertNotEqual(old, redactor.redact(STAKEHOLDERS + EMAIL))
        replacements = core.build_rehydration_map(core.RedactedContext(self.root, redactor.config), redactor)
        restored = core.rehydrate_text(old, replacements)
        # The heading's ENTITY restores to the spelling first seen in the
        # scan, the file name `stakeholders.md`; every alias form is exact.
        self.assertEqual(restored, (STAKEHOLDERS + EMAIL).replace("# Stakeholders", "# stakeholders"))
        self.assertEqual(core.unresolved_rehydration_tokens(restored), [])

    def test_unresolved_linked_placeholders_are_reported(self) -> None:
        unknown = f"[PERSON_{self.entity()}.deadbeef]"
        self.assertEqual(core.unresolved_rehydration_tokens(f"Hi {unknown}."), [unknown])
        self.assertEqual(core.rehydrate_text(f"Hi {unknown}.", {}), f"Hi {unknown}.")

    def test_audit_and_doctor_report_counts_only(self) -> None:
        redactor = self.redactor()
        ctx = core.RedactedContext(self.root, redactor.config)
        checks = core.audit_checks(ctx, redactor)
        check = next(check for check in checks if check["name"] == "alias groups")
        self.assertEqual(check["status"], "PASS")
        self.assertEqual(check["detail"], "1 groups, 2 aliases, 0 forms not redacted as one linked placeholder on their own")
        self.assert_no_raw_values(json.dumps(checks))
        self.assertNotIn("alias groups", json.dumps(core.audit_checks(ctx, self.redactor(aliases=""))))


class AliasCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "kb"
        self.root.mkdir()
        self.state = self.base / "state"
        write_config(self.root, salt=None)
        write_corpus(self.root)

    def run_cli(self, *args: str, state: Path | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", "redacted_context_mcp.core", "--root", str(self.root), *args],
            text=True,
            capture_output=True,
            check=False,
            cwd=PROJECT_ROOT,
            env={**ENV, "REDACTED_CONTEXT_STATE_DIR": str(state or self.state)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for raw in ("Avery", "avery", "example.com"):
            self.assertNotIn(raw, result.stderr)
        return result

    def test_rehydrate_restores_each_exact_form(self) -> None:
        redacted = self.run_cli("bundle", "stakeholders.md", "email.md").stdout
        self.assertNotIn("Avery", redacted)
        self.assertEqual(len(re.findall(r"\.[0-9a-f]{8}\]", redacted)), 2)
        redacted_file = self.base / "redacted.md"
        redacted_file.write_text(redacted, encoding="utf-8", newline="\n")

        restored = self.run_cli("rehydrate", str(redacted_file), "--allow-raw-output").stdout

        self.assertIn("Avery Example is Product owner", restored)
        self.assertIn("reach me at avery@example.com.", restored)
        self.assertIn("Thank you,\nAvery\n", restored)
        self.assertIsNone(PLACEHOLDER_RE.search(restored))

    def test_links_survive_restarts_and_change_with_the_salt(self) -> None:
        first = self.run_cli("read", "email.md").stdout
        self.assertEqual(first, self.run_cli("read", "email.md").stdout)
        other = self.run_cli("read", "email.md", state=self.base / "other-state").stdout
        self.assertNotEqual(first, other)
        self.assertEqual(len(re.findall(r"_([0-9a-f]{32})\.", other)), 2)

    def test_patterns_detector_nomination_gets_the_linked_form(self) -> None:
        rules = self.base / "rules.toml"
        rules.write_text('[[patterns]]\ncategory = "ENTITY"\nregex = "Avery(?=42)"\n', encoding="utf-8")
        (self.root / "ticket.md").write_text("Ticket ref Avery42 closed.\n", encoding="utf-8")
        output = self.run_cli("--detector", f"patterns={rules}", "bundle", "stakeholders.md", "ticket.md").stdout
        entity = re.search(r"\[PERSON_([0-9a-f]{32})\] is", output).group(1)
        self.assertRegex(output, "ref " + LINKED_RE.format(category="ENTITY", entity=entity) + "42 closed")

    def test_doctor_reports_alias_counts(self) -> None:
        doctor = self.run_cli("doctor").stdout
        self.assertIn("alias_groups: 1\n", doctor)
        self.assertIn("aliases: 2\n", doctor)
        self.assertNotIn("Avery", doctor)


class AliasMcpStdioTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / "kb"
        self.root.mkdir()
        self.state = Path(self.tmp.name).resolve() / "state"
        write_config(self.root, salt=None)
        write_corpus(self.root)
        self.proc = subprocess.Popen(
            [
                sys.executable, "-m", "redacted_context_mcp.server", "--root", str(self.root),
                "--enable-writes", "--write-subdir", "incoming",
            ],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PROJECT_ROOT,
            env={**ENV, "REDACTED_CONTEXT_STATE_DIR": str(self.state)},
        )
        self.addCleanup(self.stop)
        self.next_id = 1
        self.transcript: list[str] = []

    def stop(self) -> None:
        assert self.proc.stdin is not None and self.proc.stdout is not None and self.proc.stderr is not None
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        stderr = self.proc.stderr.read()
        self.proc.stdout.close()
        self.proc.stderr.close()
        for raw in ("Avery", "avery", "example.com"):
            self.assertNotIn(raw, stderr)

    def rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        self.next_id += 1
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        self.assertTrue(line, "MCP server closed stdout")
        self.transcript.append(line)
        response = json.loads(line)
        self.assertNotIn("error", response)
        return response["result"]

    def call(self, name: str, arguments: dict[str, Any]) -> tuple[bool, str]:
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        return result["isError"], result["content"][0]["text"]

    def assert_transcript_has_no_raw_values(self) -> None:
        transcript = "".join(self.transcript)
        for raw in ("Avery", "avery", "example.com"):
            self.assertNotIn(raw, transcript)

    def placeholders(self) -> tuple[str, str, str]:
        _error, stakeholders = self.call("redctx_read", {"path": "stakeholders.md"})
        _error, email = self.call("redctx_read", {"path": "email.md"})
        canonical = re.search(r"\[PERSON_[0-9a-f]{32}\](?= is)", stakeholders).group(0)
        entity = canonical[len("[PERSON_"):-1]
        email_form = re.search(LINKED_RE.format(category="EMAIL", entity=entity), email).group(0)
        name_form = re.search(LINKED_RE.format(category="PERSON", entity=entity), email).group(0)
        return canonical, email_form, name_form

    def test_submit_doc_restores_exact_forms_and_passes_the_round_trip_check(self) -> None:
        canonical, email_form, name_form = self.placeholders()
        is_error, summary = self.call(
            "redctx_submit_doc",
            {
                "target_path": f"drafts/{name_form}-summary.md",
                "text": f"Summary for {canonical}:\nWrite to {email_form} or ask {name_form} directly.\n",
            },
        )
        self.assertFalse(is_error, summary)
        self.assertIn("replacements: 4", summary)
        written = (self.root / "incoming" / "drafts" / "Avery-summary.md").read_text(encoding="utf-8")
        self.assertEqual(written, "Summary for Avery Example:\nWrite to avery@example.com or ask Avery directly.\n")
        self.assert_transcript_has_no_raw_values()

    def test_submit_doc_refuses_unresolvable_linked_placeholders(self) -> None:
        canonical, _email_form, _name_form = self.placeholders()
        entity = canonical[len("[PERSON_"):-1]
        for token in (f"[PERSON_{entity}.deadbeef]", f"[EMAIL_{'0' * 32}.0123abcd]"):
            with self.subTest(token=token):
                is_error, message = self.call("redctx_submit_doc", {"target_path": "drafts/x.md", "text": f"Hi {token}."})
                self.assertTrue(is_error)
                self.assertIn(f"Unresolved redaction token(s) in text: {token}.", message)
        self.assertFalse((self.root / "incoming").exists())

    def test_search_finds_every_form_by_entity_prefix(self) -> None:
        canonical, email_form, name_form = self.placeholders()
        entity = canonical[len("[PERSON_"):-1]
        _error, by_prefix = self.call("redctx_search", {"query": f"[PERSON_{entity}"})
        self.assertIn(f"{canonical} is ", by_prefix)
        self.assertIn(name_form, by_prefix)
        self.assertNotIn(email_form, by_prefix)
        _error, by_entity = self.call("redctx_search", {"query": entity})
        for placeholder in (canonical, email_form, name_form):
            self.assertIn(placeholder, by_entity)
        _error, by_form = self.call("redctx_search", {"query": name_form})
        self.assertEqual(len(by_form.splitlines()), 1)
        _error, retrieved = self.call("redctx_retrieve", {"query": name_form})
        self.assertIn(name_form, retrieved)
        self.assert_transcript_has_no_raw_values()

    def test_resources_serve_linked_placeholders_without_raw_values(self) -> None:
        resources = self.rpc("resources/list", {})["resources"]
        texts = [self.rpc("resources/read", {"uri": resource["uri"]})["contents"][0]["text"] for resource in resources]
        self.assertTrue(any(re.search(r"\[EMAIL_[0-9a-f]{32}\.[0-9a-f]{8}\]", text) for text in texts))
        self.assertNotIn(".agent-context-redactor.toml", json.dumps(resources))
        self.assert_transcript_has_no_raw_values()


class AliasLiveReloadTest(IsolatedEnvironment):
    def setUp(self) -> None:
        super().setUp()
        self.config = write_config(self.root, aliases="")
        write_corpus(self.root)
        self.mcp = server.RedactedContextMcp(root=self.root, config_path=None, mode="balanced", include_private=False)
        self.uri = server.resource_uri(self.mcp.ctx.path_id("email.md"))

    def rewrite(self, aliases: str) -> None:
        write_config(self.root, aliases)
        # A same-size rewrite can land within one timestamp tick.
        stat = self.config.stat()
        os.utime(self.config, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))

    def read(self) -> str:
        return self.mcp.read_resource({"uri": self.uri})["contents"][0]["text"]

    def test_reload_adds_and_removes_alias_groups(self) -> None:
        entity = pre_feature_digest(SALT, "PERSON", "avery example")
        unlinked = self.read()
        self.assertNotIn(entity, unlinked)
        self.rewrite(ALIASES)
        linked = self.read()
        self.assertRegex(linked, LINKED_RE.format(category="PERSON", entity=entity))
        self.assertRegex(linked, LINKED_RE.format(category="EMAIL", entity=entity))
        self.rewrite("")
        self.assertEqual(self.read(), unlinked)

    def test_invalid_alias_config_blocks_access_without_echoing_values(self) -> None:
        self.read()
        self.rewrite('\n[redaction.aliases]\n"Avery Q. Example" = ["Avery"]\n')
        result = self.mcp.call_tool("redctx_read", {"path": "email.md"})
        self.assertTrue(result["isError"])
        self.assertIn("Context access is blocked", result["content"][0]["text"])
        self.assert_no_raw_values(json.dumps(result))
        self.rewrite(ALIASES)
        self.assertFalse(self.mcp.call_tool("redctx_read", {"path": "email.md"})["isError"])


class AliasDiscoverUpdateTest(IsolatedEnvironment):
    ALIAS_BLOCK = (
        "[redaction.aliases]  # who is who\n"
        '"Avery Example" = ["Avery", "avery@example.com"]\n'
        'people = ["Morgan"]\n'
    )

    def merged(self, existing: str) -> str:
        return core.merge_discovery_toml(
            existing,
            core.DiscoveryResult(people=("Morgan Sample",), terms=("PROJECT-LANTERN-042",)),
        )

    def test_merge_preserves_the_aliases_table(self) -> None:
        existing = '[redaction]\npeople = ["Avery Example"]\n\n' + self.ALIAS_BLOCK
        merged = self.merged(existing)
        self.assertTrue(merged.endswith(self.ALIAS_BLOCK), merged)
        self.assertIn('"Morgan Sample"', merged.split("[redaction.aliases]")[0])
        path = self.root / ".agent-context-redactor.toml"
        path.write_text(merged.replace('people = ["Morgan"]\n', ""), encoding="utf-8")
        self.assertEqual(load_config(self.root, path).alias_groups[0].aliases, ("Avery", "avery@example.com"))

    def test_merge_adds_a_redaction_table_beside_a_lone_aliases_table(self) -> None:
        block = '[redaction.aliases]\n"Morgan Sample" = ["Morgan"]\n'
        merged = self.merged(block)
        self.assertTrue(merged.startswith("[redaction]\n"), merged)
        self.assertTrue(merged.endswith(block), merged)
        path = self.root / ".agent-context-redactor.toml"
        path.write_text(merged, encoding="utf-8")
        config = load_config(self.root, path)
        self.assertEqual(config.alias_groups, (AliasGroup("PERSON", "Morgan Sample", ("Morgan",)),))


if __name__ == "__main__":
    unittest.main()
