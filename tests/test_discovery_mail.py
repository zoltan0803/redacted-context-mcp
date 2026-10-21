"""Mail discovery: `discover --source mail` and `discover-update --source mail` over synthetic mailboxes."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core
from redacted_context_mcp.config import load_config
from redacted_context_mcp.discovery import mail_header_aliases
from redacted_context_mcp.mail import GLOB_MESSAGE, UNKNOWN_MAILBOX_MESSAGE
from tests import mail_fixtures as mf
from tests.test_discovery import FakeOllamaResponse

URLOPEN = "redacted_context_mcp.discovery.urllib.request.urlopen"
SHARED_ADDRESS = "shared@example.test"
# What the fake model answers for every message. "Invented Person" never
# occurs in the mail, so source filtering must drop it.
MODEL_OUTPUT = {
    "clients": ["Northwind Traders"],
    "organizations": [],
    "people": ["Invented Person"],
    "terms": ["Project Bluefin"],
    "allow": [],
    "aliases": {},
}


def inbox_messages() -> list[bytes]:
    return [
        mf.message(
            message_id="<kickoff@example.test>",
            sender=f"{mf.AVERY} <{mf.AVERY_ADDRESS}>",
            to=f"{mf.JORDAN} <{mf.JORDAN_ADDRESS}>",
            subject="Project Bluefin kickoff",
            date="Thu, 01 Oct 2026 10:00:00 +0000",
            body="Hello,\nThe Project Bluefin rollout for Northwind Traders starts Monday.\n",
        ),
        mf.message(
            message_id="<reply@example.test>",
            sender=f'"Sample, Jordan" <{mf.JORDAN_ADDRESS}>',
            to=f"{mf.AVERY} <{mf.AVERY_ADDRESS}>",
            subject="Re: kickoff",
            date="Sat, 03 Oct 2026 10:00:00 +0000",
            headers=(("Cc", f'"Casey Northfield" <{SHARED_ADDRESS}>'),),
            body="Northwind Traders confirmed the date.\n\nOn Thu, someone wrote:\n> Project Bluefin rollout\n",
        ),
        mf.message(
            message_id="<status@example.test>",
            sender=f"Riley Shared <{SHARED_ADDRESS}>",
            to=f"{mf.AVERY} <{mf.AVERY_ADDRESS}>",
            subject="Status",
            date="Mon, 05 Oct 2026 10:00:00 +0000",
            body="Status update: nothing new.\n",
        ),
    ]


def archive_messages() -> dict[str, bytes]:
    return {
        "1.host": mf.message(
            message_id="<archive-1@example.test>",
            sender="Morgan Archive <morgan@example.net>",
            to=f"{mf.AVERY} <{mf.AVERY_ADDRESS}>",
            subject="Old note",
            date="Fri, 02 Oct 2026 10:00:00 +0000",
            body="Archive note about Kestrel Holdings.\n",
        ),
        "2.host": mf.message(
            message_id="<archive-2@example.test>",
            sender="Morgan Archive <morgan@example.net>",
            to=f"{mf.AVERY} <{mf.AVERY_ADDRESS}>",
            subject="Second note",
            date="Sun, 04 Oct 2026 10:00:00 +0000",
            body="Another archive note.\n",
        ),
    }


class FakeOllama:
    """Records each prompt's label and text and answers ``MODEL_OUTPUT``."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, request: object, timeout: float) -> FakeOllamaResponse:
        del timeout
        prompt = json.loads(request.data.decode("utf-8"))["prompt"]  # type: ignore[attr-defined]
        label = re.search(r"^Path: (.*)$", prompt, re.MULTILINE).group(1)  # type: ignore[union-attr]
        self.calls.append((label, prompt.split("Text:\n", 1)[1]))
        return FakeOllamaResponse({"response": json.dumps(MODEL_OUTPUT)})


class MailDiscoveryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.mail_tmp = tempfile.TemporaryDirectory()
        self.state_tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.mail_dir = Path(self.mail_tmp.name).resolve()
        self.env = patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": self.state_tmp.name})
        self.env.start()
        self.inbox = mf.write_mbox(self.mail_dir / "inbox.mbox", inbox_messages())
        self.archive = mf.write_maildir(self.mail_dir / "Maildir", cur=archive_messages())
        self.config = self.root / core.LOCAL_CONFIG
        self.config.write_text(
            '[redaction]\nsalt = "mail-discovery-salt"\n\n'
            f"[mail.sources.inbox]\npath = '{self.inbox.as_posix()}'\nformat = \"mbox\"\n\n"
            f"[mail.sources.archive]\npath = '{self.archive.as_posix()}'\nformat = \"maildir\"\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.env.stop()
        self.tmp.cleanup()
        self.mail_tmp.cleanup()
        self.state_tmp.cleanup()

    def run_main(self, *argv: str, fake: FakeOllama | None = None) -> tuple[int, str, FakeOllama]:
        fake = fake or FakeOllama()
        output = io.StringIO()
        with patch(URLOPEN, side_effect=fake), contextlib.redirect_stdout(output):
            status = core.main(["--root", str(self.root), *argv])
        return status, output.getvalue(), fake

    def discover_json(self, *argv: str) -> tuple[dict[str, object], FakeOllama]:
        _status, output, fake = self.run_main("discover", "--source", "mail", "--format", "json", *argv)
        return json.loads(output), fake

    def draft(self, *argv: str) -> tuple[str, FakeOllama]:
        _status, _output, fake = self.run_main("discover", "--source", "mail", "--output", "draft.toml", *argv)
        return (self.root / "draft.toml").read_text(encoding="utf-8"), fake

    def refs(self) -> list[str]:
        _payload, fake = self.discover_json()
        return [label.rsplit("/", 1)[1] for label, _text in fake.calls]


class DiscoverMailScopeTest(MailDiscoveryTestCase):
    def test_labels_are_neutral_alias_and_ref(self) -> None:
        _payload, fake = self.discover_json()
        self.assertEqual(len(fake.calls), 5)
        for label, _text in fake.calls:
            self.assertRegex(label, r"^mail:(inbox|archive)/@m_[0-9a-f]{12}$")
        prompts = "".join(text for _label, text in fake.calls)
        self.assertNotIn(self.mail_dir.as_posix(), prompts)
        self.assertNotIn("Maildir", prompts)

    def test_alias_scope_reads_only_that_mailbox(self) -> None:
        _payload, fake = self.discover_json("archive")
        self.assertEqual(len(fake.calls), 2)
        self.assertTrue(all(label.startswith("mail:archive/") for label, _text in fake.calls))

    def test_ref_scope_reads_one_message(self) -> None:
        ref = self.refs()[2]
        payload, fake = self.discover_json(ref)
        self.assertEqual([label.rsplit("/", 1)[1] for label, _text in fake.calls], [ref])
        self.assertEqual(payload["messages"], 1)

    def test_unknown_alias_path_and_glob_are_refused_before_any_model_call(self) -> None:
        for argv, message in (
            (("nope",), UNKNOWN_MAILBOX_MESSAGE),
            (("notes.md",), UNKNOWN_MAILBOX_MESSAGE),
            (("inbox", "--glob", "*.md"), GLOB_MESSAGE),
        ):
            with self.subTest(argv=argv):
                fake = FakeOllama()
                with self.assertRaises(SystemExit) as caught:
                    self.run_main("discover", "--source", "mail", *argv, fake=fake)
                self.assertEqual(str(caught.exception), message)
                self.assertEqual(fake.calls, [])

    def test_no_configured_mailbox_is_an_unknown_alias(self) -> None:
        self.config.write_text('[redaction]\nsalt = "mail-discovery-salt"\n', encoding="utf-8")
        with self.assertRaises(SystemExit) as caught:
            self.run_main("discover", "--source", "mail")
        self.assertEqual(str(caught.exception), UNKNOWN_MAILBOX_MESSAGE)

    def test_unknown_ref_is_refused(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.run_main("discover", "--source", "mail", "@m_000000000000")
        self.assertEqual(str(caught.exception), core.UNKNOWN_REFERENCE_MESSAGE)

    def test_max_messages_cap_holds_newest_first(self) -> None:
        payload, fake = self.discover_json("--max-messages", "2")
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(payload["messages"], 2)
        self.assertTrue(fake.calls[0][1].startswith("Status\n\n"))
        self.assertTrue(fake.calls[1][1].startswith("Second note\n\n"))
        for value in ("0", "-1"):
            with self.subTest(value=value), self.assertRaises(SystemExit) as caught:
                self.run_main("discover", "--source", "mail", "--max-messages", value)
            self.assertEqual(str(caught.exception), "--max-messages must be at least 1.")

    def test_max_files_does_not_apply_to_mail(self) -> None:
        _payload, fake = self.discover_json("--max-files", "1")
        self.assertEqual(len(fake.calls), 5)

    def test_total_byte_budget_fails_closed(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.run_main("discover", "--source", "mail", "--max-total-raw-bytes", "10")
        self.assertEqual(str(caught.exception), "Total raw byte limit exceeded.")

    def test_messages_are_capped_with_the_truncation_marker(self) -> None:
        _payload, fake = self.discover_json("inbox", "--max-chars-per-file", "12")
        self.assertTrue(all(text.rstrip("\n").endswith("[TRUNCATED DISCOVERY SAMPLE]") for _l, text in fake.calls))
        fake = FakeOllama()
        with self.assertRaises(SystemExit) as caught:
            self.run_main(
                "discover", "--source", "mail", "inbox", "--max-chars-per-file", "12", "--fail-on-truncation",
                fake=fake,
            )
        self.assertRegex(str(caught.exception), r"^Discovery input was truncated: @m_[0-9a-f]{12}$")
        self.assertEqual(fake.calls, [])

    def test_quoted_text_is_not_sent_to_the_model(self) -> None:
        _payload, fake = self.discover_json("inbox")
        reply = next(text for _label, text in fake.calls if text.startswith("Re: kickoff"))
        self.assertNotIn("> Project Bluefin rollout", reply)


class DiscoverMailDraftTest(MailDiscoveryTestCase):
    def test_unsourced_model_values_are_dropped(self) -> None:
        payload, _fake = self.discover_json()
        self.assertEqual(payload["clients"], ["Northwind Traders"])
        self.assertEqual(payload["terms"], ["Project Bluefin"])
        self.assertNotIn("Invented Person", payload["people"])

    def test_header_groups_are_flagged_and_ambiguous_address_is_not_linked(self) -> None:
        payload, _fake = self.discover_json()
        header = payload["header_aliases"]
        self.assertIn(mf.AVERY_ADDRESS, header[mf.AVERY])
        self.assertEqual(header[mf.JORDAN], ["Sample, Jordan", mf.JORDAN_ADDRESS])
        self.assertEqual(header["Morgan Archive"], ["morgan@example.net"])
        self.assertNotIn("Casey Northfield", header)
        self.assertNotIn("Riley Shared", header)
        linked = [alias for aliases in (*header.values(), *payload["aliases"].values()) for alias in aliases]
        self.assertNotIn(SHARED_ADDRESS, linked)
        for name in (mf.AVERY, mf.JORDAN, "Casey Northfield", "Riley Shared", "Morgan Archive"):
            self.assertIn(name, payload["people"])
        self.assertGreaterEqual(payload["dropped_alias_proposals"], 1)

    def test_draft_toml_flags_header_groups_and_loads_as_a_config(self) -> None:
        text, _fake = self.draft()
        header, _sep, rest = text.partition("# Source: ")
        self.assertIn("provider=ollama model=gemma4:e4b source=mail messages=5\n", rest)
        self.assertNotIn(self.mail_dir.as_posix(), text)
        self.assertNotIn("inbox.mbox", text)
        _before, marker, flagged = text.partition("# From mail headers (From/To/Cc), linked without the model")
        self.assertTrue(marker)
        self.assertIn(f'"{mf.JORDAN}" = ["Sample, Jordan", "{mf.JORDAN_ADDRESS}"]', flagged)
        self.assertIn('"Morgan Archive" = ["morgan@example.net"]', flagged)
        self.assertNotIn(SHARED_ADDRESS, text)
        self.assertNotIn("Invented Person", text)

        data = tomllib.loads(text)
        self.assertIn("Northwind Traders", data["redaction"]["clients"])
        self.assertEqual(data["redaction"]["aliases"]["Morgan Archive"], ["morgan@example.net"])
        loaded_root = Path(self.mail_tmp.name) / "loaded"
        loaded_root.mkdir()
        (loaded_root / core.LOCAL_CONFIG).write_text(text, encoding="utf-8")
        config = load_config(loaded_root, None)
        groups = {group.canonical: group.aliases for group in config.alias_groups}
        self.assertEqual(groups[mf.JORDAN], ("Sample, Jordan", mf.JORDAN_ADDRESS))
        self.assertEqual(groups["Morgan Archive"], ("morgan@example.net",))

    def test_raw_discovery_skips_the_header_step(self) -> None:
        payload, _fake = self.discover_json("--raw-discovery")
        self.assertEqual(payload["header_aliases"], {})
        self.assertNotIn(mf.AVERY, payload["people"])
        text, _fake = self.draft("--raw-discovery")
        self.assertNotIn("# From mail headers", text)

    def test_detector_discovery_reads_mail_without_the_model(self) -> None:
        rules = Path(self.mail_tmp.name) / "patterns.toml"
        rules.write_text("[[patterns]]\ncategory = 'ORG'\nregex = 'Kestrel Holdings'\n", encoding="utf-8")
        fake = FakeOllama()
        _status, output, _fake = self.run_main(
            "discover", "--source", "mail", "archive", "--format", "json", "--detector", f"patterns={rules}",
            fake=fake,
        )
        payload = json.loads(output)
        self.assertEqual(fake.calls, [])
        self.assertEqual(payload["organizations"], ["Kestrel Holdings"])
        self.assertEqual(
            payload["header_aliases"],
            {"Morgan Archive": ["morgan@example.net"], mf.AVERY: [mf.AVERY_ADDRESS]},
        )


class DiscoverUpdateMailTest(MailDiscoveryTestCase):
    def test_merges_terms_and_header_people_without_aliases_by_default(self) -> None:
        status, output, fake = self.run_main("discover-update", "--source", "mail", "inbox")
        self.assertEqual(status, 0)
        self.assertEqual(len(fake.calls), 3)
        self.assertIn("documents: 3\n", output)
        merged = self.config.read_text(encoding="utf-8")
        data = tomllib.loads(merged)
        self.assertIn("Northwind Traders", data["redaction"]["clients"])
        self.assertIn("Project Bluefin", data["redaction"]["terms"])
        for name in (mf.AVERY, mf.JORDAN, "Casey Northfield", "Riley Shared"):
            self.assertIn(name, data["redaction"]["people"])
        self.assertNotIn("Invented Person", merged)
        self.assertNotIn("aliases", data["redaction"])
        self.assertEqual(data["redaction"]["salt"], "mail-discovery-salt")
        self.assertIn("inbox", data["mail"]["sources"])

    def test_include_discovered_aliases_merges_header_groups(self) -> None:
        status, output, _fake = self.run_main(
            "discover-update", "--source", "mail", "--include-discovered-aliases", "--max-messages", "3"
        )
        self.assertEqual(status, 0)
        self.assertIn("documents: 3\n", output)
        merged = self.config.read_text(encoding="utf-8")
        aliases = tomllib.loads(merged)["redaction"]["aliases"]
        self.assertIn(mf.AVERY_ADDRESS, aliases[mf.AVERY])
        self.assertEqual(aliases[mf.JORDAN], ["Sample, Jordan", mf.JORDAN_ADDRESS])
        self.assertNotIn(SHARED_ADDRESS, merged.split("[redaction.aliases]", 1)[1])
        counts = json.loads(re.search(r"^alias_counts: (.*)$", output, re.MULTILINE).group(1))  # type: ignore[union-attr]
        self.assertGreaterEqual(counts["dropped"], 1)
        load_config(self.root, None)

    def test_mail_refuses_jsonl_and_merge_only_and_filesystem_refuses_aliases(self) -> None:
        jsonl = self.root / "documents.jsonl"
        jsonl.write_text('{"path":"a.md","text":"Northwind Traders"}\n', encoding="utf-8")
        for argv, message in (
            (("--source", "mail", "--input-jsonl", str(jsonl)), "--source mail cannot be combined with --input-jsonl."),
            (("--source", "mail", "--merge-only"), "--source mail cannot be combined with --merge-only."),
            (("inbox", "--input-jsonl", str(jsonl)), "Mailbox aliases and @m_ refs are accepted only with --source mail."),
            (("--source", "mail", "nope"), UNKNOWN_MAILBOX_MESSAGE),
        ):
            with self.subTest(argv=argv):
                fake = FakeOllama()
                with self.assertRaises(SystemExit) as caught:
                    self.run_main("discover-update", *argv, fake=fake)
                self.assertEqual(str(caught.exception), message)
                self.assertEqual(fake.calls, [])

    def test_oversized_message_fails_naming_only_its_ref(self) -> None:
        fake = FakeOllama()
        before = self.config.read_text(encoding="utf-8")
        with self.assertRaises(SystemExit) as caught:
            self.run_main("discover-update", "--source", "mail", "--max-chars-per-document", "20", fake=fake)
        self.assertRegex(
            str(caught.exception),
            r"^@m_[0-9a-f]{12} exceeds --max-chars-per-document=20; refusing to classify a partial model input\.$",
        )
        self.assertEqual(fake.calls, [])
        self.assertEqual(self.config.read_text(encoding="utf-8"), before)

    def test_total_chars_limit_applies(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.run_main("discover-update", "--source", "mail", "--max-total-chars", "50")
        self.assertEqual(str(caught.exception), "Discovery input exceeds --max-total-chars=50.")


class MailHeaderAliasesTest(unittest.TestCase):
    def test_links_one_name_per_address_and_drops_shared_addresses(self) -> None:
        people, groups, dropped = mail_header_aliases(
            [
                ("Avery Example", "avery@example.com"),
                ('"avery example"', "avery@example.com"),
                ("Sample, Jordan", "jordan@example.org"),
                ("Jordan Sample", "jordan@example.org"),
                ("Casey Northfield", "shared@example.test"),
                ("Riley Shared", "shared@example.test"),
                ("Avery Example", "avery@work.example.net"),
                ("Billing Team", "billing@example.test"),
                ("Jordan", "jo@example.test"),
                ("someone@example.test", "someone@example.test"),
                ("", "nobody@example.test"),
            ]
        )
        self.assertEqual(people, ("Avery Example", "Jordan Sample", "Casey Northfield", "Riley Shared"))
        self.assertEqual(
            groups,
            (
                ("Avery Example", ("avery@example.com", "avery@work.example.net")),
                ("Jordan Sample", ("Sample, Jordan", "jordan@example.org")),
            ),
        )
        self.assertEqual(dropped, 1)

    def test_files_draft_without_header_groups_is_unchanged(self) -> None:
        result = core.DiscoveryResult(people=("Avery Example",), aliases=(("Avery Example", ("Avery",)),))
        self.assertEqual(
            core.format_discovery_toml(result, source_note="provider=ollama model=m root=."),
            "# Generated by redctx discover.\n"
            "# Review before use; this file intentionally contains sensitive terms.\n"
            "# Source: provider=ollama model=m root=.\n"
            "\n"
            "[redaction]\n"
            "clients = []\n"
            "organizations = []\n"
            'people = [\n  "Avery Example"\n]\n'
            "terms = []\n"
            "allow = []\n"
            "\n[redaction.aliases]\n"
            "# Proposed alias groups. Check every link: a wrong one tells the agent that\n"
            "# two different people or organizations are one. Remove any you are unsure of.\n"
            '"Avery Example" = ["Avery"]\n',
        )


if __name__ == "__main__":
    unittest.main()
