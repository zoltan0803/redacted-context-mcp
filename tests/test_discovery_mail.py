"""Mail discovery: `discover --source mail` and `discover-update --source mail` over synthetic mailboxes."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import re
import tempfile
import tomllib
import unittest
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core
from redacted_context_mcp.config import load_config
from redacted_context_mcp.discovery import mail_header_aliases
from redacted_context_mcp.mail import GLOB_MESSAGE, UNKNOWN_MAILBOX_MESSAGE, MailSource
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
# A hostile sender pairs a known name with its own address in From, and
# another known name with a victim address in To and Cc.
ATTACKER_ADDRESS = "attacker@evil.example"
VICTIM_ADDRESS = "ceo@victim.example"
CC_ADDRESS = "cc@evil.example"


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


def hostile_message() -> bytes:
    return mf.message(
        message_id="<hostile@example.test>",
        sender=f'"{mf.AVERY}" <{ATTACKER_ADDRESS}>',
        to=f'"{mf.JORDAN}" <{VICTIM_ADDRESS}>',
        subject="Invoice",
        date="Tue, 06 Oct 2026 10:00:00 +0000",
        headers=(("Cc", f'"Morgan Archive" <{CC_ADDRESS}>'),),
        body="Please pay the attached invoice.\n",
    )


def mail_date(offset: dt.timedelta) -> str:
    return format_datetime(dt.datetime.now(dt.timezone.utc) + offset)


class FakeOllama:
    """Records each prompt's label and text and answers ``output`` (default ``MODEL_OUTPUT``)."""

    def __init__(self, output: dict[str, object] | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self.output = MODEL_OUTPUT if output is None else output

    def __call__(self, request: object, timeout: float) -> FakeOllamaResponse:
        del timeout
        prompt = json.loads(request.data.decode("utf-8"))["prompt"]  # type: ignore[attr-defined]
        label = re.search(r"^Path: (.*)$", prompt, re.MULTILINE).group(1)  # type: ignore[union-attr]
        self.calls.append((label, prompt.split("Text:\n", 1)[1]))
        return FakeOllamaResponse({"response": json.dumps(self.output)})


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
        self.write_config()

    def tearDown(self) -> None:
        self.env.stop()
        self.tmp.cleanup()
        self.mail_tmp.cleanup()
        self.state_tmp.cleanup()

    def write_config(self, *, archive_limits: str = "") -> None:
        self.config.write_text(
            '[redaction]\nsalt = "mail-discovery-salt"\n\n'
            f"[mail.sources.inbox]\npath = '{self.inbox.as_posix()}'\nformat = \"mbox\"\n\n"
            f"[mail.sources.archive]\npath = '{self.archive.as_posix()}'\nformat = \"maildir\"\n{archive_limits}",
            encoding="utf-8",
        )

    def add_mbox(self, alias: str, messages: list[bytes], *, under_root: bool = False) -> Path:
        path = mf.write_mbox((self.root if under_root else self.mail_dir) / f"{alias}.mbox", messages)
        with self.config.open("a", encoding="utf-8") as handle:
            handle.write(f"\n[mail.sources.{alias}]\npath = '{path.as_posix()}'\nformat = \"mbox\"\n")
        return path

    def run_main(self, *argv: str, fake: FakeOllama | None = None) -> tuple[int, str, FakeOllama]:
        fake = fake or FakeOllama()
        output = io.StringIO()
        with patch(URLOPEN, side_effect=fake), contextlib.redirect_stdout(output):
            status = core.main(["--root", str(self.root), *argv])
        return status, output.getvalue(), fake

    def discover_json(self, *argv: str, fake: FakeOllama | None = None) -> tuple[dict[str, object], FakeOllama]:
        _status, output, fake = self.run_main("discover", "--source", "mail", "--format", "json", *argv, fake=fake)
        return json.loads(output), fake

    def draft(self, *argv: str, fake: FakeOllama | None = None) -> tuple[str, FakeOllama]:
        _status, _output, fake = self.run_main(
            "discover", "--source", "mail", "--output", "draft.toml", *argv, fake=fake
        )
        return (self.root / "draft.toml").read_text(encoding="utf-8"), fake

    def refs(self) -> list[str]:
        _payload, fake = self.discover_json()
        return [label.rsplit("/", 1)[1] for label, _text in fake.calls]

    def sizes_newest_first(self) -> list[int]:
        summaries, _total = MailSource(load_config(self.root, None)).list_messages(None, limit=50, offset=0)
        return [summary.size for summary in summaries]

    def merged_config(self) -> tuple[str, dict[str, object]]:
        merged = self.config.read_text(encoding="utf-8")
        return merged, tomllib.loads(merged)["redaction"]


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

    def test_alias_and_ref_scope_is_merged_newest_first_without_repeats(self) -> None:
        refs = self.refs()
        _payload, fake = self.discover_json(refs[2], "archive", refs[1])
        self.assertEqual([label.rsplit("/", 1)[1] for label, _text in fake.calls], refs[1:4])

    def test_unknown_alias_path_glob_and_attachment_ref_are_refused_before_any_model_call(self) -> None:
        for argv, message in (
            (("nope",), UNKNOWN_MAILBOX_MESSAGE),
            (("notes.md",), UNKNOWN_MAILBOX_MESSAGE),
            (("inbox", "--glob", "*.md"), GLOB_MESSAGE),
            ((f"{self.refs()[0]}/1",), core.UNKNOWN_REFERENCE_MESSAGE),
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

    def test_total_byte_budget_stops_sampling_before_a_partial_message(self) -> None:
        newest, second = self.sizes_newest_first()[:2]
        payload, fake = self.discover_json("--max-total-raw-bytes", str(newest + second - 1))
        self.assertEqual(payload["messages"], 1)
        self.assertEqual(payload["skipped_messages"], 0)
        self.assertIs(payload["byte_cap_reached"], True)
        self.assertEqual(len(fake.calls), 1)
        self.assertTrue(fake.calls[0][1].startswith("Status\n\n"))

        payload, fake = self.discover_json("--max-total-raw-bytes", "10")
        self.assertEqual((payload["messages"], payload["byte_cap_reached"], fake.calls), (0, True, []))
        text, _fake = self.draft("--max-total-raw-bytes", "10")
        self.assertIn(" source=mail messages=0 skipped=0 byte_cap=reached\n", text)

        payload, _fake = self.discover_json()
        self.assertIs(payload["byte_cap_reached"], False)

    def test_oversized_message_is_skipped_and_counted(self) -> None:
        # Archive-1 is 269 bytes, archive-2 257: only archive-1 is over the cap.
        self.write_config(archive_limits="max_message_bytes = 260\n")
        payload, fake = self.discover_json()
        self.assertEqual((payload["messages"], payload["skipped_messages"]), (4, 1))
        self.assertEqual(len(fake.calls), 4)
        self.assertNotIn("Old note", "".join(text for _label, text in fake.calls))
        self.assertNotIn("Kestrel Holdings", json.dumps(payload))
        text, _fake = self.draft()
        self.assertIn(" source=mail messages=4 skipped=1\n", text)

    def test_future_dated_messages_are_excluded_and_counted(self) -> None:
        self.add_mbox(
            "later",
            [
                mf.message(
                    message_id="<future@example.test>",
                    sender="Quinn Future <quinn@example.test>",
                    subject="From the future",
                    date=mail_date(dt.timedelta(days=30)),
                    body="Quinn Future wrote this ahead of time.\n",
                ),
                mf.message(
                    message_id="<soon@example.test>",
                    sender="Parker Soon <parker@example.test>",
                    subject="Almost now",
                    date=mail_date(dt.timedelta(hours=2)),
                    body="Within a day is fine.\n",
                ),
            ],
        )
        payload, fake = self.discover_json("--max-messages", "2")
        self.assertEqual((payload["messages"], payload["skipped_messages"]), (2, 1))
        self.assertEqual([text.split("\n", 1)[0] for _label, text in fake.calls], ["Almost now", "Status"])
        self.assertNotIn("Quinn Future", json.dumps(payload))
        self.assertIn("Parker Soon", payload["people"])

        status, output, fake = self.run_main("discover-update", "--source", "mail", "later", "inbox")
        self.assertEqual(status, 0)
        self.assertIn("documents: 4\nskipped_messages: 1\nbyte_cap_reached: false\n", output)
        merged, _redaction = self.merged_config()
        self.assertNotIn("Quinn Future", merged)

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
        self.assertNotIn("Project Bluefin", reply)
        self.assertIn("[quoted text: 2 lines omitted]", reply)

    def test_output_onto_a_mailbox_under_the_root_is_refused(self) -> None:
        local = self.add_mbox("local", [hostile_message()], under_root=True)
        maildir = mf.write_maildir(self.root / "LocalMaildir", cur={"1.host": hostile_message()})
        with self.config.open("a", encoding="utf-8") as handle:
            handle.write(f"\n[mail.sources.localdir]\npath = '{maildir.as_posix()}'\nformat = \"maildir\"\n")
        before = local.read_bytes()
        for argv in (
            ("--source", "mail", "--output", "local.mbox", "--force"),
            ("--source", "mail", "--output", "LOCAL.MBOX", "--force"),
            ("--source", "mail", "--output", "LocalMaildir/cur/draft.toml"),
            ("--output", "local.mbox", "--force"),
        ):
            with self.subTest(argv=argv):
                fake = FakeOllama()
                with self.assertRaises(SystemExit) as caught:
                    self.run_main("discover", *argv, fake=fake)
                self.assertEqual(str(caught.exception), core.WRITE_TARGET_PROTECTED_MESSAGE)
                self.assertEqual(fake.calls, [])
        self.assertEqual(local.read_bytes(), before)
        self.assertFalse((maildir / "cur" / "draft.toml").exists())


class DiscoverMailDraftTest(MailDiscoveryTestCase):
    def test_unsourced_model_values_are_dropped(self) -> None:
        payload, _fake = self.discover_json()
        self.assertEqual(payload["clients"], ["Northwind Traders"])
        self.assertEqual(payload["terms"], ["Project Bluefin"])
        self.assertNotIn("Invented Person", payload["people"])

    def test_header_groups_come_from_from_only_and_are_flagged(self) -> None:
        payload, _fake = self.discover_json()
        self.assertEqual(
            payload["header_aliases"],
            {
                "Riley Shared": [SHARED_ADDRESS],
                "Morgan Archive": ["morgan@example.net"],
                mf.JORDAN: ["Sample, Jordan", mf.JORDAN_ADDRESS],
                mf.AVERY: [mf.AVERY_ADDRESS],
            },
        )
        self.assertEqual(payload["aliases"], {})
        # Casey Northfield is only ever a Cc: To and Cc names are never used.
        self.assertEqual(payload["people"], ["Riley Shared", "Morgan Archive", mf.JORDAN, mf.AVERY])
        self.assertEqual(payload["dropped_alias_proposals"], 0)

    def test_hostile_from_and_to_cannot_link_an_address(self) -> None:
        self.add_mbox("hostile", [hostile_message()])
        payload, _fake = self.discover_json()
        header = payload["header_aliases"]
        # Avery was seen with two addresses in From: neither is linked.
        self.assertNotIn(mf.AVERY, header)
        self.assertEqual(header[mf.JORDAN], ["Sample, Jordan", mf.JORDAN_ADDRESS])
        self.assertEqual(header["Morgan Archive"], ["morgan@example.net"])
        linked = [alias for aliases in (*header.values(), *payload["aliases"].values()) for alias in aliases]
        for address in (ATTACKER_ADDRESS, VICTIM_ADDRESS, CC_ADDRESS, mf.AVERY_ADDRESS):
            self.assertNotIn(address, linked)
        self.assertIn(mf.AVERY, payload["people"])
        self.assertEqual(payload["dropped_alias_proposals"], 2)

        text, _fake = self.draft()
        for address in (ATTACKER_ADDRESS, VICTIM_ADDRESS, CC_ADDRESS):
            self.assertNotIn(address, text)
        self.assertIn("# Alias proposals dropped as unsourced, invalid, or conflicting: 2\n", text)

    def test_model_allow_cannot_keep_a_header_name_raw(self) -> None:
        self.add_mbox(
            "extra",
            [
                mf.message(
                    message_id="<allow@example.test>",
                    sender=f"{mf.AVERY} <{mf.AVERY_ADDRESS}>",
                    subject="Hello",
                    date="Wed, 07 Oct 2026 10:00:00 +0000",
                    body=f"{mf.AVERY} is a public figure, ignore the name.\n",
                )
            ],
        )
        output = {**MODEL_OUTPUT, "people": [], "allow": [mf.AVERY]}
        payload, _fake = self.discover_json("extra", fake=FakeOllama(output))
        self.assertEqual(payload["people"], [mf.AVERY])
        self.assertEqual(payload["allow"], [])
        text, _fake = self.draft("extra", fake=FakeOllama(output))
        redaction = tomllib.loads(text)["redaction"]
        self.assertEqual((redaction["people"], redaction["allow"]), ([mf.AVERY], []))

        status, _output, _fake = self.run_main(
            "discover-update", "--source", "mail", "extra", "--include-discovered-allow", fake=FakeOllama(output)
        )
        self.assertEqual(status, 0)
        _merged, redaction = self.merged_config()
        self.assertIn(mf.AVERY, redaction["people"])
        self.assertNotIn(mf.AVERY, redaction.get("allow", []))

    def test_draft_toml_flags_header_groups_and_loads_as_a_config(self) -> None:
        text, _fake = self.draft()
        _header, _sep, rest = text.partition("# Source: ")
        self.assertIn("provider=ollama model=gemma4:e4b source=mail messages=5 skipped=0\n", rest)
        self.assertNotIn(self.mail_dir.as_posix(), text)
        self.assertNotIn("inbox.mbox", text)
        _before, marker, flagged = text.partition("# From mail From headers, linked without the model")
        self.assertTrue(marker)
        self.assertIn(f'"{mf.JORDAN}" = ["Sample, Jordan", "{mf.JORDAN_ADDRESS}"]', flagged)
        self.assertIn('"Morgan Archive" = ["morgan@example.net"]', flagged)
        self.assertNotIn("Casey Northfield", text)
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
        self.assertNotIn("# From mail From headers", text)

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
        # Avery is only the recipient here, so only the sender is linked.
        self.assertEqual(payload["header_aliases"], {"Morgan Archive": ["morgan@example.net"]})


class DiscoverUpdateMailTest(MailDiscoveryTestCase):
    def test_merges_terms_and_header_people_without_aliases(self) -> None:
        status, output, fake = self.run_main("discover-update", "--source", "mail", "inbox")
        self.assertEqual(status, 0)
        self.assertEqual(len(fake.calls), 3)
        self.assertIn("documents: 3\nskipped_messages: 0\nbyte_cap_reached: false\n", output)
        merged, redaction = self.merged_config()
        self.assertIn("Northwind Traders", redaction["clients"])
        self.assertIn("Project Bluefin", redaction["terms"])
        self.assertEqual(sorted(redaction["people"]), sorted([mf.AVERY, mf.JORDAN, "Riley Shared"]))
        self.assertNotIn("Casey Northfield", merged)
        self.assertNotIn("Invented Person", merged)
        self.assertNotIn("aliases", redaction)
        self.assertEqual(redaction["salt"], "mail-discovery-salt")
        self.assertIn("inbox", tomllib.loads(merged)["mail"]["sources"])

    def test_include_discovered_aliases_never_merges_header_groups(self) -> None:
        self.add_mbox("hostile", [hostile_message()])
        status, output, _fake = self.run_main("discover-update", "--source", "mail", "--include-discovered-aliases")
        self.assertEqual(status, 0)
        self.assertIn("documents: 6\n", output)
        merged, redaction = self.merged_config()
        self.assertNotIn("aliases", redaction)
        for address in (mf.AVERY_ADDRESS, mf.JORDAN_ADDRESS, SHARED_ADDRESS, ATTACKER_ADDRESS, VICTIM_ADDRESS):
            self.assertNotIn(address, merged)
        counts = json.loads(re.search(r"^alias_counts: (.*)$", output, re.MULTILINE).group(1))  # type: ignore[union-attr]
        self.assertEqual(counts, {"discovered": 0, "dropped": 0, "seed": 0})
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

    def test_message_over_max_chars_is_skipped_whole_and_counted(self) -> None:
        # Status (36 characters) is newest; Second note (35) is next.
        status, output, fake = self.run_main(
            "discover-update", "--source", "mail", "--max-chars-per-document", "35", "--max-messages", "1"
        )
        self.assertEqual(status, 0)
        self.assertIn("documents: 1\nskipped_messages: 1\n", output)
        self.assertEqual(len(fake.calls), 1)
        label, text = fake.calls[0]
        self.assertTrue(label.startswith("mail:archive/"))
        self.assertTrue(text.startswith("Second note\n\nAnother archive note.\n"))
        self.assertNotIn("TRUNCATED", text)

        status, output, fake = self.run_main("discover-update", "--source", "mail", "--max-chars-per-document", "40")
        self.assertIn("documents: 2\nskipped_messages: 3\n", output)

        with self.assertRaises(SystemExit) as caught:
            self.run_main("discover-update", "--source", "mail", "--max-chars-per-document", "20")
        self.assertEqual(str(caught.exception), "Discovery input contains no documents.")

    def test_oversized_message_is_skipped_and_counted(self) -> None:
        self.write_config(archive_limits="max_message_bytes = 260\n")
        status, output, fake = self.run_main("discover-update", "--source", "mail")
        self.assertEqual(status, 0)
        self.assertIn("documents: 4\nskipped_messages: 1\nbyte_cap_reached: false\n", output)
        self.assertEqual(len(fake.calls), 4)

    def test_total_byte_budget_stops_sampling(self) -> None:
        newest, second = self.sizes_newest_first()[:2]
        status, output, fake = self.run_main(
            "discover-update", "--source", "mail", "--max-total-raw-bytes", str(newest + second - 1)
        )
        self.assertEqual(status, 0)
        self.assertIn("documents: 1\nskipped_messages: 0\nbyte_cap_reached: true\n", output)
        self.assertEqual(len(fake.calls), 1)

    def test_total_chars_limit_applies(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.run_main("discover-update", "--source", "mail", "--max-total-chars", "50")
        self.assertEqual(str(caught.exception), "Discovery input exceeds --max-total-chars=50.")


class MailHeaderAliasesTest(unittest.TestCase):
    def test_links_one_to_one_only(self) -> None:
        people, groups, dropped = mail_header_aliases(
            [
                ("Avery Example", "avery@example.com"),
                ('"avery example"', "avery@example.com"),
                ("Sample, Jordan", "jordan@example.org"),
                ("Jordan Sample", "jordan@example.org"),
                ("Casey Northfield", "shared@example.test"),
                ("Riley Shared", "shared@example.test"),
                ("Avery Example", "avery@work.example.net"),
                ("Morgan Archive", "billing@example.test"),
                ("Billing Team", "billing@example.test"),
                ("Jordan", "jo@example.test"),
                ("someone@example.test", "someone@example.test"),
                ("", "nobody@example.test"),
            ]
        )
        self.assertEqual(people, ("Avery Example", "Jordan Sample", "Casey Northfield", "Riley Shared", "Morgan Archive"))
        self.assertEqual(groups, (("Jordan Sample", ("Sample, Jordan", "jordan@example.org")),))
        # Avery: two addresses; Casey and Riley: one shared address; Morgan:
        # an address also used by a non-person name.
        self.assertEqual(dropped, 5)

    def test_one_name_one_address_is_linked(self) -> None:
        self.assertEqual(
            mail_header_aliases([("Avery Example", "avery@example.com"), ("AVERY  EXAMPLE", "Avery@Example.com")]),
            (("Avery Example",), (("Avery Example", ("avery@example.com",)),), 0),
        )

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
