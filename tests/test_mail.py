"""Read-only mail source tests over synthetic mailboxes only."""

from __future__ import annotations

import ast
import codecs
import hashlib
import hmac
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core, mail, server
from redacted_context_mcp.documents import DISABLED_MESSAGE
from redacted_context_mcp.limits import OperationBudget, OperationLimitError
from redacted_context_mcp.mail import (
    MAIL_SAFE_MESSAGES,
    MailAddress,
    MailIndexEntry,
    MailSource,
    collapse_quotes,
    html_to_text,
)
from redacted_context_mcp.models import UNKNOWN_REFERENCE_MESSAGE, MailSourceConfig, RedactionConfig
from redacted_context_mcp.sources import build_sources
from tests import mail_fixtures as mf

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "redacted_context_mcp"
SALT = "mail-test-salt"


def expected_ref(message_id: str, salt: str = SALT) -> str:
    digest = hmac.new(salt.encode("utf-8"), f"mail-message:{message_id}".encode("utf-8"), hashlib.sha256)
    return f"@m_{digest.hexdigest()[:12]}"


def tree_state(path: Path) -> dict[str, tuple[bytes, int]]:
    """Bytes and mtimes of a file, or of every file and directory under a directory."""
    if path.is_file():
        return {".": (path.read_bytes(), path.stat().st_mtime_ns)}
    state: dict[str, tuple[bytes, int]] = {".": (b"<dir>", path.stat().st_mtime_ns)}
    for child in sorted(path.rglob("*")):
        data = child.read_bytes() if child.is_file() else b"<dir>"
        state[child.relative_to(path).as_posix()] = (data, child.stat().st_mtime_ns)
    return state


class MailTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name).resolve()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def source(
        self,
        *mailboxes: tuple[str, Path, str],
        salt: str = SALT,
        documents: bool = False,
        **limits: int,
    ) -> MailSource:
        configs = {
            alias: MailSourceConfig(path=str(path), format=mail_format, **limits)
            for alias, path, mail_format in mailboxes
        }
        return MailSource(RedactionConfig(salt=salt, mail_sources=configs), documents=documents)

    def mbox_source(self, messages: list[bytes], *, newline: str = "\n", **kwargs: object) -> MailSource:
        path = mf.write_mbox(self.dir / "inbox.mbox", messages, newline=newline)
        return self.source(("inbox", path, "mbox"), **kwargs)  # type: ignore[arg-type]

    @staticmethod
    def refs_by_subject(source: MailSource, mailbox: str | None = None) -> dict[str, str]:
        page, _total = source.list_messages(mailbox, limit=500, offset=0)
        return {summary.subject: summary.ref for summary in page}

    def exercise(self, source: MailSource) -> list[object]:
        """Run every read operation and return all records produced."""
        records: list[object] = []
        page, _total = source.list_messages(None, limit=500, offset=0)
        records.extend(page)
        records.append(source.identities())
        for summary in page:
            for include_quoted in (False, True):
                message = source.read_message(summary.ref, include_quoted=include_quoted)
                records.append(message)
                records.extend(source.thread_messages(summary.ref, max_messages=50, include_quoted=include_quoted)[0])
                for attachment in message.attachments:
                    try:
                        records.append(source.read_attachment(attachment.ref))
                    except SystemExit as exc:
                        records.append(str(exc))
        records.extend(source.iter_documents(OperationBudget()))
        return records


class MailReaderTest(MailTestCase):
    def test_mbox_lf_and_crlf_read_the_same_messages(self) -> None:
        results = []
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)):
                source = self.mbox_source(mf.standard_messages(), newline=newline)
                page, total = source.list_messages(None, limit=50, offset=0)
                self.assertEqual(total, 5)
                bodies = [source.read_message(item.ref, include_quoted=True).body for item in page]
                results.append(([item.ref for item in page], [item.subject for item in page], bodies))
        self.assertEqual(results[0], results[1])

    def test_mbox_unescapes_from_lines_and_drops_separator_blank_line(self) -> None:
        raw = mf.message(message_id="<plain@example.test>", subject="Plain", body="Line one.\nLine two.\n")
        source = self.mbox_source([mf.standard_messages()[0], raw])
        refs = self.refs_by_subject(source)
        body = source.read_message(refs["Quarterly planning"], include_quoted=True).body
        self.assertIn("\nFrom the desk of Avery.\n", body)
        self.assertIn("\n>From here on, escaped.", body)
        self.assertNotIn(">>From", body)
        entry = source.resolve_reference(expected_ref("plain@example.test"))
        assert isinstance(entry, MailIndexEntry)
        self.assertEqual(entry.size, len(raw))

    def test_mbox_tolerates_leading_blank_lines_and_rejects_other_preamble(self) -> None:
        path = self.dir / "inbox.mbox"
        path.write_bytes(mf.mbox_bytes([mf.message()], leading_blank=True))
        self.assertEqual(self.source(("inbox", path, "mbox")).list_messages(None, limit=5, offset=0)[1], 1)
        path.write_bytes(b"not an mbox line\n" + mf.mbox_bytes([mf.message()]))
        with self.assertRaises(SystemExit) as caught:
            self.source(("inbox", path, "mbox")).list_messages(None, limit=5, offset=0)
        self.assertEqual(str(caught.exception), "Mailbox could not be read.")
        path.write_bytes(b"")
        self.assertEqual(self.source(("inbox", path, "mbox")).list_messages(None, limit=5, offset=0), ([], 0))

    def test_maildir_reads_cur_and_new_but_not_tmp_or_dot_files(self) -> None:
        path = mf.write_maildir(
            self.dir / "Maildir",
            cur={"1001.host!2,S": mf.message(message_id="<cur@example.test>", subject="In cur")},
            new={
                "1002.host": mf.message(message_id="<new@example.test>", subject="In new"),
                ".hidden": mf.message(message_id="<dot@example.test>", subject="Dot file"),
            },
            tmp={"1003.host": mf.message(message_id="<tmp@example.test>", subject="In tmp")},
        )
        (path / "cur" / "subdir").mkdir()
        source = self.source(("box", path, "maildir"))
        self.assertEqual(set(self.refs_by_subject(source)), {"In cur", "In new"})

    def test_maildir_storage_order_is_by_name(self) -> None:
        path = mf.write_maildir(
            self.dir / "Maildir",
            cur={"200.host": mf.message(message_id="<same@example.test>", body="second by name\n")},
            new={"100.host": mf.message(message_id="<same@example.test>", body="first by name\n")},
        )
        source = self.source(("box", path, "maildir"))
        message = source.read_message(expected_ref("same@example.test"))
        self.assertIn("first by name", message.body)

    def test_eml_directory_is_walked_recursively_and_a_single_file_works(self) -> None:
        path = mf.write_eml_tree(
            self.dir / "eml",
            {
                "a.eml": mf.message(message_id="<a@example.test>", subject="Top"),
                "nested/deeper/B.EML": mf.message(message_id="<b@example.test>", subject="Nested"),
                "nested/notes.txt": mf.message(message_id="<c@example.test>", subject="Not eml"),
                ".hidden.eml": mf.message(message_id="<d@example.test>", subject="Dot file"),
                ".git/e.eml": mf.message(message_id="<e@example.test>", subject="Dot dir"),
            },
        )
        source = self.source(("eml", path, "eml"))
        self.assertEqual(set(self.refs_by_subject(source)), {"Top", "Nested"})
        single = self.source(("one", path / "a.eml", "eml"))
        self.assertEqual(set(self.refs_by_subject(single)), {"Top"})

    def test_unreadable_mailboxes_fail_without_paths(self) -> None:
        maildir = mf.write_maildir(self.dir / "secret-folder-name")
        mbox = mf.write_mbox(self.dir / "secret-file-name.mbox", [mf.message()])
        cases = (
            ("inbox", self.dir / "missing-private-name.mbox", "mbox"),
            ("inbox", maildir, "mbox"),
            ("inbox", mbox, "maildir"),
            ("inbox", self.dir / "missing-private-name", "eml"),
        )
        for mailbox in cases:
            with self.subTest(format=mailbox[2], path=mailbox[1].name):
                with self.assertRaises(SystemExit) as caught:
                    self.source(mailbox).list_messages(None, limit=5, offset=0)
                message = str(caught.exception)
                self.assertEqual(message, "Mailbox could not be read.")
                self.assertNotIn(mailbox[1].name, message)

    def test_reads_never_use_the_stdlib_mailbox_module_or_write_modes(self) -> None:
        tree = ast.parse((PACKAGE_ROOT / "mail.py").read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[-1])
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[-1] for alias in node.names)
        self.assertTrue({"mailbox", "redaction", "rendering"}.isdisjoint(imported))

        modes: list[str] = []
        real_open = open

        def recording_open(file: object, mode: str = "r", *args: object, **kwargs: object) -> object:
            modes.append(mode)
            return real_open(file, mode, *args, **kwargs)  # type: ignore[call-overload]

        path = mf.write_maildir(self.dir / "Maildir", new={"1.host": mf.attachments_message()})
        with patch("redacted_context_mcp.mail.open", recording_open, create=True):
            self.exercise(self.mbox_source(mf.standard_messages()))
            self.exercise(self.source(("box", path, "maildir")))
        self.assertTrue(modes)
        self.assertEqual(set(modes), {"rb"})


class MailReadOnlyTest(MailTestCase):
    def test_operations_leave_bytes_mtimes_and_layout_unchanged(self) -> None:
        messages = mf.standard_messages() + mf.thread_messages()
        mbox = mf.write_mbox(self.dir / "inbox.mbox", messages)
        maildir = mf.write_maildir(
            self.dir / "Maildir",
            cur={f"{number}.host!2,S": raw for number, raw in enumerate(messages[:4])},
            new={f"{number}.host": raw for number, raw in enumerate(messages[4:], start=4)},
            tmp={"partial.host": mf.message(message_id="<partial@example.test>")},
        )
        eml = mf.write_eml_tree(self.dir / "eml", {f"dir{number % 2}/{number}.eml": raw for number, raw in enumerate(messages)})
        for mailbox in (("inbox", mbox, "mbox"), ("box", maildir, "maildir"), ("eml", eml, "eml")):
            with self.subTest(format=mailbox[2]):
                before = tree_state(mailbox[1])
                records = self.exercise(self.source(mailbox))
                self.assertTrue(records)
                self.assertEqual(tree_state(mailbox[1]), before)
        self.assertEqual(sorted(os.listdir(maildir / "new")), sorted(f"{n}.host" for n in range(4, len(messages))))

    def test_symlinked_entries_are_skipped(self) -> None:
        outside = self.dir / "outside"
        outside.mkdir()
        (outside / "linked.eml").write_bytes(mf.message(message_id="<linked@example.test>", subject="Linked"))
        maildir = mf.write_maildir(self.dir / "Maildir", cur={"1.host": mf.message(subject="Real")})
        eml = mf.write_eml_tree(self.dir / "eml", {"real.eml": mf.message(subject="Real")})
        mbox = mf.write_mbox(self.dir / "real.mbox", [mf.message(subject="Real")])
        try:
            os.symlink(outside / "linked.eml", maildir / "cur" / "2.host")
            os.symlink(outside / "linked.eml", eml / "linked.eml")
            os.symlink(outside, eml / "linked-dir", target_is_directory=True)
            os.symlink(mbox, self.dir / "link.mbox")
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {type(exc).__name__}")
        for mailbox in (("box", maildir, "maildir"), ("eml", eml, "eml")):
            with self.subTest(format=mailbox[2]):
                self.assertEqual(set(self.refs_by_subject(self.source(mailbox))), {"Real"})
        with self.assertRaises(SystemExit) as caught:
            self.source(("inbox", self.dir / "link.mbox", "mbox")).list_messages(None, limit=5, offset=0)
        self.assertEqual(str(caught.exception), "Mailbox could not be read.")


class MailReferenceTest(MailTestCase):
    def test_refs_are_deterministic_salted_hmacs(self) -> None:
        first = self.refs_by_subject(self.mbox_source(mf.standard_messages()))
        second = self.refs_by_subject(self.mbox_source(mf.standard_messages()))
        other = self.refs_by_subject(self.mbox_source(mf.standard_messages(), salt="another-salt"))
        self.assertEqual(first, second)
        self.assertEqual(first["Quarterly planning"], expected_ref("m1@example.test"))
        self.assertEqual(other["Quarterly planning"], expected_ref("m1@example.test", "another-salt"))
        self.assertTrue(set(first.values()).isdisjoint(other.values()))
        for ref in first.values():
            self.assertRegex(ref, r"^@m_[0-9a-f]{12}$")

    def test_message_id_normalization_keeps_case(self) -> None:
        source = self.mbox_source([mf.message(message_id="  < MiXeD@Example.Test >  ")])
        self.assertEqual(list(self.refs_by_subject(source).values()), [expected_ref("MiXeD@Example.Test")])

    def test_messages_without_message_id_use_the_header_block_hash(self) -> None:
        raw = mf.message(message_id=None, subject="No identifier")
        header = raw.split(b"\n\n", 1)[0] + b"\n"
        digest = hashlib.sha256(header).hexdigest()
        expected = "@m_" + hmac.new(
            SALT.encode("utf-8"), f"mail-message-headers:{digest}".encode("utf-8"), hashlib.sha256
        ).hexdigest()[:12]
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)):
                source = self.mbox_source([raw], newline=newline)
                self.assertEqual(self.refs_by_subject(source), {"No identifier": expected})
                self.assertEqual(source.read_message(expected).thread, expected)

    def test_duplicates_keep_the_first_in_config_then_storage_order(self) -> None:
        first = mf.write_mbox(
            self.dir / "first.mbox",
            [
                mf.message(message_id="<dup@example.test>", body="first copy\n"),
                mf.message(message_id="<dup@example.test>", body="second copy\n"),
            ],
        )
        second = mf.write_maildir(
            self.dir / "Maildir",
            cur={
                "1.host": mf.message(message_id="<dup@example.test>", body="maildir copy\n"),
                "2.host": mf.message(message_id="<only@example.test>", subject="Only here"),
            },
        )
        source = self.source(("zeta", first, "mbox"), ("alpha", second, "maildir"))
        page, total = source.list_messages(None, limit=50, offset=0)
        self.assertEqual(total, 2)
        message = source.read_message(expected_ref("dup@example.test"))
        self.assertEqual((message.mailbox, message.body), ("zeta", "first copy\n"))
        # A mailbox filter lists every message stored in that mailbox, once,
        # under the filtered alias, even when an earlier mailbox holds it too.
        alpha, total = source.list_messages("alpha", limit=50, offset=0)
        self.assertEqual(total, 2)
        self.assertEqual(
            sorted((item.mailbox, item.subject) for item in alpha),
            [("alpha", "Only here"), ("alpha", "Quarterly planning")],
        )
        zeta, total = source.list_messages("zeta", limit=50, offset=0)
        self.assertEqual(([item.ref for item in zeta], total), ([expected_ref("dup@example.test")], 1))
        self.assertEqual(source.mailboxes(), [("alpha", "maildir"), ("zeta", "mbox")])

    def test_two_message_ids_with_one_ref_fail_closed(self) -> None:
        source = self.mbox_source([mf.message(message_id="<one@example.test>"), mf.message(message_id="<two@example.test>")])
        with patch.object(mail, "mail_digest", return_value="0" * 12):
            with self.assertRaises(SystemExit) as caught:
                source.list_messages(None, limit=5, offset=0)
        self.assertEqual(str(caught.exception), "Mail reference collision.")

    def test_reference_ownership_is_syntactic_and_resolution_is_safe(self) -> None:
        source = self.mbox_source([mf.attachments_message()])
        ref = expected_ref("attach@example.test")
        for owned in (ref, f"{ref}/1", f"{ref}/9999", "@m_000000000000"):
            self.assertTrue(source.owns_reference(owned), owned)
        for foreign in ("", "@m_", "@m_123", "@m_ABCDEF012345", f"{ref}/0", f"{ref}/10000", f"{ref}/01", f"{ref}/", "m_000000000000", "@p_000000000000", None, 7):
            self.assertFalse(source.owns_reference(foreign), foreign)  # type: ignore[arg-type]
        entry, number = source.resolve_reference(f"{ref}/2")  # type: ignore[misc]
        self.assertEqual((entry.ref, number), (ref, 2))
        for unknown in ("@m_000000000000", "@m_000000000000/1", "attach@example.test", "@m_123", None):
            with self.subTest(ref=unknown):
                with self.assertRaises(SystemExit) as caught:
                    source.resolve_reference(unknown)  # type: ignore[arg-type]
                self.assertEqual(str(caught.exception), UNKNOWN_REFERENCE_MESSAGE)
        for call, argument in ((source.read_message, f"{ref}/1"), (source.read_attachment, ref)):
            with self.assertRaises(SystemExit) as caught:
                call(argument)
            self.assertEqual(str(caught.exception), UNKNOWN_REFERENCE_MESSAGE)
        with self.assertRaises(SystemExit) as caught:
            source.read_attachment(f"{ref}/99")
        self.assertEqual(str(caught.exception), UNKNOWN_REFERENCE_MESSAGE)


class MailHeaderPolicyTest(MailTestCase):
    def test_dropped_headers_and_raw_message_ids_never_appear_in_records(self) -> None:
        source = self.mbox_source(mf.standard_messages() + mf.thread_messages())
        serialized = repr(self.exercise(source))
        unique_values = (
            "relay-zq81", "192.0.2.71", "bounce-hv93", "dkimsig4471", "arcseal8823", "authres5510",
            "delivered-ux62", "listtok7781", "team-yy18", "MailerSentinel", "198.51.100.239",
            "m1@example.test", "reply-a@example.test", "root@example.test", "inbox.mbox", str(self.dir),
        )
        for value in unique_values:
            self.assertNotIn(value, serialized)

    def test_address_headers_keep_groups_and_decoded_names(self) -> None:
        source = self.mbox_source(mf.standard_messages())
        message = source.read_message(expected_ref("m2@example.test"))
        self.assertEqual(
            message.addresses,
            (
                ("from", (MailAddress("Jördan Sample", mf.JORDAN_ADDRESS),)),
                (
                    "to",
                    (
                        MailAddress("Planning Team", ""),
                        MailAddress(mf.AVERY, mf.AVERY_ADDRESS),
                        MailAddress("", mf.CASEY_ADDRESS),
                    ),
                ),
                ("cc", (MailAddress("Sample, Jordan", mf.JORDAN_ADDRESS),)),
            ),
        )
        self.assertEqual(message.subject, "Re: planning – draft")

    def test_all_allowed_address_headers_in_order(self) -> None:
        raw = mf.message(
            to=f"{mf.JORDAN} <{mf.JORDAN_ADDRESS}>",
            headers=(
                ("Bcc", f"hidden@{'example.org'}"),
                ("Cc", f"{mf.CASEY} <{mf.CASEY_ADDRESS}>"),
                ("Reply-To", "replies@example.com"),
                ("Sender", "Assistant Example <assistant@example.com>"),
                ("To", "second-to@example.org"),
            ),
        )
        message = self.mbox_source([raw]).read_message(expected_ref("m1@example.test"))
        self.assertEqual([name for name, _value in message.addresses], ["from", "sender", "reply_to", "to", "cc", "bcc"])
        self.assertEqual(
            dict(message.addresses)["to"],
            (MailAddress(mf.JORDAN, mf.JORDAN_ADDRESS), MailAddress("", "second-to@example.org")),
        )

    def test_unparsed_address_headers_are_none_and_not_harvested(self) -> None:
        raw = mf.message(
            sender='"',
            to=f"{mf.JORDAN} <{mf.JORDAN_ADDRESS}>",
            headers=(("Cc", "Group:;;;"),),
        )
        source = self.mbox_source([raw])
        message = source.read_message(expected_ref("m1@example.test"))
        self.assertEqual(dict(message.addresses), {"from": None, "to": (MailAddress(mf.JORDAN, mf.JORDAN_ADDRESS),), "cc": None})
        page, _total = source.list_messages(None, limit=5, offset=0)
        self.assertIsNone(page[0].sender)
        self.assertEqual(source.identities(), ((mf.JORDAN, mf.JORDAN_ADDRESS),))

    def test_defective_address_headers_are_unparsed_on_every_python_version(self) -> None:
        # The stdlib raises for some of these on one Python version and
        # returns ``<>`` placeholder addresses on another.
        unparsed = ('"', "Group:;;;", "<>", "Avery Example <>", "jordan", "@example.org", "Avery Example", ":;")
        for value in unparsed:
            with self.subTest(value=value):
                self.assertEqual(mail.parse_address_header(mail.parse_headers(f"From: {value}\n".encode()), "From"), (True, None))
        parsed = {
            "undisclosed-recipients:;": (MailAddress("undisclosed-recipients", ""),),
            "Sender <@route.example:s@example.test>": (MailAddress("Sender", "s@example.test"),),
            "a@example.test, , c@example.test": (MailAddress("", "a@example.test"), MailAddress("", "c@example.test")),
            "root@localhost": (MailAddress("", "root@localhost"),),
        }
        for value, expected in parsed.items():
            with self.subTest(value=value):
                self.assertEqual(
                    mail.parse_address_header(mail.parse_headers(f"From: {value}\n".encode()), "From"), (True, expected)
                )

    def test_dates_are_generated_utc_strings(self) -> None:
        cases = (
            ("Thu, 01 Oct 2026 10:15:00 +0200", "2026-10-01T08:15:00Z"),
            ("Thu, 01 Oct 2026 10:15:00 -0000", "2026-10-01T10:15:00Z"),
            ("1 Oct 2026 23:30:00 -0500", "2026-10-02T04:30:00Z"),
            ("Sat, 01 Oct 1960 10:15:00 +0000", "?"),
            ("not a date at all", "?"),
            (None, "?"),
        )
        messages = [
            mf.message(message_id=f"<date{number}@example.test>", date=date, subject=f"case {number}")
            for number, (date, _expected) in enumerate(cases)
        ]
        source = self.mbox_source(messages)
        for number, (_date, expected) in enumerate(cases):
            with self.subTest(case=number):
                message = source.read_message(expected_ref(f"date{number}@example.test"))
                self.assertEqual(message.date, expected)
                self.assertEqual(message.timestamp is None, expected == "?")

    def test_invisible_characters_are_removed(self) -> None:
        raw = mf.message(subject="Quar​terly⁠ plan", body="Av​ery﻿ Ex‮ample\r\nnext line\r\n")
        message = self.mbox_source([raw]).read_message(expected_ref("m1@example.test"))
        self.assertEqual(message.subject, "Quarterly plan")
        self.assertEqual(message.body, "Avery Example\nnext line\n")

    def test_other_invisible_characters_cannot_split_names(self) -> None:
        body = "Av­ery Ex͏ample, Av\U000e0061ery️ Exam؜ple, Avㅤery Example\n"
        raw = mf.message(subject="Quar­terly\U000e0070 plan", body=body)
        message = self.mbox_source([raw]).read_message(expected_ref("m1@example.test"))
        self.assertEqual(message.subject, "Quarterly plan")
        self.assertEqual(message.body, "Avery Example, Avery Example, Avery Example\n")

    def test_identities_cover_every_mailbox_sorted_and_deduplicated(self) -> None:
        mbox = mf.write_mbox(self.dir / "inbox.mbox", mf.standard_messages())
        maildir = mf.write_maildir(
            self.dir / "Maildir",
            cur={"1.host": mf.message(message_id="<x@example.test>", to="Other Person <other@example.test>")},
        )
        source = self.source(("inbox", mbox, "mbox"), ("box", maildir, "maildir"))
        self.assertEqual(
            source.identities(),
            (
                ("", mf.CASEY_ADDRESS),
                (mf.AVERY, mf.AVERY_ADDRESS),
                (mf.JORDAN, mf.JORDAN_ADDRESS),
                ("Jördan Sample", mf.JORDAN_ADDRESS),
                ("Other Person", "other@example.test"),
                ("Planning Team", ""),
                ("Sample, Jordan", mf.JORDAN_ADDRESS),
            ),
        )


class MailBodyTest(MailTestCase):
    def test_alternative_prefers_plain_and_html_only_is_converted(self) -> None:
        markup = "<html><head><title>Hidden title</title></head><body><p>Visible <b>text</b></p></body></html>"
        source = self.mbox_source([mf.alternative_message(), mf.html_message(markup)])
        self.assertEqual(source.read_message(expected_ref("alt@example.test")).body, "Plain body for the alternative.")
        self.assertEqual(source.read_message(expected_ref("html@example.test")).body, "Visible text")

    def test_html_drops_hidden_and_non_content_elements(self) -> None:
        markup = (
            "<html><head><style>p { color: red }</style><title>Title text</title></head><body>"
            "<script>alert('script text')</script><noscript>noscript text</noscript>"
            "<template>template text</template><!-- comment text -->"
            "<p>Shown one</p><p hidden>hidden attribute text</p>"
            "<div style='DISPLAY : None'>display none text</div>"
            "<span style=\"color:red; visibility: HIDDEN\">visibility text</span>"
            "<div style='display:none'><p>nested hidden <b>text</b></p><img alt='hidden alt'></div>"
            "<p>Shown two</p></body></html>"
        )
        text = html_to_text(markup)
        self.assertEqual(text, "Shown one\n\nShown two")

    def test_html_structure_links_images_and_lists(self) -> None:
        markup = (
            "<h1>Heading</h1><p>Intro with <a href='https://example.com/page'>a link</a> and "
            "<a href='https://example.com/same'>https://example.com/same</a> and "
            "<a href='mailto:avery@example.com'>avery@example.com</a> and "
            "<a href='javascript:void(0)'>script link</a>.</p>"
            "<ul><li>First</li><li>Second <img src='x.png' alt='logo'></li></ul>"
            "Line<br>break<hr>after rule<table><tr><td>a</td><td>b</td></tr></table>"
            "<pre>  keep   spacing\n  here</pre>"
        )
        self.assertEqual(
            html_to_text(markup),
            "Heading\n\nIntro with a link <https://example.com/page> and https://example.com/same and "
            "avery@example.com and script link.\n\n- First\n- Second logo\nLine\nbreak\nafter rule\na b\n"
            "  keep   spacing\n  here",
        )

    def test_html_quotes_get_prefixes_and_mismatched_tags_are_tolerated(self) -> None:
        markup = (
            "<div>Reply text</div>"
            "<div class='gmail_quote gmail_quote_container'><div class='gmail_attr'>On Monday Jordan wrote:</div>"
            "<blockquote>Quoted line<blockquote>Deeper</blockquote></blockquote></div>"
            "<p>Unclosed <b>bold <i>italic</p> after</span> end"
        )
        self.assertEqual(
            html_to_text(markup),
            "Reply text\n> On Monday Jordan wrote:\n> > Quoted line\n> > > Deeper\n\nUnclosed bold italic\n\nafter end",
        )

    def test_unclosed_head_does_not_hide_the_body(self) -> None:
        self.assertEqual(html_to_text("<html><head><meta charset='utf-8'><body><p>Body text</p>"), "Body text")

    def test_hostile_nesting_stays_linear_and_bounded(self) -> None:
        count = 20_000
        for markup in (
            "<div>" * count + "</span>" * count,
            "<div>" * count + "<body>" * count,
            '<a href="https://example.test/x">' * count + "w<br>" * count + "</a>" * count,
        ):
            started = time.monotonic()
            html_to_text(markup)
            self.assertLess(time.monotonic() - started, 5.0)
        deep = html_to_text("<blockquote>x" * 200)
        self.assertEqual(max(len(line) for line in deep.split("\n")), len("> " * mail.MAX_HTML_QUOTE_DEPTH) + 1)

    def test_nested_links_keep_their_targets(self) -> None:
        markup = (
            '<p><a href="https://example.test/outer">see <a href="https://example.test/inner">'
            "https://example.test/inner</a></a> now</p>"
        )
        self.assertEqual(html_to_text(markup), "see https://example.test/inner <https://example.test/outer> now")

    def test_blank_line_runs_collapse(self) -> None:
        self.assertEqual(html_to_text("<p>a</p><p></p><p></p><div><br><br><br></div><p>b</p>"), "a\n\nb")

    def test_quote_runs_and_attribution_collapse(self) -> None:
        text = "Thanks!\n\nOn Mon, Jordan Sample wrote:\n> line one\n> line two\n\nInline answer.\n\n> more\n  > indented\n"
        self.assertEqual(
            collapse_quotes(text),
            "Thanks!\n\n[quoted text: 3 lines omitted]\n\nInline answer.\n\n[quoted text: 2 lines omitted]",
        )
        across_blank = "Reply.\nOn Tue, Avery WROTE:\n\n> quoted\n"
        self.assertEqual(collapse_quotes(across_blank), "Reply.\n[quoted text: 3 lines omitted]")

    def test_outlook_blocks_collapse_to_the_end(self) -> None:
        separator = "Reply.\n\n-----Original Message-----\nFrom: Jordan\nSent: Monday\nOld text\n"
        self.assertEqual(collapse_quotes(separator), "Reply.\n\n[quoted text: 4 lines omitted]")
        header_block = "Reply.\nFrom: Jordan Sample\nTo: Avery\nSubject: x\nDate: Monday\n\nOld text"
        self.assertEqual(collapse_quotes(header_block), "Reply.\n[quoted text: 6 lines omitted]")
        not_outlook = "From: the start\nno sent line here\na\nb\nc\nSent: too late"
        self.assertEqual(collapse_quotes(not_outlook), not_outlook)

    def test_signature_collapses_and_later_quotes_stay_separate(self) -> None:
        self.assertEqual(
            collapse_quotes("Body.\n-- \nAvery Example\nExample Corp\n"),
            "Body.\n[signature: 3 lines omitted]",
        )
        self.assertEqual(
            collapse_quotes("Body.\n--\nSig\n\nOn Mon, X wrote:\n> old\n"),
            "Body.\n[signature: 3 lines omitted]\n[quoted text: 2 lines omitted]",
        )
        self.assertEqual(collapse_quotes("Body.\n> -- \n> quoted sig\n"), "Body.\n[quoted text: 2 lines omitted]")
        self.assertEqual(collapse_quotes("No markers here.\n---\n"), "No markers here.\n---\n")

    def test_include_quoted_returns_the_unmodified_body(self) -> None:
        body = "Answer.\n\nOn Mon, Jordan wrote:\n> question\n-- \nAvery\n"
        source = self.mbox_source([mf.message(body=body)])
        ref = expected_ref("m1@example.test")
        self.assertEqual(source.read_message(ref, include_quoted=True).body, body)
        self.assertEqual(
            source.read_message(ref).body,
            "Answer.\n\n[quoted text: 2 lines omitted]\n[signature: 2 lines omitted]",
        )

    def test_bodies_honour_byte_order_marks(self) -> None:
        text = "Hello from Marta Kowalczyk.\n"
        cases = (
            ("text/plain", codecs.BOM_UTF16_LE + text.encode("utf-16-le")),
            ("text/plain; charset=us-ascii", codecs.BOM_UTF16_BE + text.encode("utf-16-be")),
            ("text/plain; charset=utf-8", codecs.BOM_UTF8 + text.encode("utf-8")),
            ("text/plain", text.encode("utf-8")),
        )
        for number, (content_type, data) in enumerate(cases):
            with self.subTest(content_type=content_type, number=number):
                raw = mf.multipart([mf.encoded_text_part(data, content_type=content_type)], message_id=f"<bom{number}@example.test>")
                source = self.mbox_source([raw])
                self.assertEqual(source.read_message(expected_ref(f"bom{number}@example.test")).body, text)
        html = codecs.BOM_UTF16_LE + "<p>Hello <b>Marta</b></p>".encode("utf-16-le")
        raw = mf.multipart([mf.encoded_text_part(html, content_type="text/html")], message_id="<bom-html@example.test>")
        self.assertEqual(self.mbox_source([raw]).read_message(expected_ref("bom-html@example.test")).body, "Hello Marta")

    def test_bodies_that_do_not_decode_to_text_are_withheld(self) -> None:
        cases = (
            ("text/plain", "Marta Kowalczyk mk@corp.example\n".encode("utf-16-le")),
            ("text/html", "<p>Marta Kowalczyk</p>".encode("utf-16-be")),
            ("text/plain; charset=utf-8", bytes(range(128, 256))),
        )
        for number, (content_type, data) in enumerate(cases):
            with self.subTest(content_type=content_type, number=number):
                raw = mf.multipart(
                    [mf.encoded_text_part(data, content_type=content_type), mf.attachment_part("a.txt", "text/plain", b"kept\n")],
                    message_id=f"<nul{number}@example.test>",
                    subject="Readable subject",
                )
                source = self.mbox_source([raw])
                ref = expected_ref(f"nul{number}@example.test")
                for include_quoted in (False, True):
                    message = source.read_message(ref, include_quoted=include_quoted)
                    self.assertEqual(message.body, mail.BODY_NOT_TEXT)
                    self.assertEqual(message.subject, "Readable subject")
                self.assertEqual(source.read_attachment(f"{ref}/1"), "kept\n")
                (document,) = source.iter_documents(OperationBudget())
                self.assertEqual(document.text, f"Readable subject\n\n{mail.BODY_NOT_TEXT}")
                self.assertNotIn("\0", document.text)


class MailAttachmentTest(MailTestCase):
    def test_attachments_are_listed_with_validated_types(self) -> None:
        source = self.mbox_source([mf.attachments_message()])
        ref = expected_ref("attach@example.test")
        message = source.read_message(ref)
        self.assertEqual(message.body, "See the attached files.")
        self.assertEqual(
            [(item.ref, item.content_type, item.size, item.filename) for item in message.attachments],
            [
                (f"{ref}/1", "text/plain", 47, "notes.txt"),
                (f"{ref}/2", "application/pdf", 23, "report.pdf"),
                (f"{ref}/3", "application/x-made-up", 9, "archive.bin"),
                (f"{ref}/4", "text/plain", 6, "weird.dat"),
            ],
        )

    def test_overlong_content_types_fall_back_to_octet_stream(self) -> None:
        raw = mf.multipart(
            [mf.text_part("Body.\n"), mf.attachment_part("x.bin", "application/" + "x" * 70, b"data")],
            message_id="<long@example.test>",
        )
        message = self.mbox_source([raw]).read_message(expected_ref("long@example.test"))
        self.assertEqual(message.attachments[0].content_type, "application/octet-stream")

    def test_text_attachment_is_decoded_raw_text(self) -> None:
        raw = mf.multipart(
            [
                mf.text_part("Body.\n"),
                mf.attachment_part("latin.txt", "text/plain; charset=iso-8859-1", "Café résumé\r\n".encode("latin-1")),
                mf.attachment_part("zw.txt", "text/plain; charset=utf-8", "Jor​dan\n".encode("utf-8")),
            ],
            message_id="<text@example.test>",
        )
        source = self.mbox_source([raw])
        ref = expected_ref("text@example.test")
        self.assertEqual(source.read_attachment(f"{ref}/1"), "Café résumé\n")
        self.assertEqual(source.read_attachment(f"{ref}/2"), "Jordan\n")
        self.assertEqual(
            self.mbox_source([mf.attachments_message()]).read_attachment(f"{expected_ref('attach@example.test')}/1"),
            "Attachment notes from Jordan Sample.\nLine two.\n",
        )

    def test_byte_order_marks_win_over_a_missing_or_ascii_charset(self) -> None:
        text = "Marta Kowalczyk\tmk@corp.example\n"
        raw = mf.multipart(
            [
                mf.text_part("Body.\n"),
                mf.attachment_part("le.txt", "text/plain", codecs.BOM_UTF16_LE + text.encode("utf-16-le")),
                mf.attachment_part("be.txt", "text/plain", codecs.BOM_UTF16_BE + text.encode("utf-16-be")),
                mf.attachment_part("ascii.txt", "text/plain; charset=us-ascii", codecs.BOM_UTF16_LE + text.encode("utf-16-le")),
                mf.attachment_part("le32.txt", "text/csv", codecs.BOM_UTF32_LE + text.encode("utf-32-le")),
                mf.attachment_part("be32.txt", "text/plain; charset=utf-8", codecs.BOM_UTF32_BE + text.encode("utf-32-be")),
                mf.attachment_part("sig.txt", "text/plain; charset=iso-8859-1", codecs.BOM_UTF8 + "Zoë Brönte\n".encode("utf-8")),
                mf.attachment_part("plain.txt", "text/plain", "Zoë Brönte\n".encode("utf-8")),
            ],
            message_id="<bom@example.test>",
        )
        source = self.mbox_source([raw])
        ref = expected_ref("bom@example.test")
        for number in range(1, 6):
            with self.subTest(number=number):
                self.assertEqual(source.read_attachment(f"{ref}/{number}"), text)
        self.assertEqual(source.read_attachment(f"{ref}/6"), "Zoë Brönte\n")
        # Without a declared charset, UTF-8 is assumed.
        self.assertEqual(source.read_attachment(f"{ref}/7"), "Zoë Brönte\n")

    def test_text_attachments_that_do_not_decode_to_text_are_refused(self) -> None:
        raw = mf.multipart(
            [
                mf.text_part("Body.\n"),
                mf.attachment_part("bare16.txt", "text/plain", "Marta Kowalczyk\tmk@corp.example\n".encode("utf-16-le")),
                mf.attachment_part("image.txt", "text/plain", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" * 8),
                mf.attachment_part("nul.csv", "text/csv; charset=iso-8859-1", b"name,Marta\x00Kowalczyk\n"),
                mf.attachment_part("junk.txt", "text/plain; charset=utf-8", bytes(range(128, 256))),
                mf.attachment_part("mixed.txt", "text/plain; charset=utf-8", b"Mostly text \xff here.\n"),
            ],
            message_id="<nul@example.test>",
        )
        source = self.mbox_source([raw])
        ref = expected_ref("nul@example.test")
        for number in range(1, 5):
            with self.subTest(number=number):
                with self.assertRaises(SystemExit) as caught:
                    source.read_attachment(f"{ref}/{number}")
                self.assertEqual(str(caught.exception), "Unsupported attachment type.")
        # A few undecodable bytes in otherwise readable text are replaced, not refused.
        self.assertEqual(source.read_attachment(f"{ref}/5"), "Mostly text \ufffd here.\n")

    def test_documents_are_refused_unless_enabled_and_other_types_unsupported(self) -> None:
        ref = expected_ref("attach@example.test")
        source = self.mbox_source([mf.attachments_message()])
        with self.assertRaises(SystemExit) as caught:
            source.read_attachment(f"{ref}/2")
        self.assertEqual(str(caught.exception), DISABLED_MESSAGE)
        with self.assertRaises(SystemExit) as caught:
            source.read_attachment(f"{ref}/3")
        self.assertEqual(str(caught.exception), "Unsupported attachment type.")

        enabled = self.mbox_source([mf.attachments_message()], documents=True)
        with patch("redacted_context_mcp.documents.extract_document", return_value="extracted text") as extract:
            self.assertEqual(enabled.read_attachment(f"{ref}/2"), "extracted text")
        extract.assert_called_once_with(b"%PDF-1.4 fake pdf bytes", ".pdf")

    def test_document_type_by_content_type_and_rfc822_is_unsupported(self) -> None:
        docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        raw = mf.multipart(
            [
                mf.text_part("Body.\n"),
                mf.attachment_part("noextension", docx, b"PK fake docx"),
                "Content-Type: message/rfc822\nContent-Disposition: attachment\n\n"
                "Subject: inner\nX-Inner: inner-header-value\n\ninner body",
            ],
            message_id="<docs@example.test>",
        )
        source = self.mbox_source([raw], documents=True)
        ref = expected_ref("docs@example.test")
        self.assertEqual([item.content_type for item in source.read_message(ref).attachments], [docx, "message/rfc822"])
        with patch("redacted_context_mcp.documents.extract_document", return_value="docx text") as extract:
            self.assertEqual(source.read_attachment(f"{ref}/1"), "docx text")
        self.assertEqual(extract.call_args.args[1], ".docx")
        with self.assertRaises(SystemExit) as caught:
            source.read_attachment(f"{ref}/2")
        self.assertEqual(str(caught.exception), "Unsupported attachment type.")


class MailBudgetTest(MailTestCase):
    def test_message_limit_fails_closed_for_every_format(self) -> None:
        messages = [mf.message(message_id=f"<n{number}@example.test>") for number in range(3)]
        mbox = mf.write_mbox(self.dir / "inbox.mbox", messages)
        maildir = mf.write_maildir(self.dir / "Maildir", cur={f"{n}.host": raw for n, raw in enumerate(messages)})
        eml = mf.write_eml_tree(self.dir / "eml", {f"{n}.eml": raw for n, raw in enumerate(messages)})
        for mailbox in (("inbox", mbox, "mbox"), ("box", maildir, "maildir"), ("eml", eml, "eml")):
            with self.subTest(format=mailbox[2]):
                self.assertEqual(self.source(mailbox, max_messages=3).list_messages(None, limit=5, offset=0)[1], 3)
                with self.assertRaises(OperationLimitError) as caught:
                    self.source(mailbox, max_messages=2).list_messages(None, limit=5, offset=0)
                self.assertEqual(str(caught.exception), "Mailbox message limit exceeded.")

    def test_message_byte_limit_applies_to_reads(self) -> None:
        big = mf.message(message_id="<big@example.test>", body="x" * 5000 + "\n")
        source = self.mbox_source([big, mf.message(message_id="<small@example.test>", body="ok\n")], max_message_bytes=1000)
        self.assertEqual(source.read_message(expected_ref("small@example.test")).body, "ok\n")
        for call in (
            lambda: source.read_message(expected_ref("big@example.test")),
            lambda: list(source.iter_documents(OperationBudget())),
        ):
            with self.assertRaises(OperationLimitError) as caught:
                call()
            self.assertEqual(str(caught.exception), "Mail message byte limit exceeded.")

    def test_index_deadline_header_cap_and_caller_deadline(self) -> None:
        source = self.mbox_source(mf.standard_messages())
        with patch.object(mail, "MAIL_INDEX_SECONDS", -1.0):
            with self.assertRaises(OperationLimitError):
                source.identities()
        with patch.object(mail, "MAIL_INDEX_MAX_HEADER_BYTES", 10):
            with self.assertRaises(OperationLimitError) as caught:
                source.identities()
        self.assertEqual(str(caught.exception), "Mailbox header byte limit exceeded.")
        with self.assertRaises(OperationLimitError):
            source.identities(OperationBudget(deadline=time.monotonic() - 1))
        self.assertTrue(source.identities())

    def test_documents_are_charged_raw_size_before_reading(self) -> None:
        source = self.mbox_source(mf.standard_messages())
        budget = OperationBudget()
        documents = list(source.iter_documents(budget))
        sizes = [source.resolve_reference(document.ref).size for document in documents]  # type: ignore[union-attr]
        self.assertEqual((budget.files_seen, budget.raw_bytes_seen), (len(documents), sum(sizes)))
        with patch.object(MailSource, "_read_raw", side_effect=AssertionError("read before charge")):
            for limited in (
                OperationBudget(max_files=0),
                OperationBudget(max_raw_bytes_per_file=10),
                OperationBudget(max_total_raw_bytes=10),
            ):
                with self.subTest(budget=limited):
                    with self.assertRaises(OperationLimitError):
                        list(source.iter_documents(limited))


class MailCacheTest(MailTestCase):
    def test_index_is_reused_until_the_mbox_changes(self) -> None:
        path = mf.write_mbox(self.dir / "inbox.mbox", mf.thread_messages())
        source = self.source(("inbox", path, "mbox"))
        with patch.object(mail, "index_mbox", wraps=mail.index_mbox) as built:
            self.assertEqual(source.list_messages(None, limit=50, offset=0)[1], 4)
            source.identities()
            source.read_message(expected_ref("reply-a@example.test"))
            self.assertEqual(built.call_count, 1)
            entry = source.resolve_reference(expected_ref("reply-a@example.test"))
            with path.open("ab") as handle:
                handle.write(mf.mbox_bytes([mf.message(message_id="<late@example.test>", subject="Late")]))
            with self.assertRaises(SystemExit) as caught:
                source._read_raw(entry)  # type: ignore[arg-type]
            self.assertEqual(str(caught.exception), "Mailbox changed during read. Retry.")
            self.assertEqual(source.read_message(expected_ref("late@example.test")).subject, "Late")
            self.assertEqual(source.list_messages(None, limit=50, offset=0)[1], 5)
            self.assertEqual(built.call_count, 2)

    def test_maildir_index_rebuilds_when_entries_change(self) -> None:
        path = mf.write_maildir(self.dir / "Maildir", new={"1.host": mf.message(message_id="<one@example.test>")})
        source = self.source(("box", path, "maildir"))
        with patch.object(mail, "index_files", wraps=mail.index_files) as built:
            source.list_messages(None, limit=5, offset=0)
            source.list_messages(None, limit=5, offset=0)
            self.assertEqual(built.call_count, 1)
            entry = source.resolve_reference(expected_ref("one@example.test"))
            (path / "new" / "1.host").unlink()
            with self.assertRaises(SystemExit) as caught:
                source._read_raw(entry)  # type: ignore[arg-type]
            self.assertEqual(str(caught.exception), "Mailbox changed during read. Retry.")
            (path / "cur" / "2.host").write_bytes(mf.message(message_id="<two@example.test>"))
            self.assertEqual(source.list_messages(None, limit=5, offset=0)[1], 1)
            self.assertEqual(built.call_count, 2)
        with self.assertRaises(SystemExit) as caught:
            source.read_message(expected_ref("one@example.test"))
        self.assertEqual(str(caught.exception), UNKNOWN_REFERENCE_MESSAGE)


class MailListAndThreadTest(MailTestCase):
    def test_listing_is_newest_first_with_paging_and_totals(self) -> None:
        source = self.mbox_source(mf.thread_messages() + [mf.message(message_id="<nodate@example.test>", date=None, subject="Undated")])
        page, total = source.list_messages(None, limit=500, offset=0)
        self.assertEqual(total, 5)
        self.assertEqual([item.subject for item in page], ["Lunch", "Re: Launch", "Re: Launch", "Re: Launch", "Undated"])
        self.assertEqual(page[0].sender, (MailAddress(mf.AVERY, mf.AVERY_ADDRESS),))
        second, total = source.list_messages("inbox", limit=2, offset=1)
        self.assertEqual(([item.ref for item in second], total), ([page[1].ref, page[2].ref], 5))
        self.assertEqual(source.list_messages(None, limit=5, offset=50), ([], 5))

    def test_date_filters_are_inclusive_utc_days(self) -> None:
        source = self.mbox_source(mf.thread_messages() + [mf.message(message_id="<nodate@example.test>", date=None)])
        page, total = source.list_messages(None, limit=50, offset=0, since="2026-10-06", until="2026-10-07")
        self.assertEqual(total, 2)
        self.assertEqual({item.ref for item in page}, {expected_ref("reply-b@example.test"), expected_ref("reply-c@example.test")})
        self.assertEqual(source.list_messages(None, limit=50, offset=0, since="2026-10-08")[1], 1)
        self.assertEqual(source.list_messages(None, limit=50, offset=0, until="2026-10-04")[1], 0)

    def test_list_arguments_are_validated_before_io(self) -> None:
        source = self.source(("inbox", self.dir / "missing.mbox", "mbox"))
        cases = (
            (dict(limit=0, offset=0), "--limit must be at least 1."),
            (dict(limit=True, offset=0), "--limit must be at least 1."),
            (dict(limit=501, offset=0), "--limit must be at most 500."),
            (dict(limit=5, offset=-1), "--offset must be at least 0."),
            (dict(limit=5, offset=0, since="2026-1-01"), "Mail date filters must be YYYY-MM-DD."),
            (dict(limit=5, offset=0, until="2026-02-30"), "Mail date filters must be YYYY-MM-DD."),
            (dict(limit=5, offset=0, since="2026-10-06T00:00"), "Mail date filters must be YYYY-MM-DD."),
        )
        for kwargs, message in cases:
            with self.subTest(message=message, kwargs=kwargs):
                with self.assertRaises(SystemExit) as caught:
                    source.list_messages(None, **kwargs)  # type: ignore[arg-type]
                self.assertEqual(str(caught.exception), message)
                self.assertIn(message, MAIL_SAFE_MESSAGES)
        with self.assertRaises(SystemExit) as caught:
            source.list_messages("secret-unknown-alias", limit=5, offset=0)
        self.assertEqual(str(caught.exception), "Unknown mailbox alias.")

    def test_threads_are_connected_components_oldest_first(self) -> None:
        source = self.mbox_source(mf.thread_messages())
        root = expected_ref("root@example.test")
        messages, total = source.thread_messages(expected_ref("reply-c@example.test"), max_messages=50)
        self.assertEqual(total, 3)
        self.assertEqual(
            [message.ref for message in messages],
            [expected_ref("reply-a@example.test"), expected_ref("reply-b@example.test"), expected_ref("reply-c@example.test")],
        )
        self.assertEqual({message.thread for message in messages}, {root})
        self.assertEqual(messages[1].references, (root, expected_ref("reply-a@example.test")))
        self.assertEqual(messages[1].in_reply_to, (expected_ref("reply-a@example.test"),))
        self.assertEqual(messages[2].in_reply_to, (root,))
        limited, total = source.thread_messages(expected_ref("reply-a@example.test"), max_messages=2)
        self.assertEqual((len(limited), total), (2, 3))
        alone, total = source.thread_messages(expected_ref("unrelated@example.test"), max_messages=5)
        self.assertEqual(([message.subject for message in alone], total), (["Lunch"], 1))
        for value, message in ((0, "--max-messages must be at least 1."), (51, "--max-messages must be at most 50.")):
            with self.assertRaises(SystemExit) as caught:
                source.thread_messages(root, max_messages=value)
            self.assertEqual(str(caught.exception), message)
        with self.assertRaises(SystemExit) as caught:
            source.thread_messages(root, max_messages=5)
        self.assertEqual(str(caught.exception), UNKNOWN_REFERENCE_MESSAGE)


class MailDocumentIterationTest(MailTestCase):
    def test_documents_are_subject_plus_collapsed_body_newest_first(self) -> None:
        source = self.mbox_source(mf.thread_messages() + [mf.message(message_id="<q@example.test>", date="Fri, 09 Oct 2026 08:00:00 +0000", subject="Quoted", body="Top.\n> old\n")])
        documents = list(source.iter_documents(OperationBudget()))
        self.assertEqual(documents[0].text, "Quoted\n\nTop.\n[quoted text: 1 lines omitted]")
        self.assertEqual({document.locator for document in documents}, {"inbox"})
        self.assertEqual(documents[-1].ref, expected_ref("reply-a@example.test"))

    def test_scope_selects_mailboxes_and_refs(self) -> None:
        mbox = mf.write_mbox(self.dir / "inbox.mbox", mf.thread_messages())
        maildir = mf.write_maildir(self.dir / "Maildir", cur={"1.host": mf.message(message_id="<box@example.test>")})
        source = self.source(("inbox", mbox, "mbox"), ("box", maildir, "maildir"))
        scoped = list(source.iter_documents(OperationBudget(), scope=["box"]))
        self.assertEqual([document.ref for document in scoped], [expected_ref("box@example.test")])
        ref = expected_ref("reply-b@example.test")
        scoped = list(source.iter_documents(OperationBudget(), scope=[ref, "box", ref]))
        self.assertEqual({document.ref for document in scoped}, {ref, expected_ref("box@example.test")})
        self.assertEqual(len(scoped), 2)

    def test_scope_and_patterns_are_refused_safely(self) -> None:
        source = self.mbox_source(mf.thread_messages())
        cases = (
            (dict(patterns=["*.eml"]), "Glob patterns are not supported for mail."),
            (dict(scope=["private-unknown-alias"]), "Unknown mailbox alias."),
            (dict(scope=["@m_000000000000"]), UNKNOWN_REFERENCE_MESSAGE),
            (dict(scope=[f"{expected_ref('reply-a@example.test')}/1"]), UNKNOWN_REFERENCE_MESSAGE),
        )
        for kwargs, message in cases:
            with self.subTest(message=message):
                budget = OperationBudget()
                with self.assertRaises(SystemExit) as caught:
                    list(source.iter_documents(budget, **kwargs))  # type: ignore[arg-type]
                self.assertEqual(str(caught.exception), message)
                self.assertEqual(budget.files_seen, 0)


class MailMailboxFilterTest(MailTestCase):
    """Label folders: a message stored in an earlier mailbox too still belongs to every mailbox holding it."""

    @staticmethod
    def label_messages() -> dict[str, bytes]:
        return {
            "alpha": mf.message(message_id="<alpha@example.test>", subject="Alpha", date="Mon, 05 Oct 2026 08:00:00 +0000", body="alpha body\n"),
            "bravo": mf.message(message_id="<bravo@example.test>", subject="Bravo", date="Tue, 06 Oct 2026 08:00:00 +0000", body="bravo body\n"),
            "charlie": mf.message(message_id="<charlie@example.test>", subject="Charlie", date="Wed, 07 Oct 2026 08:00:00 +0000", body="charlie body\n"),
        }

    def label_source(self, mail_format: str) -> MailSource:
        messages = self.label_messages()
        everything = [messages["alpha"], messages["bravo"], messages["charlie"]]
        labelled = [messages["bravo"], messages["charlie"]]
        if mail_format == "mbox":
            all_path = mf.write_mbox(self.dir / mail_format / "all.mbox", everything)
            label_path = mf.write_mbox(self.dir / mail_format / "label.mbox", labelled)
        else:
            all_path = mf.write_maildir(self.dir / mail_format / "all", cur={f"{n}.host": raw for n, raw in enumerate(everything)})
            label_path = mf.write_maildir(self.dir / mail_format / "label", cur={f"{n}.host": raw for n, raw in enumerate(labelled)})
        return self.source(("all", all_path, mail_format), ("label", label_path, mail_format))

    def test_list_filters_by_every_mailbox_holding_a_message(self) -> None:
        bravo, charlie = expected_ref("bravo@example.test"), expected_ref("charlie@example.test")
        for mail_format in ("mbox", "maildir"):
            with self.subTest(format=mail_format):
                source = self.label_source(mail_format)
                page, total = source.list_messages(None, limit=50, offset=0)
                self.assertEqual(total, 3)
                self.assertEqual({item.mailbox for item in page}, {"all"})
                label, total = source.list_messages("label", limit=50, offset=0)
                self.assertEqual(total, 2)
                self.assertEqual([(item.ref, item.mailbox) for item in label], [(charlie, "label"), (bravo, "label")])
                second, total = source.list_messages("label", limit=1, offset=1)
                self.assertEqual(([item.ref for item in second], total), ([bravo], 2))
                self.assertEqual(source.list_messages("label", limit=50, offset=0, since="2026-10-07")[1], 1)
                self.assertEqual(source.list_messages("all", limit=50, offset=0)[1], 3)
                # Ref resolution stays first-wins in config order.
                self.assertEqual(source.read_message(bravo).mailbox, "all")
                self.assertEqual(len(source.thread_messages(bravo, max_messages=5)[0]), 1)

    def test_document_scope_reads_every_message_in_the_mailbox(self) -> None:
        alpha, bravo, charlie = (expected_ref(f"{name}@example.test") for name in ("alpha", "bravo", "charlie"))
        for mail_format in ("mbox", "maildir"):
            with self.subTest(format=mail_format):
                source = self.label_source(mail_format)
                scoped = list(source.iter_documents(OperationBudget(), scope=["label"]))
                self.assertEqual([(document.ref, document.locator) for document in scoped], [(charlie, "label"), (bravo, "label")])
                self.assertEqual(scoped[1].text, "Bravo\n\nbravo body\n")
                both = list(source.iter_documents(OperationBudget(), scope=["label", "all"]))
                self.assertEqual([document.ref for document in both], [charlie, bravo, alpha])
                self.assertEqual([document.locator for document in both], ["all", "all", "all"])
                mixed = list(source.iter_documents(OperationBudget(), scope=[alpha, "label"]))
                self.assertEqual([(document.ref, document.locator) for document in mixed], [(charlie, "label"), (bravo, "label"), (alpha, "all")])
                self.assertEqual(len(list(source.iter_documents(OperationBudget()))), 3)


class MailSafeMessagesTest(unittest.TestCase):
    def test_safe_messages_are_input_free_constants(self) -> None:
        for message in MAIL_SAFE_MESSAGES:
            self.assertIsInstance(message, str)
            self.assertNotIn("{", message)
        for message in (
            "Mailbox could not be read.",
            "Mailbox changed during read. Retry.",
            "Unknown mailbox alias.",
            "Mailbox message limit exceeded.",
            "Mail message byte limit exceeded.",
            "Mail reference collision.",
            "Unsupported attachment type.",
            UNKNOWN_REFERENCE_MESSAGE,
            DISABLED_MESSAGE,
        ):
            self.assertIn(message, MAIL_SAFE_MESSAGES)

    def test_config_defaults_match_the_module_constants(self) -> None:
        config = MailSourceConfig(path="x", format="mbox")
        self.assertEqual(
            (config.max_messages, config.max_message_bytes),
            (mail.DEFAULT_MAIL_MAX_MESSAGES, mail.DEFAULT_MAIL_MAX_MESSAGE_BYTES),
        )


class MailConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.env_patch = patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": self.state_tmp.name})
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()
        self.state_tmp.cleanup()

    def write_config(self, mail_tables: str) -> None:
        (self.root / ".agent-context-redactor.toml").write_text(
            f'{mail_tables}\n[redaction]\nsalt = "{SALT}"\n', encoding="utf-8"
        )

    def test_mail_sources_are_parsed_with_defaults_and_resolved_paths(self) -> None:
        outside = Path(self.state_tmp.name).resolve() / "outside.mbox"
        self.write_config(
            "[mail.sources.inbox]\npath = \"exports/inbox.mbox\"\nformat = \"mbox\"\n"
            f"[mail.sources.archive]\npath = '{outside}'\nformat = \"maildir\"\n"
            "max_messages = 10\nmax_message_bytes = 2048\n"
        )
        config = core.load_config(self.root, None)
        self.assertEqual(list(config.mail_sources), ["inbox", "archive"])
        self.assertEqual(
            config.mail_sources["inbox"],
            MailSourceConfig(path=str(self.root / "exports" / "inbox.mbox"), format="mbox"),
        )
        self.assertEqual(
            config.mail_sources["archive"],
            MailSourceConfig(path=str(outside), format="maildir", max_messages=10, max_message_bytes=2048),
        )
        self.assertIn("exports/inbox.mbox", config.protected_paths)
        self.assertEqual(len(config.protected_paths), 1)
        self.assertNotIn("inbox.mbox", " ".join(config.terms))
        self.assertEqual(core.load_config(self.root, None), config)

    def test_home_relative_paths_are_expanded(self) -> None:
        home = Path(self.state_tmp.name).resolve() / "home"
        self.write_config('[mail.sources.inbox]\npath = "~/mail/inbox.mbox"\nformat = "mbox"\n')
        with patch.dict(os.environ, {"HOME": str(home), "USERPROFILE": str(home)}):
            config = core.load_config(self.root, None)
        self.assertEqual(config.mail_sources["inbox"].path, str(home / "mail" / "inbox.mbox"))

    def test_without_mail_tables_nothing_changes(self) -> None:
        self.write_config("")
        config = core.load_config(self.root, None)
        self.assertEqual(config.mail_sources, {})
        self.assertIsNone(MailSource.from_config(config))
        self.assertEqual(build_sources(self.root, config).names(), ("filesystem",))
        self.assertIsNone(build_sources(self.root, config).mail)

    def test_invalid_tables_fail_with_input_free_messages(self) -> None:
        private = "private-mailbox-name"
        cases = (
            ("mail = 'x'\n", "Expected [mail.sources.<alias>] tables in redaction config."),
            ("[mail]\nsources = 'x'\n", "Expected [mail.sources.<alias>] tables in redaction config."),
            ("[mail.sources]\nsecret-alias = 'x'\n", "Expected [mail.sources.<alias>] tables in redaction config."),
            (f"[mail.sources.'-{private}']\npath = 'a'\nformat = 'mbox'\n", "Mail source alias is invalid."),
            (f"[mail.sources.'has space {private}']\npath = 'a'\nformat = 'mbox'\n", "Mail source alias is invalid."),
            (f"[mail.sources.{'a' * 65}]\npath = 'a'\nformat = 'mbox'\n", "Mail source alias is invalid."),
            (f"[mail.sources.{private}]\nformat = 'mbox'\n", "Mail source config requires path and format."),
            (f"[mail.sources.{private}]\npath = '{private}.mbox'\n", "Mail source config requires path and format."),
            (f"[mail.sources.{private}]\npath = ' '\nformat = 'mbox'\n", "Mail source config requires path and format."),
            (f"[mail.sources.{private}]\npath = '{private}'\nformat = 'imap'\n", "Mail source format must be mbox, maildir, or eml."),
            (f"[mail.sources.{private}]\npath = '{private}'\nformat = 'mbox'\nmax_messages = 0\n", "Mail source limits must be positive integers within range."),
            (f"[mail.sources.{private}]\npath = '{private}'\nformat = 'mbox'\nmax_messages = true\n", "Mail source limits must be positive integers within range."),
            (f"[mail.sources.{private}]\npath = '{private}'\nformat = 'mbox'\nmax_messages = 1000001\n", "Mail source limits must be positive integers within range."),
            (f"[mail.sources.{private}]\npath = '{private}'\nformat = 'mbox'\nmax_message_bytes = 1.5\n", "Mail source limits must be positive integers within range."),
            (f"[mail.sources.{private}]\npath = '{private}'\nformat = 'mbox'\nmax_message_bytes = 1073741825\n", "Mail source limits must be positive integers within range."),
            (f"[mail.sources.{private}]\npath = '.'\nformat = 'maildir'\n", "Mail source path must not be the served root."),
            (f"[mail.sources.{private}]\npath = '{self.root.as_posix()}'\nformat = 'eml'\n", "Mail source path must not be the served root."),
        )
        for tables, message in cases:
            with self.subTest(message=message, tables=tables):
                self.write_config(tables)
                with self.assertRaises(SystemExit) as caught:
                    core.load_config(self.root, None)
                self.assertEqual(str(caught.exception), message)
                self.assertNotIn(private, str(caught.exception))
                self.assertNotIn(str(self.root), str(caught.exception))

    def test_missing_mailbox_is_allowed_at_load_and_fails_at_access(self) -> None:
        self.write_config('[mail.sources.inbox]\npath = "not-yet/private.mbox"\nformat = "mbox"\n')
        config = core.load_config(self.root, None)
        source = build_sources(self.root, config).mail
        assert source is not None
        with self.assertRaises(SystemExit) as caught:
            source.list_messages(None, limit=5, offset=0)
        self.assertEqual(str(caught.exception), "Mailbox could not be read.")

    def test_mailboxes_under_the_root_are_never_served_by_file_tools(self) -> None:
        marker = "UniqueMailboxBodyMarker"
        messages = [mf.message(body=f"{marker} in the export.\n")]
        mf.write_mbox(self.root / "exports" / "inbox.txt", messages)
        mf.write_maildir(self.root / "Maildir", cur={"1.txt": messages[0]})
        mf.write_eml_tree(self.root / "eml", {"a.eml": messages[0]})
        self.write_config("")
        plain = server.RedactedContextMcp(root=self.root, config_path=None, mode="strict", include_private=False)
        self.assertFalse(plain.call_tool("redctx_read", {"path": "exports/inbox.txt"})["isError"])

        self.write_config(
            '[mail.sources.inbox]\npath = "exports/inbox.txt"\nformat = "mbox"\n'
            '[mail.sources.box]\npath = "Maildir"\nformat = "maildir"\n'
            '[mail.sources.eml]\npath = "eml"\nformat = "eml"\n'
        )
        config = core.load_config(self.root, None)
        self.assertEqual(set(config.protected_paths), {"exports/inbox.txt", "Maildir", "eml"})
        registry = build_sources(self.root, config)
        self.assertEqual(registry.names(), ("filesystem", "mail"))
        self.assertIsInstance(registry.mail, MailSource)
        ctx = registry.filesystem
        for rel in ("exports/inbox.txt", "Maildir/cur/1.txt", "eml/a.eml"):
            self.assertTrue(ctx.is_excluded(self.root / rel), rel)
        self.assertEqual(list(ctx.iter_documents(OperationBudget())), [])
        mcp = server.RedactedContextMcp(root=self.root, config_path=None, mode="strict", include_private=True)
        for tool, arguments in (
            ("redctx_read", {"path": "exports/inbox.txt"}),
            ("redctx_read", {"path": "Maildir/cur/1.txt"}),
        ):
            with self.subTest(tool=tool, arguments=arguments):
                result = mcp.call_tool(tool, arguments)
                self.assertTrue(result["isError"])
                self.assertNotIn(marker, result["structuredContent"]["text"])
        result = mcp.call_tool("redctx_search", {"query": marker})
        self.assertNotIn(marker, repr(result))
        self.assertNotIn("inbox.txt", repr(result))

    def test_build_sources_passes_documents_through(self) -> None:
        self.write_config('[mail.sources.inbox]\npath = "inbox.mbox"\nformat = "mbox"\n')
        config = core.load_config(self.root, None)
        with patch("redacted_context_mcp.filesystem.require_document_support"):
            registry = build_sources(self.root, config, documents=True)
        assert registry.mail is not None
        self.assertTrue(registry.mail.documents)
        self.assertFalse(build_sources(self.root, config).mail.documents)  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
