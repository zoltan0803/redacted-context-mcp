"""Tests for the 0.7.0 security hardening changes."""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core, server
from redacted_context_mcp.discovery import OllamaDiscoveryClient
from redacted_context_mcp.models import RedactionConfig
from redacted_context_mcp.redaction import Redactor


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}

TEST_SALT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PERSON_NAME = "Taylor Reed"
UNIQUE_NAME = "Zephyr Quill"


def person_placeholder(name: str, salt: str = TEST_SALT) -> str:
    return category_placeholder("PERSON", name, salt=salt)


def category_placeholder(category: str, name: str, salt: str = TEST_SALT) -> str:
    normalized = " ".join(name.split()).casefold()
    digest = hmac.new(
        salt.encode("utf-8"),
        f"{category}:{normalized}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]
    return f"[{category}_{digest}]"


class FakeChunkStream:
    """Minimal stream exposing read1 like a buffered stdin."""

    def __init__(self, data: bytes, chunk_size: int = 7) -> None:
        self._view = memoryview(data)
        self._chunk_size = chunk_size

    def read1(self, size: int) -> bytes:  # noqa: D102 - test double
        take = min(size, self._chunk_size, len(self._view))
        chunk = bytes(self._view[:take])
        self._view = self._view[take:]
        return chunk


class NeverServeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / ".agent-context-redactor.toml").write_text(
            f'[redaction]\nsalt = "{TEST_SALT}"\npeople = ["{PERSON_NAME}"]\nterm_files = ["extra-terms.txt"]\n',
            encoding="utf-8",
        )
        (self.root / "extra-terms.txt").write_text(f"{PERSON_NAME}\n", encoding="utf-8")
        (self.root / "notes.md").write_text(f"{PERSON_NAME} overview.\n", encoding="utf-8")
        (self.root / ".env").write_text("PASSWORD=super-secret-value\n", encoding="utf-8")
        (self.root / "server.key").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
        (self.root / "server.pem").write_text("cert\n", encoding="utf-8")
        self.addCleanup(self.tmp.cleanup)

    def make_context(self, include_private: bool):
        from redacted_context_mcp.config import load_config
        from redacted_context_mcp.filesystem import RedactedContext

        config = load_config(self.root, None)
        return RedactedContext(self.root, config, include_private=include_private)

    def test_never_serve_files_excluded_even_with_include_private(self) -> None:
        ctx = self.make_context(include_private=True)
        for name in (
            ".agent-context-redactor.toml",
            "extra-terms.txt",
            ".env",
            "server.key",
            "server.pem",
        ):
            self.assertTrue(ctx.is_excluded(ctx.root / name), name)

    def test_include_private_still_serves_normal_files(self) -> None:
        ctx = self.make_context(include_private=True)
        self.assertFalse(ctx.is_excluded(ctx.root / "notes.md"))

    def test_mcp_read_of_never_serve_file_is_rejected(self) -> None:
        mcp = server.RedactedContextMcp(
            root=self.root,
            config_path=None,
            mode="strict",
            include_private=True,
        )
        result = mcp.call_tool("redctx_read", {"path": ".agent-context-redactor.toml"})
        self.assertTrue(result["isError"])
        text = result["structuredContent"]["text"]
        self.assertNotIn(TEST_SALT, text)

    def test_bare_hex_salt_value_is_redacted(self) -> None:
        redactor = Redactor(RedactionConfig(salt=TEST_SALT))
        text = f"salt echo {TEST_SALT} end"
        redacted = redactor.redact(text)
        self.assertNotIn(TEST_SALT, redacted)
        self.assertIn("[SECRET_", redacted)

    def test_salt_assignment_is_redacted(self) -> None:
        redactor = Redactor(RedactionConfig(salt=TEST_SALT))
        redacted = redactor.redact('salt = "my-local-vault-passphrase"')
        self.assertNotIn("my-local-vault-passphrase", redacted)
        self.assertIn("[SECRET_", redacted)

    def test_google_api_key_is_redacted(self) -> None:
        redactor = Redactor(RedactionConfig(salt=TEST_SALT))
        key = "AIza" + "a" * 35
        redacted = redactor.redact(f"key {key} end")
        self.assertNotIn(key, redacted)
        self.assertIn("[SECRET_", redacted)

    def test_normal_hex_fragments_survive(self) -> None:
        redactor = Redactor(RedactionConfig(salt=TEST_SALT))
        text = "short hex cafebabe and git 40-char 0123456789abcdef0123456789abcdef01234567"
        redacted = redactor.redact(text)
        self.assertIn("cafebabe", redacted)

    def test_longer_hex_runs_are_redacted(self) -> None:
        redactor = Redactor(RedactionConfig(salt=TEST_SALT))
        for length in (64, 65, 128):
            with self.subTest(length=length):
                value = "f" * length
                redacted = redactor.redact(f"digest {value} end")
                self.assertNotIn(value, redacted)

    def test_salt_assignment_variants_are_redacted(self) -> None:
        redactor = Redactor(RedactionConfig(salt=TEST_SALT))
        cases = (
            ('salt = "my-local-vault-passphrase"', "my-local-vault-passphrase"),
            ("salt:hunter2", "hunter2"),
            ('salt="x"', None),
            ('salt = """multiline-salt-value-1234"""', "multiline-salt-value-1234"),
            ("salt = 'correct horse battery'", "correct horse battery"),
            ("vault_salt: another secret value", "another secret value"),
        )
        for text, raw in cases:
            with self.subTest(text=text):
                redacted = redactor.redact(text)
                self.assertIn("[SECRET_", redacted)
                if raw is not None:
                    self.assertNotIn(raw, redacted)

    def test_underscore_qualified_secrets_are_redacted(self) -> None:
        redactor = Redactor(RedactionConfig(salt=TEST_SALT))
        redacted = redactor.redact("DB_PASSWORD=hunter2boogaloo and API_TOKEN=abcdefghijklmnop")
        self.assertNotIn("hunter2boogaloo", redacted)
        self.assertNotIn("abcdefghijklmnop", redacted)

    def test_case_mangled_never_serve_files_are_excluded(self) -> None:
        # On case-insensitive filesystems these are the same files as their
        # lowercase forms; use TOML-valid content in case of an overwrite.
        for name in (".ENV", "server.PEM", "SERVER.Key", "host.CRT", ".Agent-Context-Redactor.toml"):
            (self.root / name).write_text('note = "secret payload"\n', encoding="utf-8")
        ctx = self.make_context(include_private=True)
        for name in (".ENV", "server.PEM", "SERVER.Key", "host.CRT", ".Agent-Context-Redactor.toml"):
            with self.subTest(name=name):
                self.assertTrue(ctx.is_excluded(ctx.root / name), name)

    def test_case_mangled_config_read_is_rejected_over_mcp(self) -> None:
        (self.root / ".ENV").write_text("DB_PASSWORD=hunter2boogaloo\n", encoding="utf-8")
        mcp = server.RedactedContextMcp(
            root=self.root,
            config_path=None,
            mode="strict",
            include_private=True,
        )
        result = mcp.call_tool("redctx_read", {"path": ".ENV"})
        self.assertTrue(result["isError"])
        self.assertNotIn("hunter2boogaloo", result["structuredContent"]["text"])

    def test_explicit_config_file_is_protected(self) -> None:
        (self.root / "myconfig.toml").write_text(
            f'[redaction]\nsalt = "short"\npeople = ["{PERSON_NAME}"]\n',
            encoding="utf-8",
        )
        mcp = server.RedactedContextMcp(
            root=self.root,
            config_path=self.root / "myconfig.toml",
            mode="strict",
            include_private=False,
        )
        result = mcp.call_tool("redctx_read", {"path": "myconfig.toml"})
        self.assertTrue(result["isError"])
        text = result["structuredContent"]["text"]
        self.assertNotIn("short", text)

    def test_github_owner_and_repo_become_terms(self) -> None:
        (self.root / ".agent-context-redactor.toml").write_text(
            f'[redaction]\nsalt = "{TEST_SALT}"\n'
            "[github.repos.context]\nowner = \"acme-internal-org\"\nrepo = \"private-context\"\n",
            encoding="utf-8",
        )
        (self.root / "notes.md").write_text(
            "See acme-internal-org/private-context for details.\n",
            encoding="utf-8",
        )
        mcp = server.RedactedContextMcp(
            root=self.root,
            config_path=None,
            mode="strict",
            include_private=False,
        )
        result = mcp.call_tool("redctx_read", {"path": "notes.md"})
        text = result["structuredContent"]["text"]
        self.assertNotIn("acme-internal-org", text)
        self.assertNotIn("private-context", text)


class RegexSafetyTest(unittest.TestCase):
    def test_unsafe_patterns_are_flagged(self) -> None:
        for pattern in (
            "(a+)+",
            "(a+)+$",
            r"(\w*)+",
            r"(\w+)*x",
            "((a+))+",
            "(a+)+b",
            "(?:a|a)+",
            "(a|a)*b",
            "(a|ab)+",
            "(x[0-9]+y)+",
            # Second-round review findings: dot and negated-class ambiguity,
            # nested-group hazards, and high-repetition bounded quantifiers.
            r"(?:.|[^a])+Q",
            r"([^b]z|az)+q",
            r"((a|a)x)+z",
            "(a|aa){0,60}b",
            "(a{1,2}){1,60}b",
            "(a?){40}b",
            r"(?:a{0,3}){0,30}c",
        ):
            with self.subTest(pattern=pattern):
                self.assertIsNotNone(core.regex_backtracking_violation(pattern))

    def test_safe_patterns_are_allowed(self) -> None:
        for pattern in (
            "needle",
            r"\d+",
            "[a-z]+",
            "(ab)+c",
            "(?:foo|bar)+",
            r"(?:\d{1,3}\.){3}\d{1,3}",
            "a?",
            "x{2,4}",
            "^(?:TODO|NOTE):",
            r"\b\w+@\w+\.com\b",
            r"(?:\d{1,3}\.){8}\d",
        ):
            with self.subTest(pattern=pattern):
                self.assertIsNone(core.regex_backtracking_violation(pattern))

    def test_grep_rejects_pathological_regex_quickly(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "big.md").write_text("a" * 60 + "\n", encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "redacted_context_mcp.core",
                "--root",
                str(root),
                "search",
                "(a+)+$",
                ".",
                "--regex",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            cwd=PROJECT_ROOT,
            env=ENV,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("a" * 60, result.stdout + result.stderr)

    def test_grep_deadline_stops_scan(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for index in range(5):
            (root / f"file{index}.md").write_text("needle\n", encoding="utf-8")
        ctx = core.RedactedContext(root, RedactionConfig(salt=TEST_SALT))
        redactor = Redactor(RedactionConfig(salt=TEST_SALT))
        args = Namespace(
            query="needle",
            paths=[],
            glob=[],
            ignore_case=False,
            regex=False,
            context=0,
            max_results=10,
            # Negative: deadline is deterministically in the past even on
            # Windows, where time.monotonic() has ~15.6ms resolution on
            # Python <= 3.12 and a zero-second deadline may not tick over.
            max_seconds=-1,
        )
        with self.assertRaises(SystemExit):
            core.command_grep(args, ctx, redactor)

    def test_mcp_search_applies_deadline(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "notes.md").write_text("content\n", encoding="utf-8")
        captured: list[float | None] = []

        original = core.command_grep

        def recording_grep(args, ctx, redactor):
            captured.append(getattr(args, "max_seconds", None))
            return original(args, ctx, redactor)

        with patch.object(core, "command_grep", recording_grep):
            mcp = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False)
            mcp.call_tool("redctx_search", {"query": "content", "regex": True})

        self.assertEqual(captured, [server.rc.DEFAULT_MCP_SEARCH_SECONDS])


class RequestLineCapTest(unittest.TestCase):
    def test_normal_lines_are_yielded(self) -> None:
        stream = FakeChunkStream(b'{"a": 1}\n{"b": 2}\n')
        lines = list(server.iter_request_lines(stream, 1024))
        self.assertEqual(lines, [b'{"a": 1}', b'{"b": 2}'])

    def test_oversized_line_reports_none_and_continues(self) -> None:
        payload = b"x" * 40 + b"\n" + b'{"ok": true}\n'
        stream = FakeChunkStream(payload)
        lines = list(server.iter_request_lines(stream, 32))
        self.assertEqual(lines, [None, b'{"ok": true}'])

    def test_oversized_trailing_chunk_without_newline(self) -> None:
        stream = FakeChunkStream(b'{"a": 1}\n' + b"y" * 64)
        lines = list(server.iter_request_lines(stream, 32))
        self.assertEqual(lines, [b'{"a": 1}', None])

    def test_oversized_exact_line_without_newline_at_eof_reports_error(self) -> None:
        # Exactly one over the cap with no further data: the overflow flag is
        # set and the buffer is empty at EOF, which must still report None.
        stream = FakeChunkStream(b'{"a": 1}\n' + b"y" * 33)
        lines = list(server.iter_request_lines(stream, 32))
        self.assertEqual(lines, [b'{"a": 1}', None])


class RegexWorkerIsolationTest(unittest.TestCase):
    def test_worker_returns_matches_for_safe_pattern(self) -> None:
        matched = core.match_regex_lines(r"needle", 0, [["no", "needle here", "nope"]], 30.0)
        self.assertEqual(matched, [[1]])

    def test_worker_is_killed_on_timeout_for_catastrophic_pattern(self) -> None:
        # Bypasses the screen deliberately: this exercises the enforcement
        # boundary (killable child process), not the fast-fail screen.
        started = time.monotonic()
        with self.assertRaises(SystemExit) as raised:
            core.match_regex_lines("(a|aa){0,60}b", 0, [["a" * 60]], 1.0)
        elapsed = time.monotonic() - started
        self.assertIn("deadline", str(raised.exception))
        self.assertLess(elapsed, 20.0)

    def test_mcp_regex_search_is_bounded_by_worker(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "big.md").write_text("a" * 60 + "\n", encoding="utf-8")
        mcp = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False)
        result = mcp.call_tool("redctx_search", {"query": "a{50,60}", "regex": True})
        self.assertFalse(result["isError"], result["structuredContent"]["text"])
        self.assertIn("a" * 50, result["structuredContent"]["text"])


class ServeOversizedLineTest(unittest.TestCase):
    def test_serve_rejects_oversized_line_then_serves_next_request(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "notes.md").write_text("content\n", encoding="utf-8")
        mcp = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False)

        oversized = b'{"id": 1, "method": "ping", "params": {"pad": "' + b"x" * 300 + b'"}}\n'
        valid = b'{"id": 2, "method": "ping", "params": {}}\n'

        captured: list[dict[str, object]] = []

        def fake_write_response(request_id, *, result=None, error=None) -> None:
            captured.append({"id": request_id, "result": result, "error": error})

        with patch.object(server, "write_response", fake_write_response), patch.object(
            server, "MAX_REQUEST_LINE_BYTES", 128
        ):
            server.serve(mcp, stream=FakeChunkStream(oversized + valid))

        self.assertEqual(len(captured), 2)
        self.assertEqual(captured[0]["id"], None)
        self.assertEqual(captured[0]["error"]["code"], -32600)
        self.assertEqual(captured[1]["id"], 2)
        self.assertIsNone(captured[1]["error"])


class SubmitDocHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / ".agent-context-redactor.toml").write_text(
            f'[redaction]\nsalt = "{TEST_SALT}"\npeople = ["{PERSON_NAME}"]\nterms = ["Project Meridian"]\n',
            encoding="utf-8",
        )
        (self.root / "notes.md").write_text(
            f"{PERSON_NAME} wrote the assessment for Project Meridian.\n",
            encoding="utf-8",
        )
        incoming = self.root / "incoming"
        incoming.mkdir()
        (incoming / "preexisting.md").write_text(f"{UNIQUE_NAME} draft only in write dir.\n", encoding="utf-8")
        self.mcp = server.RedactedContextMcp(
            root=self.root,
            config_path=None,
            mode="strict",
            include_private=False,
            enable_writes=True,
            write_subdir="incoming",
        )
        self.addCleanup(self.tmp.cleanup)

    def test_submit_rejects_value_glued_into_token(self) -> None:
        placeholder = person_placeholder(PERSON_NAME)
        result = self.mcp.call_tool(
            "redctx_submit_doc",
            {"target_path": "reviews/leak.md", "text": f"foo{placeholder}bar wrote it"},
        )
        self.assertTrue(result["isError"])
        text = result["structuredContent"]["text"]
        self.assertNotIn(PERSON_NAME, text)
        self.assertIn("redact consistently", text)

    def test_submit_accepts_clean_rehydrated_text(self) -> None:
        placeholder = person_placeholder(PERSON_NAME)
        result = self.mcp.call_tool(
            "redctx_submit_doc",
            {"target_path": "reviews/summary.md", "text": f"Reviewer {placeholder} approved."},
        )
        self.assertFalse(result["isError"], result["structuredContent"]["text"])

    def test_write_subdir_is_not_a_rehydration_source(self) -> None:
        placeholder = person_placeholder(UNIQUE_NAME)
        result = self.mcp.call_tool(
            "redctx_submit_doc",
            {"target_path": "reviews/draft.md", "text": f"Draft by {placeholder}."},
        )
        self.assertTrue(result["isError"])
        text = result["structuredContent"]["text"]
        self.assertIn("Unresolved redaction token(s)", text)

    def test_interactive_read_of_write_dir_cannot_seed_map(self) -> None:
        # Reading a write-subdir file populates the redactor's alias table,
        # but the submit map must still be derived solely from the corpus walk.
        read = self.mcp.call_tool("redctx_read", {"path": "incoming/preexisting.md"})
        self.assertFalse(read["isError"])
        placeholder = person_placeholder(UNIQUE_NAME)
        result = self.mcp.call_tool(
            "redctx_submit_doc",
            {"target_path": "reviews/seeded.md", "text": f"Draft by {placeholder}."},
        )
        self.assertTrue(result["isError"])
        self.assertIn("Unresolved redaction token(s)", result["structuredContent"]["text"])

    def test_large_write_subdir_is_pruned_from_submit_scan(self) -> None:
        incoming = self.root / "incoming"
        for index in range(50):
            (incoming / f"agent-output-{index}.md").write_text(
                "agent generated content\n",
                encoding="utf-8",
            )

        limited = server.RedactedContextMcp(
            root=self.root,
            config_path=None,
            mode="strict",
            include_private=False,
            enable_writes=True,
            write_subdir="incoming",
            # Root + its three direct entries fit exactly. Descending into
            # incoming would exceed this budget before scanning notes.md.
            max_traversal_entries=4,
        )
        placeholder = person_placeholder(PERSON_NAME)
        result = limited.call_tool(
            "redctx_submit_doc",
            {
                "target_path": "reviews/pruned.md",
                "text": f"Reviewer {placeholder} approved.",
            },
        )

        self.assertFalse(result["isError"], result["structuredContent"]["text"])
        self.assertTrue((incoming / "reviews" / "pruned.md").exists())

    def test_glue_that_only_balanced_mode_would_leak_is_rejected(self) -> None:
        # "Taylor Reedapproved" redacts cleanly under strict mode (title-case
        # fallback) but leaks the surname under balanced mode, so verification
        # must run against both profiles.
        person = person_placeholder(PERSON_NAME)
        result = self.mcp.call_tool(
            "redctx_submit_doc",
            {"target_path": "reviews/glued.md", "text": f"{person}approved and noted."},
        )
        self.assertTrue(result["isError"])
        self.assertIn("redact consistently", result["structuredContent"]["text"])
        self.assertFalse((self.root / "incoming" / "reviews" / "glued.md").exists())

    def test_adjacent_placeholders_are_rejected_or_safe_in_both_modes(self) -> None:
        person = person_placeholder(PERSON_NAME)
        sensitive = category_placeholder("SENSITIVE", "project meridian")
        result = self.mcp.call_tool(
            "redctx_submit_doc",
            {"target_path": "reviews/adjacent.md", "text": f"See {person}{sensitive} notes."},
        )
        if not result["isError"]:
            for mode in ("strict", "balanced"):
                with self.subTest(mode=mode):
                    reader = server.RedactedContextMcp(
                        root=self.root,
                        config_path=None,
                        mode=mode,
                        include_private=False,
                    )
                    read = reader.call_tool("redctx_read", {"path": "incoming/reviews/adjacent.md"})
                    self.assertFalse(read["isError"])
                    text = read["structuredContent"]["text"]
                    self.assertNotIn(PERSON_NAME.split()[0], text)
                    self.assertNotIn(PERSON_NAME.split()[1], text)

    def test_clean_submit_is_safe_in_both_read_modes(self) -> None:
        placeholder = person_placeholder(PERSON_NAME)
        result = self.mcp.call_tool(
            "redctx_submit_doc",
            {"target_path": "reviews/dual.md", "text": f"Reviewer {placeholder} approved."},
        )
        self.assertFalse(result["isError"], result["structuredContent"]["text"])
        for mode in ("strict", "balanced"):
            with self.subTest(mode=mode):
                reader = server.RedactedContextMcp(
                    root=self.root,
                    config_path=None,
                    mode=mode,
                    include_private=False,
                )
                read = reader.call_tool("redctx_read", {"path": "incoming/reviews/dual.md"})
                self.assertFalse(read["isError"])
                text = read["structuredContent"]["text"]
                self.assertNotIn(PERSON_NAME, text)


class OllamaEndpointTest(unittest.TestCase):
    def test_remote_plain_http_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            OllamaDiscoveryClient(endpoint="http://example.com:11434", model="m", timeout=1)

    def test_loopback_plain_http_is_allowed(self) -> None:
        for endpoint in ("http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434", "http://localhost.:11434"):
            with self.subTest(endpoint=endpoint):
                OllamaDiscoveryClient(endpoint=endpoint, model="m", timeout=1)

    def test_https_is_allowed(self) -> None:
        OllamaDiscoveryClient(endpoint="https://llm.internal.example", model="m", timeout=1)

    def test_remote_opt_in_is_honored(self) -> None:
        OllamaDiscoveryClient(endpoint="http://example.com:11434", model="m", timeout=1, allow_remote=True)

    def test_invalid_scheme_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            OllamaDiscoveryClient(endpoint="ftp://localhost:11434", model="m", timeout=1)


class TruncationTest(unittest.TestCase):
    def test_truncate_redacted_does_not_split_placeholder_at_any_boundary(self) -> None:
        placeholder = person_placeholder(PERSON_NAME)
        prefix = "intro "
        text = prefix + placeholder + " suffix"
        for offset in range(len(placeholder) + 1):
            with self.subTest(offset=offset):
                cut = core.truncate_redacted(text, len(prefix) + offset)
                before_marker = cut.removesuffix("\n[TRUNCATED]\n")
                expected = prefix if offset < len(placeholder) else prefix + placeholder
                self.assertEqual(before_marker, expected)
                self.assertTrue(cut.endswith("[TRUNCATED]\n"))

    def test_truncate_redacted_keeps_short_text(self) -> None:
        text = "short text"
        self.assertEqual(core.truncate_redacted(text, 100), text)

    def test_cat_truncation_preserves_placeholder_tokens(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / ".agent-context-redactor.toml").write_text(
            f'[redaction]\nsalt = "{TEST_SALT}"\npeople = ["{PERSON_NAME}"]\n',
            encoding="utf-8",
        )
        (root / "notes.md").write_text(f"start {PERSON_NAME} " + "tail " * 200 + "\n", encoding="utf-8")
        from redacted_context_mcp.config import load_config

        config = load_config(root, None)
        ctx = core.RedactedContext(root, config)
        redactor = Redactor(config)
        args = Namespace(path="notes.md", start_line=None, end_line=None, max_chars=60, line_numbers=False)
        output = io.StringIO()
        with patch("sys.stdout", output):
            core.command_cat(args, ctx, redactor)
        printed = output.getvalue()
        self.assertNotIn(PERSON_NAME, printed)
        partials = re.findall(r"\[PERSON_[0-9a-f]{0,32}$", printed, re.MULTILINE)
        self.assertEqual(partials, [])


if __name__ == "__main__":
    unittest.main()
