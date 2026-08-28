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
    normalized = " ".join(name.split()).casefold()
    digest = hmac.new(
        salt.encode("utf-8"),
        f"PERSON:{normalized}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]
    return f"[PERSON_{digest}]"


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
            max_seconds=0,
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
            f'[redaction]\nsalt = "{TEST_SALT}"\npeople = ["{PERSON_NAME}"]\n',
            encoding="utf-8",
        )
        (self.root / "notes.md").write_text(f"{PERSON_NAME} wrote the assessment.\n", encoding="utf-8")
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


class OllamaEndpointTest(unittest.TestCase):
    def test_remote_plain_http_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            OllamaDiscoveryClient(endpoint="http://example.com:11434", model="m", timeout=1)

    def test_loopback_plain_http_is_allowed(self) -> None:
        for endpoint in ("http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434"):
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
    def test_truncate_redacted_does_not_split_placeholder(self) -> None:
        placeholder = person_placeholder(PERSON_NAME)
        text = "intro " + placeholder
        cut = core.truncate_redacted(text, 10)
        self.assertNotIn("[PERSON_", cut)
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
        partials = re.findall(r"\[PERSON_[0-9a-f]{1,31}$", printed, re.MULTILINE)
        self.assertEqual(partials, [])


if __name__ == "__main__":
    unittest.main()
