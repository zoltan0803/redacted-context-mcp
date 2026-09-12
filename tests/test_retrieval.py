from __future__ import annotations

import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from redacted_context_mcp import core, retrieval, server
from redacted_context_mcp.filesystem import RedactedContext
from redacted_context_mcp.limits import OperationBudget, OperationLimitError
from redacted_context_mcp.models import RedactionConfig
from redacted_context_mcp.redaction import Redactor


class RetrievalTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.config = RedactionConfig(salt="retrieval-test", terms=("quokkaproject",))
        self.ctx = RedactedContext(self.root, self.config)
        self.redactor = Redactor(self.config, mode="balanced")

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def retrieve(self, query: str, **kwargs) -> str:
        options = dict(paths=[], globs=[], budget=OperationBudget(max_files=80))
        options.update(kwargs)
        return retrieval.retrieve(self.ctx, self.redactor, query, **options)

    def test_multiword_coverage_beats_repeated_single_word_in_first_file(self) -> None:
        self.write("a.txt", "backup " * 100)
        self.write("z.txt", "database recovery\n\nbackup procedures for PostgreSQL\n")
        result = self.retrieve("database backup recovery")
        self.assertIn(self.ctx.display_ref("z.txt"), result.splitlines()[0])
        self.assertIn("lines 1-3", result.splitlines()[0])
        self.assertIn("database recovery\n\nbackup procedures", result)

    def test_case_and_unicode_words(self) -> None:
        self.write("notes.txt", "árvíz recovery database\n")
        self.assertIn("@p_", self.retrieve("ÁRVÍZ DATABASE"))

    def test_private_query_cannot_match_raw_text_or_filename(self) -> None:
        self.write("quokkaproject.txt", "quokkaproject database backup\n")
        self.assertEqual("No matches.\n", self.retrieve("quokkaproject"))
        result = self.retrieve("database backup")
        self.assertNotIn("quokkaproject", result)
        self.assertIn("[SENSITIVE_", result)

    def test_placeholder_is_searchable_as_one_token(self) -> None:
        self.write("notes.txt", "quokkaproject database backup\n")
        placeholder = self.redactor.redact("quokkaproject")
        self.assertIn(placeholder, self.retrieve(placeholder))
        self.assertEqual("No matches.\n", self.retrieve("SENSITIVE"))

    def test_paths_globs_and_exclusions_are_respected(self) -> None:
        self.write("docs/a.md", "backup database\n")
        self.write("docs/b.txt", "backup database\n")
        self.write("personal/c.md", "private-file-canary backup database\n")
        self.write(".env", "private-env-canary backup database\n")
        result = self.retrieve("backup", paths=[self.ctx.display_ref("docs")], globs=["*.md"])
        self.assertIn(self.ctx.display_ref("docs/a.md"), result)
        self.assertNotIn(self.ctx.display_ref("docs/b.txt"), result)
        self.assertNotIn("canary", result)
        with self.assertRaises(SystemExit):
            self.retrieve("backup", paths=["../outside"])

    def test_multiline_secrets_are_redacted_before_passage_splitting(self) -> None:
        self.write("notes.txt", "\n" * 23 + "-----BEGIN PRIVATE KEY-----\nraw-secret-canary\n-----END PRIVATE KEY-----\nbackup database\n")
        result = self.retrieve("backup")
        self.assertNotIn("raw-secret-canary", result)
        self.assertNotIn("PRIVATE KEY", result)

    def test_line_citations_match_read_tool_ranges(self) -> None:
        raw = "\n".join(["ordinary text"] * 27 + ["backup database"] + ["more text"] * 3)
        self.write("notes.txt", raw)
        result = self.retrieve("backup")
        match = re.search(r"lines (\d+)-(\d+)", result)
        self.assertIsNotNone(match)
        start, end = map(int, match.groups())
        self.assertIn("\n".join(raw.splitlines()[start - 1:end]), result)

    def test_long_line_chunks_preserve_placeholders(self) -> None:
        placeholder = self.redactor.redact("quokkaproject")
        text = "x" * 1580 + placeholder + "y" * 1700
        chunks = list(retrieval.passages(text))
        self.assertEqual(text, "".join(chunk[2] for chunk in chunks))
        self.assertTrue(any(placeholder in chunk[2] for chunk in chunks))
        self.assertTrue(all(start == end == 1 for start, end, _ in chunks))
        self.assertTrue(all(len(value) <= retrieval.PASSAGE_CHARS for _, _, value in chunks))

    def test_result_and_output_limits_and_deterministic_ties(self) -> None:
        for name in ("a.txt", "b.txt", "c.txt"):
            self.write(name, "database backup\n")
        result = self.retrieve("database", max_results=1, max_chars=512)
        self.assertEqual(result, self.retrieve("database", max_results=1, max_chars=512))
        self.assertEqual(result.count("--- @p_"), 1)
        self.assertIn("TRUNCATED", result)
        self.assertLessEqual(len(result), 512)

    def test_invalid_queries_and_limits_fail_without_echoing_input(self) -> None:
        for query in ("", "the and is", "x" * 2001):
            with self.assertRaises(SystemExit):
                self.retrieve(query)
        for options in ({"max_results": 51}, {"max_chars": 100_001}, {"max_chars": 0}):
            with self.assertRaises(SystemExit):
                self.retrieve("backup", **options)

    def test_scan_limits_do_not_present_incomplete_rankings(self) -> None:
        self.write("a.txt", "backup database\n")
        with self.assertRaises(OperationLimitError):
            self.retrieve("backup", budget=OperationBudget(max_files=0))
        with patch.object(retrieval, "MAX_PASSAGES", 0):
            with self.assertRaises(OperationLimitError):
                self.retrieve("backup")

    def test_mcp_tool_receipt_and_live_reload(self) -> None:
        config_path = self.write(".agent-context-redactor.toml", '[redaction]\nsalt = "retrieval-test"\n')
        self.write("notes.txt", "quokkaproject database backup\n")
        mcp = server.RedactedContextMcp(root=self.root, config_path=None, mode="balanced", include_private=False)
        definition = next(tool for tool in mcp.list_tools()["tools"] if tool["name"] == "redctx_retrieve")
        self.assertTrue(definition["annotations"]["readOnlyHint"])
        config_path.write_text('[redaction]\nsalt = "retrieval-test"\nterms = ["quokkaproject"]\n', encoding="utf-8")
        result = mcp.call_tool("redctx_retrieve", {"query": "database backup"})
        self.assertFalse(result["isError"])
        self.assertNotIn("quokkaproject", json.dumps(result))
        self.assertGreater(result["structuredContent"]["receipt"]["counts_by_category"].get("SENSITIVE", 0), 0)
        self.assertTrue(mcp.call_tool("redctx_retrieve", {"query": "database", "max_results": 51})["isError"])


if __name__ == "__main__":
    unittest.main()
