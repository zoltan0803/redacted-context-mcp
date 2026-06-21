from __future__ import annotations

import argparse
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core, server
from redacted_context_mcp.discovery import discover_entities
from redacted_context_mcp.filesystem import RedactedContext, is_probably_text
from redacted_context_mcp.limits import OperationBudget, OperationLimitError
from redacted_context_mcp.models import DiscoveryResult, RedactionConfig
from redacted_context_mcp.redaction import RedactionSession, Redactor


def grep_args(query: str, *, ignore_case: bool = False, max_raw_bytes_per_file: int = 1_000_000) -> argparse.Namespace:
    return argparse.Namespace(
        query=query,
        paths=[],
        glob=[],
        regex=False,
        ignore_case=ignore_case,
        context=0,
        max_results=50,
        max_files=None,
        max_raw_bytes_per_file=max_raw_bytes_per_file,
        max_total_raw_bytes=50_000_000,
        max_entries=10_000,
        max_seconds=None,
    )


class FollowupHardeningTest(unittest.TestCase):
    def test_lowercase_placeholder_query_bypasses_prefilter_when_ignore_case(self) -> None:
        self.assertFalse(core.can_use_raw_search_prefilter("person", regex=False, ignore_case=True))

    def test_partial_placeholder_category_bypasses_prefilter(self) -> None:
        self.assertFalse(core.can_use_raw_search_prefilter("ERSO", regex=False, ignore_case=True))

    def test_extended_category_query_bypasses_prefilter(self) -> None:
        self.assertFalse(core.can_use_raw_search_prefilter("MAC", regex=False, ignore_case=True))

    def test_short_hex_query_bypasses_prefilter(self) -> None:
        self.assertFalse(core.can_use_raw_search_prefilter("face", regex=False, ignore_case=True))

    def test_long_hex_query_bypasses_prefilter(self) -> None:
        self.assertFalse(core.can_use_raw_search_prefilter("deadbeef", regex=False, ignore_case=False))

    def test_placeholder_structural_characters_bypass_prefilter(self) -> None:
        for query in ("[PERSON", "PERSON_", "]"):
            self.assertFalse(core.can_use_raw_search_prefilter(query, regex=False, ignore_case=False))

    def test_case_sensitive_lowercase_category_semantics(self) -> None:
        self.assertTrue(core.can_use_raw_search_prefilter("person", regex=False, ignore_case=False))

    def test_safe_plain_query_still_uses_prefilter(self) -> None:
        self.assertTrue(core.can_use_raw_search_prefilter("policy", regex=False, ignore_case=False))

    def test_prefilter_candidate_is_verified_against_redacted_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text("needle\n", encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt", terms=("needle",)))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = core.command_grep(grep_args("needle"), ctx, Redactor(ctx.config))
            self.assertEqual(status, 1)
            self.assertEqual(output.getvalue(), "")

    def test_end_to_end_placeholder_only_queries_are_found(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            redactor = Redactor(RedactionConfig(salt="salt"))
            face_value = next(
                f"user{i}@example.test"
                for i in range(20_000)
                if "face" in redactor.placeholder("EMAIL", f"user{i}@example.test")
            )
            (root / "doc.txt").write_text(
                "Alice Example\n"
                "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
                "aa:bb:cc:dd:ee:ff\n"
                f"{face_value}\n",
                encoding="utf-8",
            )
            ctx = RedactedContext(root, RedactionConfig(salt="salt", detector_profile="extended"))
            for query in ("person", "secret", "ERSO", "MAC", "face"):
                with self.subTest(query=query):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        status = core.command_grep(grep_args(query, ignore_case=True), ctx, Redactor(ctx.config))
                    self.assertEqual(status, 0)
                    self.assertIn("[", output.getvalue())

    def test_internal_markers_contain_no_ascii_digits(self) -> None:
        session = RedactionSession("")
        marker = session.stash_allowed("value")
        self.assertFalse(any("0" <= char <= "9" for char in marker))

    def test_internal_markers_survive_100005_replacements(self) -> None:
        text = "\n".join(f"user{i}@example.test" for i in range(100_005))
        output = Redactor(RedactionConfig(salt="salt")).redact(text)
        self.assertEqual(output.count("[EMAIL_"), 100_005)
        self.assertEqual(output.count("[PHONE_"), 0)
        self.assertFalse(any("\ue000" <= char <= "\uf8ff" for char in output))
        self.assertNotIn("user100004@example.test", output)

    def test_large_email_batch_does_not_create_phone_placeholders(self) -> None:
        text = "\n".join(f"user{i}@example.test" for i in range(100_005))
        self.assertNotIn("[PHONE_", Redactor(RedactionConfig(salt="salt")).redact(text))

    def test_final_output_contains_no_internal_marker_characters(self) -> None:
        output = Redactor(RedactionConfig(salt="salt")).redact("a@example.test\nAlice Example")
        self.assertFalse(any("\ue000" <= char <= "\uf8ff" for char in output))

    def test_input_private_use_characters_do_not_collide_with_markers(self) -> None:
        source = "\ue000 Alice Example"
        output = Redactor(RedactionConfig(salt="salt")).redact(source)
        self.assertIn("\ue000", output)
        self.assertIn("[PERSON_", output)

    def test_lowercase_identity_line_preserves_following_line_number(self) -> None:
        self.assert_identity_target_line("attendees:\nAlice\ntarget\n", 3)

    def test_identity_line_with_lf_preserves_line_numbers(self) -> None:
        self.assert_identity_target_line("attendees: Alice\ntarget\n", 2)

    def test_identity_line_with_crlf_preserves_line_numbers(self) -> None:
        self.assert_identity_target_line("attendees:\r\nAlice\r\ntarget\r\n", 3)

    def test_empty_identity_field_does_not_consume_next_line(self) -> None:
        redacted = Redactor(RedactionConfig(salt="salt")).redact("attendees:\nAlice\n")
        self.assertIn("attendees:", redacted)
        self.assertIn("[ENTITY_", redacted)

    def test_identity_field_spacing_is_preserved(self) -> None:
        redacted = Redactor(RedactionConfig(salt="salt")).redact("attendees \t: \tAlice\n")
        self.assertIn("attendees \t: \t", redacted)

    def test_search_context_after_identity_field_is_correct(self) -> None:
        self.assert_identity_target_line("attendees:\nAlice\ntarget\n", 3)

    def assert_identity_target_line(self, text: str, expected_line: int) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text(text, encoding="utf-8", newline="")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = core.command_grep(grep_args("target"), ctx, Redactor(ctx.config))
            self.assertEqual(status, 0)
            self.assertIn(f":{expected_line}:", output.getvalue())

    def test_unknown_extension_text_detection_reads_only_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "large.unknown"
            path.write_bytes(b"a" * (1024 * 1024))
            reads: list[int] = []
            real_open = Path.open

            class Wrapper:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.handle.__exit__(*args)

                def read(self, size=-1):
                    reads.append(size)
                    return self.handle.read(size)

                def __getattr__(self, name):
                    return getattr(self.handle, name)

            def tracked_open(self, *args, **kwargs):
                return Wrapper(real_open(self, *args, **kwargs))

            with patch.object(Path, "open", tracked_open):
                self.assertTrue(is_probably_text(path))
            self.assertEqual(reads, [4096])

    def test_discovery_does_not_read_entire_oversized_file(self) -> None:
        self.assert_discovery_sample(truncated=True)

    def test_discovery_truncation_is_explicit(self) -> None:
        text = self.assert_discovery_sample(truncated=True)
        self.assertIn("[TRUNCATED DISCOVERY SAMPLE]", text)

    def test_discovery_respects_total_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.unknown").write_bytes(b"a" * 100)
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            with self.assertRaises(OperationLimitError):
                discover_entities(
                    ctx,
                    paths=[],
                    globs=[],
                    client=FakeDiscoveryClient(),
                    max_files=1,
                    max_chars_per_file=20,
                    max_total_raw_bytes=10,
                )

    def assert_discovery_sample(self, *, truncated: bool) -> str:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.unknown").write_bytes(b"a" * 100)
            client = FakeDiscoveryClient()
            discover_entities(
                RedactedContext(root, RedactionConfig(salt="salt")),
                paths=[],
                globs=[],
                client=client,
                max_files=1,
                max_chars_per_file=20,
            )
            self.assertEqual(len(client.texts), 1)
            if truncated:
                self.assertLess(len(client.texts[0]), 80)
            return client.texts[0]

    def test_tail_reads_file_once(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text("one\ntwo\nthree\n", encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            calls = 0
            real_read = core.read_text_file

            def counted(*args, **kwargs):
                nonlocal calls
                calls += 1
                return real_read(*args, **kwargs)

            args = argparse.Namespace(path="doc.txt", lines=2, max_chars=1000, line_numbers=False, max_files=None, max_raw_bytes_per_file=1000, max_total_raw_bytes=1000, max_entries=100, max_seconds=None)
            with patch("redacted_context_mcp.core.read_text_file", counted), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(core.command_tail(args, ctx, Redactor(ctx.config)), 0)
            self.assertEqual(calls, 1)

    def test_tail_enforces_budget_before_first_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text("x" * 100, encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            args = argparse.Namespace(path="doc.txt", lines=2, max_chars=1000, line_numbers=False, max_files=None, max_raw_bytes_per_file=10, max_total_raw_bytes=1000, max_entries=100, max_seconds=None)
            with self.assertRaises(OperationLimitError), patch.object(Path, "read_bytes", side_effect=AssertionError("should not read")):
                core.command_tail(args, ctx, Redactor(ctx.config))

    def test_tail_handles_utf8_boundary_safely(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text("one\nÁrvíztűrő\n", encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            output = io.StringIO()
            args = argparse.Namespace(path="doc.txt", lines=1, max_chars=1000, line_numbers=False, max_files=None, max_raw_bytes_per_file=1000, max_total_raw_bytes=1000, max_entries=100, max_seconds=None)
            with contextlib.redirect_stdout(output):
                self.assertEqual(core.command_tail(args, ctx, Redactor(ctx.config)), 0)
            self.assertIn("Árvíztűrő", output.getvalue())

    def test_tail_handles_crlf(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text("one\r\ntwo\r\n", encoding="utf-8", newline="")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            output = io.StringIO()
            args = argparse.Namespace(path="doc.txt", lines=1, max_chars=1000, line_numbers=True, max_files=None, max_raw_bytes_per_file=1000, max_total_raw_bytes=1000, max_entries=100, max_seconds=None)
            with contextlib.redirect_stdout(output):
                self.assertEqual(core.command_tail(args, ctx, Redactor(ctx.config)), 0)
            self.assertIn("2\t", output.getvalue())

    def test_stat_line_count_respects_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text("x" * 100, encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            args = argparse.Namespace(path="doc.txt", max_files=None, max_raw_bytes_per_file=10, max_total_raw_bytes=1000, max_entries=100, max_seconds=None)
            with self.assertRaises(OperationLimitError), contextlib.redirect_stdout(io.StringIO()):
                core.command_stat(args, ctx, Redactor(ctx.config))

    def test_stat_does_not_unboundedly_read_large_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text("a\n" * 10, encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            args = argparse.Namespace(path="doc.txt", max_files=None, max_raw_bytes_per_file=1000, max_total_raw_bytes=1000, max_entries=100, max_seconds=None)
            output = io.StringIO()
            with patch("redacted_context_mcp.core.read_text_file", side_effect=AssertionError("stat should stream")), contextlib.redirect_stdout(output):
                self.assertEqual(core.command_stat(args, ctx, Redactor(ctx.config)), 0)
            self.assertIn("lines: 10", output.getvalue())

    def test_resource_list_respects_entry_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(Path(td) / "state")}):
            root = Path(td) / "root"
            root.mkdir()
            (root / "a.txt").write_text("a", encoding="utf-8")
            mcp = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False, max_traversal_entries=0)
            with self.assertRaises(server.ProtocolError):
                mcp.list_resources({})

    def test_path_index_respects_entry_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("a", encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            with self.assertRaises(OperationLimitError):
                ctx.path_index(budget=OperationBudget(max_entries=0))

    def test_partial_index_is_never_treated_as_complete(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("a", encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            with self.assertRaises(OperationLimitError):
                ctx.path_index(budget=OperationBudget(max_entries=0))
            self.assertIsNone(ctx._path_index)

    def test_refresh_index_limit_returns_safe_error(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(Path(td) / "state")}):
            root = Path(td) / "root"
            root.mkdir()
            (root / "a.txt").write_text("a", encoding="utf-8")
            mcp = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False, max_traversal_entries=0)
            result = mcp.call_tool("redctx_refresh_index", {})
            self.assertTrue(result["isError"])
            self.assertIn("Traversal entry limit exceeded", result["content"][0]["text"])

    def test_directory_scan_counts_files_and_directories(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "dir").mkdir()
            (root / "a.txt").write_text("a", encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            with self.assertRaises(OperationLimitError):
                list(ctx.walk(budget=OperationBudget(max_entries=1)))

    def test_directory_scan_fails_before_unbounded_collection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for index in range(5):
                (root / f"{index}.txt").write_text("x", encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            with self.assertRaises(OperationLimitError):
                ctx.child_entries(root, budget=OperationBudget(max_entries=2))

    def test_link_scan_counts_every_inspected_entry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("a", encoding="utf-8")
            ctx = RedactedContext(root, RedactionConfig(salt="salt"))
            with self.assertRaises(OperationLimitError):
                ctx.scan_link_entries(budget=OperationBudget(max_entries=1))

    def test_submit_doc_rehydration_map_respects_byte_limit(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(Path(td) / "state")}):
            root = Path(td) / "root"
            root.mkdir()
            (root / "source.txt").write_text("x" * 100, encoding="utf-8")
            mcp = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False, enable_writes=True, max_total_raw_bytes=10)
            result = mcp.call_tool("redctx_submit_doc", {"target_path": "out/doc.txt", "text": "hello"})
            self.assertTrue(result["isError"])
            self.assertFalse((root / "incoming" / "out" / "doc.txt").exists())

    def test_submit_doc_rehydration_map_respects_file_limit(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(Path(td) / "state")}):
            root = Path(td) / "root"
            root.mkdir()
            (root / "source.txt").write_text("x", encoding="utf-8")
            mcp = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False, enable_writes=True, max_submit_files=0)
            result = mcp.call_tool("redctx_submit_doc", {"target_path": "out/doc.txt", "text": "hello"})
            self.assertTrue(result["isError"])

    def test_rehydration_runtime_is_independent_of_unused_mapping_size(self) -> None:
        small = {f"[PERSON_{i:032x}]": f"name{i}" for i in range(100)}
        large = {f"[PERSON_{i:032x}]": f"name{i}" for i in range(10_000)}
        doc = " ".join(list(small)[:5])
        start = time.perf_counter()
        core.rehydrate_text_with_count(doc, small)
        small_elapsed = time.perf_counter() - start
        start = time.perf_counter()
        core.rehydrate_text_with_count(doc, large)
        large_elapsed = time.perf_counter() - start
        self.assertLess(large_elapsed, max(0.01, small_elapsed * 50))

    def test_rehydration_does_not_cascade(self) -> None:
        output, count = core.rehydrate_text_with_count(
            "[PERSON_00000000000000000000000000000000]",
            {
                "[PERSON_00000000000000000000000000000000]": "[PERSON_00000000000000000000000000000001]",
                "[PERSON_00000000000000000000000000000001]": "raw",
            },
        )
        self.assertEqual(count, 1)
        self.assertEqual(output, "[PERSON_00000000000000000000000000000001]")

    def test_unknown_token_remains_unresolved(self) -> None:
        text, count = core.rehydrate_text_with_count("[PERSON_ffffffffffffffffffffffffffffffff]", {})
        self.assertEqual(count, 0)
        self.assertIn("[PERSON_", text)

    def test_rehydration_count_is_correct(self) -> None:
        text, count = core.rehydrate_text_with_count(
            "[PERSON_00000000000000000000000000000000] [PERSON_00000000000000000000000000000000]",
            {"[PERSON_00000000000000000000000000000000]": "Alice"},
        )
        self.assertEqual(count, 2)
        self.assertEqual(text, "Alice Alice")

    def test_no_overwrite_never_replaces_existing_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "out.txt"
            path.write_text("old", encoding="utf-8")
            with self.assertRaises(SystemExit):
                core.atomic_write_text(path, "new", overwrite=False)
            self.assertEqual(path.read_text(encoding="utf-8"), "old")

    def test_no_overwrite_failure_cleans_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "out.txt"
            with patch("redacted_context_mcp.core.os.link", side_effect=OSError("link failed")):
                with self.assertRaises(SystemExit):
                    core.atomic_write_text(path, "new", overwrite=False)
            self.assertFalse(list(Path(td).glob(".out.txt.*.tmp")))
            self.assertFalse(path.exists())

    def test_overwrite_uses_same_directory_atomic_replace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "out.txt"
            path.write_text("old", encoding="utf-8")
            calls: list[tuple[Path, Path]] = []
            real_replace = os.replace

            def tracked(src, dst):
                calls.append((Path(src), Path(dst)))
                return real_replace(src, dst)

            with patch("redacted_context_mcp.core.os.replace", tracked):
                core.atomic_write_text(path, "new", overwrite=True)
            self.assertEqual(path.read_text(encoding="utf-8"), "new")
            self.assertEqual(calls[0][0].parent, path.parent)
            self.assertEqual(calls[0][1], path)

    def test_write_contract_matches_implementation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "out.txt"
            core.atomic_write_text(path, "new", overwrite=False)
            self.assertEqual(path.read_text(encoding="utf-8"), "new")

    def test_audit_reports_writes_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctx = RedactedContext(Path(td), RedactionConfig(salt="salt"))
            checks = core.audit_checks(ctx, Redactor(ctx.config), writes_enabled=False)
            self.assertTrue(any(check["name"] == "controlled writes currently disabled" and check["status"] == "PASS" for check in checks))

    def test_audit_warns_when_writes_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctx = RedactedContext(Path(td), RedactionConfig(salt="salt"))
            checks = core.audit_checks(ctx, Redactor(ctx.config), writes_enabled=True)
            self.assertTrue(any(check["name"] == "controlled writes currently enabled" and check["status"] == "WARN" for check in checks))
            self.assertFalse(any(str(td) in str(check.get("detail", "")) for check in checks))

    def test_repeated_mcp_read_uses_cache(self) -> None:
        with self.mcp_with_file("Alice Example") as (mcp, uri, _root):
            first = mcp.read_resource({"uri": uri})
            self.assertIn("[PERSON_", first["contents"][0]["text"])
            with patch.object(mcp.redactor, "redact", side_effect=AssertionError("cache miss")):
                second = mcp.read_resource({"uri": uri})
            self.assertEqual(first, second)

    def test_cache_stores_only_redacted_content(self) -> None:
        with self.mcp_with_file("Alice Example") as (mcp, uri, _root):
            mcp.read_resource({"uri": uri})
            self.assertNotIn("Alice Example", repr(mcp.cache.entries))

    def test_cache_invalidates_after_normal_file_change(self) -> None:
        with self.mcp_with_file("first") as (mcp, uri, root):
            self.assertIn("first", mcp.read_resource({"uri": uri})["contents"][0]["text"])
            (root / "doc.txt").write_text("second", encoding="utf-8")
            self.assertIn("second", mcp.read_resource({"uri": uri})["contents"][0]["text"])

    def test_cache_obeys_memory_budget(self) -> None:
        with self.mcp_with_file("Alice Example", cache_bytes=1) as (mcp, uri, _root):
            mcp.read_resource({"uri": uri})
            self.assertEqual(mcp.cache.stats()["entries"], 0)

    def test_cache_key_includes_redaction_mode(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(Path(td) / "state")}):
            root = Path(td) / "root"
            root.mkdir()
            (root / "doc.txt").write_text("ALPHA\n", encoding="utf-8")
            strict = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False)
            balanced = server.RedactedContextMcp(root=root, config_path=None, mode="balanced", include_private=False)
            uri = strict.list_resources({})["resources"][0]["uri"]
            self.assertNotEqual(
                strict.read_resource({"uri": uri})["contents"][0]["text"],
                balanced.read_resource({"uri": uri})["contents"][0]["text"],
            )

    def test_cache_key_includes_configuration_fingerprint(self) -> None:
        base = RedactionConfig(salt="salt")
        configured = RedactionConfig(salt="salt", terms=("private",))
        self.assertNotEqual(
            server.redaction_config_fingerprint(base),
            server.redaction_config_fingerprint(configured),
        )

    def test_cache_invalidates_after_submit_doc(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(Path(td) / "state")}):
            root = Path(td) / "root"
            root.mkdir()
            (root / "doc.txt").write_text("source", encoding="utf-8")
            mcp = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False, enable_writes=True)
            uri = mcp.list_resources({})["resources"][0]["uri"]
            mcp.read_resource({"uri": uri})
            self.assertGreater(mcp.cache.stats()["entries"], 0)
            result = mcp.call_tool("redctx_submit_doc", {"target_path": "out/doc.txt", "text": "hello"})
            self.assertFalse(result["isError"])
            self.assertEqual(mcp.cache.stats()["entries"], 0)

    @contextlib.contextmanager
    def mcp_with_file(self, content: str, *, cache_bytes: int = 2_000_000):
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(Path(td) / "state")}):
            root = Path(td) / "root"
            root.mkdir()
            (root / "doc.txt").write_text(content, encoding="utf-8")
            mcp = server.RedactedContextMcp(root=root, config_path=None, mode="strict", include_private=False, cache_bytes=cache_bytes)
            uri = mcp.list_resources({})["resources"][0]["uri"]
            yield mcp, uri, root

    def test_cli_utf8_under_cp1250(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text("right arrow → em dash — curly “quotes” Ágnes\n", encoding="utf-8")
            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            env["PYTHONIOENCODING"] = "cp1250"
            env["REDACTED_CONTEXT_STATE_DIR"] = str(root.parent / f"{root.name}-state")
            result = subprocess.run(
                [sys.executable, "-m", "redacted_context_mcp.core", "--root", str(root), "cat", "doc.txt"],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
            self.assertIn("→", result.stdout.decode("utf-8"))

    def test_mcp_utf8_under_cp1250(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "doc.txt").write_text("right arrow → em dash — curly “quotes” Ágnes\n", encoding="utf-8")
            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            env["PYTHONIOENCODING"] = "cp1250"
            env["REDACTED_CONTEXT_STATE_DIR"] = str(root.parent / f"{root.name}-state")
            request = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
            result = subprocess.run(
                [sys.executable, "-m", "redacted_context_mcp.server", "--root", str(root)],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
            self.assertIn("Redacted Context", result.stdout.decode("utf-8"))

    def test_redirected_unicode_output_does_not_crash(self) -> None:
        self.test_cli_utf8_under_cp1250()


class FakeDiscoveryClient:
    def __init__(self) -> None:
        self.texts: list[str] = []

    def extract(self, *, rel_path: str, text: str) -> DiscoveryResult:
        self.texts.append(text)
        return DiscoveryResult()


if __name__ == "__main__":
    unittest.main()
