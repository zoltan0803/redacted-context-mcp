from __future__ import annotations

import contextlib
import io
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core, server
from redacted_context_mcp.config import vault_salt_path
from redacted_context_mcp.models import RedactionConfig
from redacted_context_mcp.redaction import Redactor


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}


def worker_load_salt(root: str, state_dir: str, event: multiprocessing.Event, queue: multiprocessing.Queue) -> None:
    from pathlib import Path
    from unittest.mock import patch

    from redacted_context_mcp.config import load_config

    event.wait()
    with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": state_dir}):
        queue.put(load_config(Path(root), None).salt)


class SecurityHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state_dir = Path(self.state_tmp.name)
        self.env_patch = patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(self.state_dir)})
        self.env_patch.start()
        (self.root / "docs").mkdir()
        (self.root / "docs" / "inside.md").write_text("inside needle\n", encoding="utf-8")
        self.env = {**ENV, "REDACTED_CONTEXT_STATE_DIR": str(self.state_dir)}

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()
        self.state_tmp.cleanup()

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "redacted_context_mcp.core", "--root", str(self.root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            cwd=PROJECT_ROOT,
            env=self.env,
        )

    def make_external_symlink(self, link: Path, secret: str = "outside secret") -> Path:
        outside_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(outside_dir, ignore_errors=True))
        outside_file = outside_dir / "outside.md"
        outside_file.write_text(secret, encoding="utf-8")
        try:
            link.symlink_to(outside_file)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        return outside_file

    def test_opaque_id_rejects_file_replaced_by_external_symlink(self) -> None:
        listing = self.run_cli("ls", "docs").stdout
        ref = listing.split()[0]
        (self.root / "docs" / "inside.md").unlink()
        self.make_external_symlink(self.root / "docs" / "inside.md")

        result = self.run_cli("cat", ref)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("outside secret", result.stdout + result.stderr)

    def test_resource_read_rejects_file_replaced_by_external_symlink(self) -> None:
        with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(self.state_dir)}):
            mcp = server.RedactedContextMcp(root=self.root, config_path=None, mode="strict", include_private=False)
            uri = mcp.list_resources({})["resources"][0]["uri"]
            (self.root / "docs" / "inside.md").unlink()
            self.make_external_symlink(self.root / "docs" / "inside.md")

            with self.assertRaises(server.ProtocolError) as raised:
                mcp.read_resource({"uri": uri})

        self.assertNotIn("outside secret", raised.exception.message)

    def test_direct_path_rejects_external_symlink(self) -> None:
        (self.root / "docs" / "inside.md").unlink()
        self.make_external_symlink(self.root / "docs" / "inside.md")

        result = self.run_cli("cat", "docs/inside.md")

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("outside secret", result.stdout + result.stderr)

    def test_state_directory_inside_root_is_rejected(self) -> None:
        with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(self.root / ".state")}):
            with self.assertRaises(SystemExit) as raised:
                core.load_config(self.root, None)
        self.assertIn("state directory must be outside", str(raised.exception))
        self.assertNotIn(str(self.root), str(raised.exception))

    def test_state_directory_equal_to_root_is_rejected(self) -> None:
        with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(self.root)}):
            with self.assertRaises(SystemExit):
                core.load_config(self.root, None)

    def test_state_directory_symlinked_inside_root_is_rejected(self) -> None:
        external_state = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(external_state, ignore_errors=True))
        link = self.root / "state-link"
        try:
            link.symlink_to(external_state, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(link)}):
            with self.assertRaises(SystemExit):
                core.load_config(self.root, None)

    def test_concurrent_vault_initialization_returns_one_salt(self) -> None:
        ctx = multiprocessing.get_context("spawn")
        event = ctx.Event()
        queue = ctx.Queue()
        workers = [
            ctx.Process(target=worker_load_salt, args=(str(self.root), str(self.state_dir), event, queue))
            for _ in range(8)
        ]
        for proc in workers:
            proc.start()
        event.set()
        salts = [queue.get(timeout=10) for _ in workers]
        for proc in workers:
            proc.join(timeout=10)
            self.assertEqual(proc.exitcode, 0)

        self.assertEqual(len(set(salts)), 1)
        persisted = vault_salt_path(self.root).read_text(encoding="utf-8").strip()
        self.assertEqual(persisted, salts[0])
        self.assertRegex(persisted, r"^[0-9a-f]{64}$")

    def test_corrupt_vault_salt_fails_without_rotation(self) -> None:
        with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(self.state_dir)}):
            salt_path = vault_salt_path(self.root)
            salt_path.parent.mkdir(parents=True)
            salt_path.write_text("not-a-valid-salt\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                core.load_config(self.root, None)
            self.assertEqual(salt_path.read_text(encoding="utf-8"), "not-a-valid-salt\n")

    def test_empty_vault_salt_fails_without_rotation(self) -> None:
        salt_path = vault_salt_path(self.root)
        salt_path.parent.mkdir(parents=True)
        salt_path.write_text("", encoding="utf-8")
        with self.assertRaises(SystemExit):
            core.load_config(self.root, None)
        self.assertEqual(salt_path.read_text(encoding="utf-8"), "")

    def test_configured_terms_cannot_rewrite_placeholders(self) -> None:
        redacted = Redactor(RedactionConfig(terms=("secret",), salt="s")).redact("password = superSecret1234")

        self.assertRegex(redacted, r"\[SECRET_[0-9a-f]{32}\]")
        self.assertNotIn("[ENTITY_", redacted)
        self.assertNotIn("superSecret1234", redacted)

    def test_search_preserves_line_numbers_after_multiline_patterns(self) -> None:
        cases = [
            ("pem.md", "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\ntarget\n", 4),
            ("secret.md", "password =\nabc123456789\ntarget\n", 3),
            ("proper.md", "Alice\nExample\ntarget\n", 3),
            ("crlf.md", "-----BEGIN PRIVATE KEY-----\r\nabc123\r\n-----END PRIVATE KEY-----\r\ntarget\r\n", 4),
        ]
        for name, content, line in cases:
            with self.subTest(name=name):
                path = self.root / "docs" / name
                path.write_text(content, encoding="utf-8", newline="")
                result = self.run_cli("grep", "target", f"docs/{name}", "--context", "0")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f":{line}:", result.stdout)
                self.assertNotIn("abc123", result.stdout)

    def test_safe_no_match_search_skips_redaction(self) -> None:
        config = core.load_config(self.root, None)
        ctx = core.RedactedContext(self.root, config)

        class FailingRedactor:
            def redact(self, *_args: object, **_kwargs: object) -> str:
                raise AssertionError("redaction should be skipped")

            def redact_path(self, value: str) -> str:
                return value

        status = core.command_grep(
            Namespace(
                query="definitely absent",
                paths=["docs"],
                glob=[],
                regex=False,
                ignore_case=True,
                context=0,
                max_results=10,
                max_files=None,
                max_raw_bytes_per_file=100_000,
                max_total_raw_bytes=100_000,
                max_entries=100,
                max_seconds=None,
            ),
            ctx,
            FailingRedactor(),  # type: ignore[arg-type]
        )

        self.assertEqual(status, 1)

    def test_placeholder_query_bypasses_raw_prefilter(self) -> None:
        config = core.load_config(self.root, None)
        ctx = core.RedactedContext(self.root, config)

        class PlaceholderRedactor:
            def redact(self, *_args: object, **_kwargs: object) -> str:
                return "[PERSON_deadbeef]\n"

            def redact_path(self, value: str) -> str:
                return value

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = core.command_grep(
                Namespace(
                    query="PERSON",
                    paths=["docs/inside.md"],
                    glob=[],
                    regex=False,
                    ignore_case=True,
                    context=0,
                    max_results=10,
                    max_files=None,
                    max_raw_bytes_per_file=100_000,
                    max_total_raw_bytes=100_000,
                    max_entries=100,
                    max_seconds=None,
                ),
                ctx,
                PlaceholderRedactor(),  # type: ignore[arg-type]
            )

        self.assertEqual(status, 0)
        self.assertIn("[PERSON_deadbeef]", output.getvalue())

    def test_failed_audit_returns_mcp_error_and_zero_refresh_receipt(self) -> None:
        (self.root / "docs" / "inside.md").unlink()
        self.make_external_symlink(self.root / "docs" / "inside.md")
        with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(self.state_dir)}):
            mcp = server.RedactedContextMcp(root=self.root, config_path=None, mode="strict", include_private=False)
            audit = mcp.call_tool("redctx_audit", {})
            refresh = mcp.call_tool("redctx_refresh_index", {})

        self.assertTrue(audit["isError"])
        self.assertIn("FAIL", audit["content"][0]["text"])
        self.assertEqual(refresh["structuredContent"]["receipt"]["counts_by_category"], {})

    def test_resource_read_rejects_oversized_file(self) -> None:
        (self.root / "docs" / "inside.md").write_text("x" * 200, encoding="utf-8")
        with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(self.state_dir)}):
            mcp = server.RedactedContextMcp(
                root=self.root,
                config_path=None,
                mode="strict",
                include_private=False,
                max_resource_bytes=10,
            )
            uri = mcp.list_resources({})["resources"][0]["uri"]
            with self.assertRaises(server.ProtocolError):
                mcp.read_resource({"uri": uri})

    def test_cache_rejects_symlink_swap(self) -> None:
        with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(self.state_dir)}):
            mcp = server.RedactedContextMcp(root=self.root, config_path=None, mode="strict", include_private=False)
            uri = mcp.list_resources({})["resources"][0]["uri"]
            first = mcp.read_resource({"uri": uri})
            self.assertIn("inside needle", first["contents"][0]["text"])
            (self.root / "docs" / "inside.md").unlink()
            self.make_external_symlink(self.root / "docs" / "inside.md")
            with self.assertRaises(server.ProtocolError):
                mcp.read_resource({"uri": uri})

    def test_write_target_symlink_is_rejected_and_returned_id_resolves(self) -> None:
        with patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": str(self.state_dir)}):
            mcp = server.RedactedContextMcp(
                root=self.root,
                config_path=None,
                mode="strict",
                include_private=False,
                enable_writes=True,
                write_subdir="incoming",
            )
            ok = mcp.call_tool(
                "redctx_submit_doc",
                {"target_path": "drafts/new.md", "text": "hello"},
            )
            self.assertFalse(ok["isError"])
            returned_id = next(line.split(":", 1)[1].strip() for line in ok["content"][0]["text"].splitlines() if line.startswith("id:"))
            read = mcp.call_tool("redctx_read", {"path": returned_id})
            self.assertFalse(read["isError"])
            self.assertIn("hello", read["content"][0]["text"])

            symlink_target = self.root / "incoming" / "drafts" / "link.md"
            try:
                symlink_target.symlink_to(self.root / "docs" / "inside.md")
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            rejected = mcp.call_tool(
                "redctx_submit_doc",
                {"target_path": "drafts/link.md", "text": "replacement", "overwrite": True},
            )
            self.assertTrue(rejected["isError"])


if __name__ == "__main__":
    unittest.main()
