from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import config_reload, server


class ConfigReloadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.state_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.state_tmp.cleanup)
        self.env = patch.dict(os.environ, {
            "REDACTED_CONTEXT_SALT": "",
            "REDACTED_CONTEXT_TERMS": "",
            "REDACTED_CONTEXT_DETECTOR_PROFILE": "",
            "REDACTED_CONTEXT_STATE_DIR": self.state_tmp.name,
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.config = self.root / ".agent-context-redactor.toml"
        self.write_config()
        (self.root / "notes.txt").write_text("the quokkaproject uses PostgreSQL\n", encoding="utf-8")
        self.mcp = server.RedactedContextMcp(
            root=self.root, config_path=None, mode="balanced", include_private=False,
            enable_writes=True,
        )
        self.uri = server.resource_uri(self.mcp.ctx.path_id("notes.txt"))

    def write_config(self, extra: str = "", *, salt: str = "reload-test-salt") -> None:
        self.config.write_text(f'[redaction]\nsalt = "{salt}"\n{extra}', encoding="utf-8")

    def read(self) -> str:
        return self.mcp.read_resource({"uri": self.uri})["contents"][0]["text"]

    def test_reload_redacts_previously_cached_content_and_preserves_references(self) -> None:
        self.assertIn("quokkaproject", self.read())
        original_placeholder = self.mcp.redactor.placeholder("EMAIL", "demo@example.test")
        original_ctx = self.mcp.ctx
        self.write_config('terms = ["quokkaproject"]\n')
        result = self.read()
        self.assertNotIn("quokkaproject", result)
        self.assertIn("PostgreSQL", result)
        self.assertIn("[SENSITIVE_", result)
        self.assertNotIn("quokkaproject", repr(self.mcp.cache.entries))
        self.assertIsNot(self.mcp.ctx, original_ctx)
        self.assertEqual(original_placeholder, self.mcp.redactor.placeholder("EMAIL", "demo@example.test"))
        self.assertEqual(self.uri, server.resource_uri(self.mcp.ctx.path_id("notes.txt")))

    def test_unchanged_requests_keep_cache_without_reparsing_policy(self) -> None:
        first = self.read()
        with patch.object(config_reload, "load_config", side_effect=AssertionError("unnecessary reload")):
            with patch.object(self.mcp.redactor, "redact", side_effect=AssertionError("cache miss")):
                self.assertEqual(first, self.read())

    def test_term_file_changes_reload_without_config_edits(self) -> None:
        terms = self.root / "terms.txt"
        terms.write_text("otherproject\n", encoding="utf-8")
        self.write_config('term_files = ["terms.txt"]\n')
        self.assertIn("quokkaproject", self.read())
        terms.write_text("otherproject\nquokkaproject\n", encoding="utf-8")
        self.assertNotIn("quokkaproject", self.read())

    def test_late_term_file_creation_is_loaded_and_never_served(self) -> None:
        self.write_config('term_files = ["terms.txt"]\n')
        self.assertIn("quokkaproject", self.read())
        (self.root / "terms.txt").write_text("quokkaproject\n", encoding="utf-8")
        self.assertNotIn("quokkaproject", self.read())
        self.assertNotIn("terms.txt", json.dumps(self.mcp.list_resources({})))
        result = self.mcp.call_tool("redctx_read", {"path": "terms.txt"})
        self.assertTrue(result["isError"])

    def test_new_exclusions_apply_to_existing_opaque_ids(self) -> None:
        self.read()
        self.write_config('exclude_globs = ["notes.txt"]\n')
        with self.assertRaises(server.ProtocolError):
            self.read()
        self.assertEqual(self.mcp.cache.stats()["entries"], 0)
        self.assertEqual(self.mcp.list_resources({})["resources"], [])

    def test_all_local_tool_outputs_use_new_policy(self) -> None:
        self.write_config('terms = ["quokkaproject"]\n')
        for name, args in (
            ("redctx_read", {"path": "notes.txt"}),
            ("redctx_search", {"query": "PostgreSQL"}),
            ("redctx_bundle", {"paths": ["notes.txt"]}),
            ("redctx_tree", {}),
            ("redctx_list", {}),
            ("redctx_stat", {"path": "notes.txt"}),
        ):
            with self.subTest(tool=name):
                result = self.mcp.call_tool(name, args)
                self.assertFalse(result["isError"], result)
                self.assertNotIn("quokkaproject", json.dumps(result))

    def test_resource_titles_use_new_policy(self) -> None:
        (self.root / "quokkaproject.txt").write_text("example\n", encoding="utf-8")
        self.write_config('allow = ["quokkaproject"]\n')
        self.assertIn("quokkaproject", json.dumps(self.mcp.list_resources({})))
        self.write_config('terms = ["quokkaproject"]\n')
        self.assertNotIn("quokkaproject", json.dumps(self.mcp.list_resources({})))

    def test_invalid_config_blocks_access_and_recovers_after_repair(self) -> None:
        self.read()
        self.config.write_text('[redaction]\nterms = ["private-parser-canary"', encoding="utf-8")
        for _ in range(2):
            result = self.mcp.call_tool("redctx_read", {"path": "notes.txt"})
            self.assertTrue(result["isError"])
            self.assertIn("Context access is blocked", json.dumps(result))
            self.assertNotIn("private-parser-canary", json.dumps(result))
            self.assertNotIn(str(self.root), json.dumps(result))
            for action in (lambda: self.read(), lambda: self.mcp.list_resources({})):
                with self.assertRaisesRegex(server.ProtocolError, "Context access is blocked"):
                    action()
        self.assertEqual(self.mcp.cache.stats()["entries"], 0)
        self.assertTrue(self.mcp.list_tools()["tools"])
        self.write_config('terms = ["quokkaproject"]\n')
        self.assertNotIn("quokkaproject", self.read())

    def test_invalid_config_blocks_writes_and_github_before_handlers_run(self) -> None:
        self.config.write_text("broken = [", encoding="utf-8")
        with patch.object(self.mcp, "submit_doc", side_effect=AssertionError("write attempted")):
            result = self.mcp.call_tool("redctx_submit_doc", {"target_path": "doc.txt", "text": "example"})
        self.assertTrue(result["isError"])
        with patch.dict(server.TOOL_HANDLERS, redctx_github_repos=lambda *_: self.fail("GitHub handler ran")):
            self.assertTrue(self.mcp.call_tool("redctx_github_repos", {})["isError"])
        self.assertFalse((self.root / "incoming").exists())

    def test_reload_rebuilds_source_registry(self) -> None:
        github = '[github.repos.context]\nowner = "example-owner"\nrepo = "example-repo"\n'
        self.assertEqual(self.mcp.sources.names(), ("filesystem",))
        self.assertEqual(self.mcp.call_tool("redctx_github_repos", {})["content"][0]["text"], "OK\n")

        self.read()
        self.assertEqual(self.mcp.cache.stats()["entries"], 1)
        self.write_config(github)
        result = self.mcp.call_tool("redctx_github_repos", {})
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["text"], "context\n")
        self.assertEqual(self.mcp.sources.names(), ("filesystem", "github"))
        self.assertIs(self.mcp.sources.github.config, self.mcp.ctx.config)
        self.assertIs(self.mcp.redactor.config, self.mcp.ctx.config)
        self.assertEqual(self.mcp.cache.stats()["entries"], 0)

        # An invalid policy blocks every source and clears the cache; the
        # candidate registry is never published.
        self.read()
        self.config.write_text("broken = [", encoding="utf-8")
        blocked = self.mcp.call_tool("redctx_github_repos", {})
        self.assertTrue(blocked["isError"])
        self.assertIn("Context access is blocked", blocked["content"][0]["text"])
        self.assertEqual(self.mcp.cache.stats()["entries"], 0)

        # Repairing the policy without the GitHub section removes the source.
        self.write_config()
        self.read()
        self.assertEqual(self.mcp.sources.names(), ("filesystem",))
        self.assertIsNone(self.mcp.sources.github)
        self.assertEqual(self.mcp.call_tool("redctx_github_repos", {})["content"][0]["text"], "OK\n")
        removed = self.mcp.call_tool("redctx_github_list_issues", {"repo_alias": "context"})
        self.assertTrue(removed["isError"])
        self.assertEqual(removed["content"][0]["text"], "Unknown GitHub repo alias.")
        self.assertNotIn("example-owner", json.dumps(removed))

    def test_removed_config_blocks_instead_of_falling_back(self) -> None:
        self.config.unlink()
        with self.assertRaisesRegex(server.ProtocolError, "Context access is blocked"):
            self.read()
        self.write_config('terms = ["quokkaproject"]\n')
        self.assertNotIn("quokkaproject", self.read())

    def test_removed_loaded_term_file_blocks_until_restored_or_unreferenced(self) -> None:
        terms = self.root / "terms.txt"
        terms.write_text("quokkaproject\n", encoding="utf-8")
        self.write_config('term_files = ["terms.txt"]\n')
        self.assertNotIn("quokkaproject", self.read())
        terms.unlink()
        with self.assertRaisesRegex(server.ProtocolError, "Context access is blocked"):
            self.read()
        # An explicit policy edit can deliberately remove the dependency.
        self.write_config('terms = ["quokkaproject"]\n')
        self.assertNotIn("quokkaproject", self.read())

    def test_salt_rotation_requires_restart_and_does_not_publish_candidate(self) -> None:
        self.read()
        old_config = self.mcp.ctx.config
        self.write_config(salt="different-private-salt")
        with self.assertRaisesRegex(server.ProtocolError, "salt changed") as caught:
            self.read()
        self.assertNotIn("different-private-salt", str(caught.exception))
        self.assertEqual(old_config, self.mcp.ctx.config)
        self.assertEqual(self.mcp.cache.stats()["entries"], 0)
        self.write_config()
        self.assertIn("quokkaproject", self.read())

    def test_explicit_config_is_watched_instead_of_default(self) -> None:
        custom = self.root / "custom.toml"
        custom.write_text(self.config.read_text(encoding="utf-8"), encoding="utf-8")
        self.mcp = server.RedactedContextMcp(
            root=self.root, config_path=custom, mode="balanced", include_private=True,
        )
        custom.write_text('[redaction]\nsalt = "reload-test-salt"\nterms = ["quokkaproject"]\n', encoding="utf-8")
        self.assertNotIn("quokkaproject", self.read())
        self.assertNotIn("custom.toml", json.dumps(self.mcp.list_resources({})))

    def test_atomic_config_replacement_is_detected(self) -> None:
        replacement = self.root / "replacement.toml"
        replacement.write_text('[redaction]\nsalt = "reload-test-salt"\nterms = ["quokkaproject"]\n', encoding="utf-8")
        replacement.replace(self.config)
        self.assertNotIn("quokkaproject", self.read())

    def test_edit_during_reload_is_rejected_and_retried_next_request(self) -> None:
        self.write_config('terms = ["otherproject"]\n')
        real_load = config_reload.load_config

        def changing_load(*args):
            result = real_load(*args)
            self.write_config('terms = ["quokkaproject"]\n')
            return result

        with patch.object(config_reload, "load_config", side_effect=changing_load):
            with self.assertRaisesRegex(server.ProtocolError, "Context access is blocked"):
                self.read()
        self.assertNotIn("quokkaproject", self.read())

    def test_unreadable_policy_error_does_not_disclose_os_exception(self) -> None:
        with patch.object(config_reload, "file_stamp", side_effect=PermissionError("private-path-canary")):
            with self.assertRaises(server.ProtocolError) as caught:
                self.read()
        self.assertNotIn("private-path-canary", str(caught.exception))
        self.assertIn("Context access is blocked", str(caught.exception))

    def test_config_created_after_startup_uses_existing_vault_salt(self) -> None:
        self.config.unlink()
        self.mcp = server.RedactedContextMcp(
            root=self.root, config_path=None, mode="balanced", include_private=False,
        )
        self.uri = server.resource_uri(self.mcp.ctx.path_id("notes.txt"))
        self.assertIn("quokkaproject", self.read())
        self.config.write_text('[redaction]\nterms = ["quokkaproject"]\n', encoding="utf-8")
        self.assertNotIn("quokkaproject", self.read())

    def test_replacement_policy_discards_old_rehydration_state(self) -> None:
        old_redactor = self.mcp.redactor
        old_redactor.redact("demo@example.test")
        self.write_config('terms = ["quokkaproject"]\n')
        result = self.mcp.call_tool("redctx_read", {"path": "notes.txt"})
        self.assertFalse(result["isError"])
        self.assertIsNot(self.mcp.redactor, old_redactor)
        self.assertEqual(result["structuredContent"]["receipt"]["counts_by_category"].get("EMAIL", 0), 0)

    def test_redactor_construction_failure_blocks_and_retries(self) -> None:
        self.read()
        self.write_config('terms = ["quokkaproject"]\n')
        with patch.object(server.rc, "Redactor", side_effect=ValueError("private-term-canary")):
            result = self.mcp.call_tool("redctx_read", {"path": "notes.txt"})
        self.assertTrue(result["isError"])
        self.assertNotIn("private-term-canary", json.dumps(result))
        self.assertEqual(self.mcp.cache.stats()["entries"], 0)
        self.assertNotIn("quokkaproject", self.read())


if __name__ == "__main__":
    unittest.main()
