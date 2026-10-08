"""Source adapter conformance tests.

Every registered source runs the same contract assertions. To add a source,
subclass ``SourceConformance`` alongside ``unittest.TestCase`` and supply its
fixtures; see ARCHITECTURE.md ("Adding a source").
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import os
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from redacted_context_mcp import core, rendering, retrieval, server
from redacted_context_mcp.filesystem import RedactedContext
from redacted_context_mcp.github import GitHubSource, opaque_github_user
from redacted_context_mcp.limits import OperationBudget, OperationLimitError
from redacted_context_mcp.models import (
    DOCUMENTS_UNSUPPORTED_MESSAGE,
    UNKNOWN_REFERENCE_MESSAGE,
    RedactionConfig,
)
from redacted_context_mcp.redaction import Redactor
from redacted_context_mcp.sources import ContextSource, SourceRegistry, build_sources
from tests.fixtures import (
    CLIENT_NAME,
    CONTEXT_REL_PATH,
    ORGANIZATION_NAME,
    PERSON_ONE,
    FakeHttpResponse,
    InMemorySource,
    load_snapshot,
    write_knowledgebase,
    write_redaction_config,
)

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "redacted_context_mcp"

# The agent-visible MCP surface is pinned by JSON snapshots in tests/snapshots
# (tools/list without and with --enable-writes, resources/templates/list).
# Changing the surface must be deliberate: regenerate them with
# ``json.dumps(value, sort_keys=True, indent=2)`` plus a trailing newline and
# keep examples/mcp-inspector.json validation in mind.
TOOLS_READ_ONLY_SNAPSHOT = "tools_list_read_only.json"
TOOLS_WITH_WRITES_SNAPSHOT = "tools_list_with_writes.json"
RESOURCE_TEMPLATES_SNAPSHOT = "resource_templates.json"

# Candidate references that are malformed for every source, or belong to a
# different source's namespace. Each source must refuse the ones it does not
# own without echoing raw identifiers.
CANDIDATE_REFERENCES = (
    "",
    "notes.txt",
    "../outside",
    "/etc/passwd",
    "C:/Windows/win.ini",
    "context",
    "@p_",
    "p_123",
    "@p_ZZZZZZZZZZZZ",
    "@p_0123456789abcdef",
    "redctx://",
    "redctx://p_xyz",
    "context#",
    "context#0",
    "context#-1",
    "context#abc",
    "context#12345678901",
    "#7",
    "unconfigured#7",
    "user_0123456789abcdef",
    "@m_123",
    "[PERSON_0123456789abcdef0123456789abcdef]",
    "@p_000000000000",
    "redctx://p_000000000000",
    "context#7",
    "@m_000000000000",
)


class SourceConformance:
    """Contract assertions shared by every context source."""

    expected_name: str
    expected_untrusted: bool
    expected_supports_document_iteration: bool

    # Subclass hooks -------------------------------------------------------

    def make_source(self) -> Any:
        raise NotImplementedError

    def valid_references(self) -> list[str]:
        """Owned references that resolve."""
        raise NotImplementedError

    def owned_unknown_references(self) -> list[str]:
        """References in this source's namespace that must still be refused."""
        raise NotImplementedError

    def raw_identifiers(self) -> list[str]:
        """Raw private identifiers that must never appear in references or errors."""
        raise NotImplementedError

    def owned_candidates(self) -> set[str]:
        return set()

    # Shared assertions ----------------------------------------------------

    def assert_safe_refusal(self, exc: SystemExit) -> None:
        message = str(exc)
        redactor = Redactor(RedactionConfig(salt="conformance"))
        self.assertEqual(server.safe_error_message(exc, redactor), message)  # type: ignore[attr-defined]
        for raw in self.raw_identifiers():
            self.assertNotIn(raw, message)  # type: ignore[attr-defined]

    def test_satisfies_protocol_and_declares_metadata(self) -> None:
        source = self.make_source()
        self.assertIsInstance(source, ContextSource)  # type: ignore[attr-defined]
        self.assertEqual(source.name, self.expected_name)  # type: ignore[attr-defined]
        self.assertIs(source.untrusted_content, self.expected_untrusted)  # type: ignore[attr-defined]
        self.assertIs(  # type: ignore[attr-defined]
            source.supports_document_iteration, self.expected_supports_document_iteration
        )

    def test_resolves_its_own_references(self) -> None:
        source = self.make_source()
        references = self.valid_references()
        self.assertTrue(references)  # type: ignore[attr-defined]
        for ref in references:
            with self.subTest(ref=ref):  # type: ignore[attr-defined]
                self.assertTrue(source.owns_reference(ref))  # type: ignore[attr-defined]
                self.assertIsNotNone(source.resolve_reference(ref))  # type: ignore[attr-defined]
                for raw in self.raw_identifiers():
                    self.assertNotIn(raw, ref)  # type: ignore[attr-defined]

    def test_refuses_owned_but_unknown_references(self) -> None:
        source = self.make_source()
        for ref in self.owned_unknown_references():
            with self.subTest(ref=ref):  # type: ignore[attr-defined]
                with self.assertRaises(SystemExit) as caught:  # type: ignore[attr-defined]
                    source.resolve_reference(ref)
                self.assert_safe_refusal(caught.exception)

    def test_rejects_foreign_and_malformed_references(self) -> None:
        source = self.make_source()
        owned = self.owned_candidates()
        for ref in CANDIDATE_REFERENCES:
            if ref in owned:
                continue
            with self.subTest(ref=ref):  # type: ignore[attr-defined]
                self.assertFalse(source.owns_reference(ref))  # type: ignore[attr-defined]
                with self.assertRaises(SystemExit) as caught:  # type: ignore[attr-defined]
                    source.resolve_reference(ref)
                self.assert_safe_refusal(caught.exception)

    def test_document_iteration_honors_budget(self) -> None:
        source = self.make_source()
        if not source.supports_document_iteration:
            budget = OperationBudget(max_files=5)
            with patch("urllib.request.urlopen", side_effect=AssertionError("network used")):
                with self.assertRaises(SystemExit) as caught:  # type: ignore[attr-defined]
                    list(source.iter_documents(budget))
            self.assertEqual(str(caught.exception), DOCUMENTS_UNSUPPORTED_MESSAGE)  # type: ignore[attr-defined]
            self.assertEqual(  # type: ignore[attr-defined]
                (budget.files_seen, budget.entries_seen, budget.raw_bytes_seen), (0, 0, 0)
            )
            return

        budget = OperationBudget(max_files=50, max_entries=500)
        documents = list(source.iter_documents(budget))
        self.assertTrue(documents)  # type: ignore[attr-defined]
        self.assertEqual(budget.files_seen, len(documents))  # type: ignore[attr-defined]
        self.assertEqual(  # type: ignore[attr-defined]
            budget.raw_bytes_seen, sum(len(document.text.encode("utf-8")) for document in documents)
        )
        for document in documents:
            self.assertTrue(source.owns_reference(document.ref))  # type: ignore[attr-defined]
            self.assertIsNotNone(source.resolve_reference(document.ref))  # type: ignore[attr-defined]
            self.assertNotIn(document.locator, document.ref)  # type: ignore[attr-defined]
            for raw in self.raw_identifiers():
                self.assertNotIn(raw, document.ref)  # type: ignore[attr-defined]

        scoped = list(source.iter_documents(OperationBudget(max_files=50), scope=[documents[0].ref]))
        self.assertEqual([document.ref for document in scoped], [documents[0].ref])  # type: ignore[attr-defined]

        exhausted = (
            OperationBudget(max_files=0),
            OperationBudget(max_files=len(documents) - 1),
            OperationBudget(max_total_raw_bytes=1),
            OperationBudget(deadline=time.monotonic() - 1),
        )
        for limited in exhausted:
            with self.subTest(budget=limited):  # type: ignore[attr-defined]
                with self.assertRaises(OperationLimitError):  # type: ignore[attr-defined]
                    list(source.iter_documents(limited))


class TempRootMixin:
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


class FilesystemSourceConformanceTest(TempRootMixin, SourceConformance, unittest.TestCase):
    expected_name = "filesystem"
    expected_untrusted = False
    expected_supports_document_iteration = True

    def setUp(self) -> None:
        super().setUp()
        write_knowledgebase(self.root)
        (self.root / "notes.txt").write_text("database backup notes\n", encoding="utf-8")
        self.config = core.load_config(self.root, None)

    def make_source(self) -> RedactedContext:
        return build_sources(self.root, self.config).filesystem

    def valid_references(self) -> list[str]:
        source = self.make_source()
        ref_id = source.path_id(CONTEXT_REL_PATH)
        return [f"@{ref_id}", ref_id, f"redctx://{ref_id}", source.display_ref("context")]

    def owned_unknown_references(self) -> list[str]:
        source = self.make_source()
        return [
            "@p_000000000000",
            "redctx://p_000000000000",
            # Excluded and never-served files have well-formed ids but must
            # not resolve through the protocol.
            source.display_ref("personal/secret.md"),
            source.display_ref(".agent-context-redactor.toml"),
        ]

    def owned_candidates(self) -> set[str]:
        return {"@p_000000000000", "redctx://p_000000000000"}

    def raw_identifiers(self) -> list[str]:
        return [CLIENT_NAME, PERSON_ONE, "Taylor", "notes.md", "context/", str(self.root)]

    def test_documents_skip_excluded_and_never_served_files(self) -> None:
        locators = {document.locator for document in self.make_source().iter_documents(OperationBudget())}
        self.assertEqual(locators, {CONTEXT_REL_PATH, "notes.txt"})

    def test_raw_paths_are_not_protocol_references(self) -> None:
        source = self.make_source()
        # The tool-facing resolver accepts raw paths; the protocol resolver must not.
        self.assertTrue(source.resolve_ref("notes.txt").is_file())
        with self.assertRaises(SystemExit) as caught:
            source.resolve_reference("notes.txt")
        self.assertEqual(str(caught.exception), UNKNOWN_REFERENCE_MESSAGE)

    def test_traversal_entry_limit_applies(self) -> None:
        with self.assertRaises(OperationLimitError):
            list(self.make_source().iter_documents(OperationBudget(max_entries=1)))

    def test_resource_uris_resolve_through_the_source(self) -> None:
        mcp = server.RedactedContextMcp(root=self.root, config_path=None, mode="strict", include_private=False)
        ref_id = mcp.ctx.path_id(CONTEXT_REL_PATH)
        uri = server.resource_uri(ref_id)
        with patch.object(mcp.ctx, "resolve_reference", wraps=mcp.ctx.resolve_reference) as resolve:
            contents = mcp.read_resource({"uri": uri})["contents"]
        self.assertEqual(resolve.call_args.args, (uri,))
        self.assertEqual(contents[0]["uri"], uri)
        refused = (
            "redctx://",
            "redctx://p_",
            "redctx://p_xyz",
            f"redctx://@{ref_id}",
            f"redctx://{ref_id}0",
            f"redctx://redctx://{ref_id}",
            f"@{ref_id}",
            ref_id,
            "file:///etc/passwd",
            "redctx://p_000000000000",
            server.resource_uri(mcp.ctx.path_id("personal/secret.md")),
            server.resource_uri(mcp.ctx.path_id(".agent-context-redactor.toml")),
        )
        for candidate in refused:
            with self.subTest(uri=candidate):
                with self.assertRaises(server.ProtocolError) as caught:
                    mcp.read_resource({"uri": candidate})
                self.assertEqual(str(caught.exception), "Resource not found.")


class GitHubSourceConformanceTest(TempRootMixin, SourceConformance, unittest.TestCase):
    expected_name = "github"
    expected_untrusted = True
    expected_supports_document_iteration = False

    def setUp(self) -> None:
        super().setUp()
        write_redaction_config(self.root, github=True)
        self.config = core.load_config(self.root, None)

    def make_source(self) -> GitHubSource:
        source = build_sources(self.root, self.config).github
        assert source is not None
        return source

    def valid_references(self) -> list[str]:
        return ["context#7", "context#1", "context#9999999999"]

    def owned_unknown_references(self) -> list[str]:
        return []

    def owned_candidates(self) -> set[str]:
        return {"context#7"}

    def raw_identifiers(self) -> list[str]:
        return ["client-alpha", "private-context", "person-one", "person-two"]

    def test_resolution_is_offline(self) -> None:
        with patch("urllib.request.urlopen", side_effect=AssertionError("network used")):
            self.assertEqual(self.make_source().resolve_reference("context#7"), ("context", 7))

    def test_records_carry_only_opaque_identities(self) -> None:
        issue = {
            "number": 7,
            "state": "open",
            "title": f"{CLIENT_NAME} rollout",
            "body": f"{PERSON_ONE} asked {ORGANIZATION_NAME}.",
            "labels": [{"name": ORGANIZATION_NAME}],
            "comments": 1,
            "user": {"login": "person-one"},
            "html_url": "https://github.com/client-alpha/private-context/issues/7",
        }
        comments = [{"created_at": "2026-06-11T12:00:00Z", "body": "ok", "user": {"login": "person-two"}}]
        source = self.make_source()
        with patch(
            "redacted_context_mcp.github.urllib.request.urlopen",
            side_effect=[FakeHttpResponse([issue]), FakeHttpResponse(issue), FakeHttpResponse(comments)],
        ):
            listed = source.list_issues("context", state="open", labels=[], limit=5)
            read = source.read_issue("context", 7)
            read_comments = source.read_comments("context", 7, limit=5)

        self.assertEqual([item.ref for item in listed], ["context#7"])
        self.assertEqual(read.ref, "context#7")
        self.assertRegex(read_comments[0].author, r"^user_[0-9a-f]{16}$")
        serialized = repr((listed, read, read_comments))
        for raw in self.raw_identifiers():
            self.assertNotIn(raw, serialized)
        # Content stays raw: the source does not redact; the boundary does.
        self.assertIn(PERSON_ONE, read.body)

    def test_author_alias_derivation_is_unchanged(self) -> None:
        expected = hmac.new(
            self.config.salt.encode("utf-8"),
            b"github-user:context:person-one",
            hashlib.sha256,
        ).hexdigest()[:16]
        self.assertEqual(opaque_github_user({"login": "person-one"}, self.config, "context"), f"user_{expected}")
        self.assertEqual(opaque_github_user({"login": ""}, self.config, "context"), "user_unknown")
        self.assertEqual(opaque_github_user(None, self.config, "context"), "user_unknown")
        comments = [{"created_at": "2026-06-11T12:00:00Z", "body": "ok", "user": {"login": "person-one"}}]
        with patch("redacted_context_mcp.github.urllib.request.urlopen", return_value=FakeHttpResponse(comments)):
            read_comments = self.make_source().read_comments("context", 7, limit=5)
        self.assertEqual([comment.author for comment in read_comments], [f"user_{expected}"])

    def test_issue_detail_fetches_comments_only_when_requested(self) -> None:
        issue = {"number": 7, "state": "open", "title": "t", "comments": 1}
        comments = [{"created_at": "2026-06-11T12:00:00Z", "body": "ok", "user": None}]
        source = self.make_source()
        urlopen = "redacted_context_mcp.github.urllib.request.urlopen"
        with patch(urlopen, side_effect=[FakeHttpResponse(issue), FakeHttpResponse(comments)]) as called:
            record, records = source.issue_detail("context", 7, comments=True, max_comments=5)
        self.assertEqual((record.ref, len(records), called.call_count), ("context#7", 1, 2))
        for flag, limit in ((False, 5), (True, 0)):
            with self.subTest(comments=flag, max_comments=limit):
                with patch(urlopen, side_effect=[FakeHttpResponse(issue)]) as called:
                    _record, records = source.issue_detail("context", 7, comments=flag, max_comments=limit)
                self.assertEqual((records, called.call_count), ([], 1))

    def test_limits_and_state_are_validated_before_any_request(self) -> None:
        source = self.make_source()
        redactor = Redactor(self.config)
        detail = dict(repo_alias="context", number=7, comments=True, max_comments=5, max_body_chars=100)
        cases = (
            (rendering.github_issue_detail_text, dict(detail, max_comments=-1), "--max-comments must be at least 0."),
            (rendering.github_issue_detail_text, dict(detail, max_body_chars=0), "--max-body-chars must be at least 1."),
            (
                rendering.github_issue_list_text,
                dict(repo_alias="context", state="draft", labels=[], limit=5),
                "GitHub state must be open, closed, or all.",
            ),
            (
                rendering.github_issue_search_text,
                dict(repo_alias="context", query="q", state="open", limit=0),
                "--limit must be at least 1.",
            ),
        )
        for function, kwargs, message in cases:
            with self.subTest(function=function.__name__, message=message):
                with patch("urllib.request.urlopen", side_effect=AssertionError("network used")):
                    with self.assertRaises(SystemExit) as caught:
                        function(source, redactor, **kwargs)
                self.assertEqual(str(caught.exception), message)

    def test_retrieval_refuses_sources_without_documents(self) -> None:
        redactor = Redactor(self.config)
        with patch("urllib.request.urlopen", side_effect=AssertionError("network used")):
            with self.assertRaises(SystemExit) as caught:
                retrieval.retrieve(
                    self.make_source(), redactor, "rollout", paths=[], globs=[], budget=OperationBudget(max_files=5)
                )
        self.assertEqual(str(caught.exception), DOCUMENTS_UNSUPPORTED_MESSAGE)


class InMemorySourceConformanceTest(SourceConformance, unittest.TestCase):
    """A non-filesystem, mailbox-shaped source implements the same contract."""

    expected_name = "memory"
    expected_untrusted = True
    expected_supports_document_iteration = True

    DOCUMENTS = {
        f"inbox/{CLIENT_NAME} kickoff": f"{PERSON_ONE} wrote about the backup plan.\n",
        f"archive/{ORGANIZATION_NAME}": "database recovery notes\n",
    }

    def make_source(self) -> InMemorySource:
        return InMemorySource(self.DOCUMENTS)

    def valid_references(self) -> list[str]:
        source = self.make_source()
        return [source.reference_for(locator) for locator in self.DOCUMENTS]

    def owned_unknown_references(self) -> list[str]:
        return ["@m_000000000000"]

    def owned_candidates(self) -> set[str]:
        return {"@m_000000000000"}

    def raw_identifiers(self) -> list[str]:
        return [CLIENT_NAME, ORGANIZATION_NAME, PERSON_ONE, "inbox", "archive"]


class SourceRegistryTest(TempRootMixin, unittest.TestCase):
    def test_github_is_registered_only_when_configured(self) -> None:
        write_redaction_config(self.root)
        plain = build_sources(self.root, core.load_config(self.root, None))
        self.assertEqual(plain.names(), ("filesystem",))
        self.assertIsNone(plain.github)

        write_redaction_config(self.root, github=True)
        both = build_sources(self.root, core.load_config(self.root, None))
        self.assertEqual(both.names(), ("filesystem", "github"))
        self.assertIsInstance(both.github, GitHubSource)
        self.assertIs(both.get("filesystem"), both.filesystem)

    def test_registry_requires_unique_names_and_a_filesystem_source(self) -> None:
        ctx = RedactedContext(self.root, RedactionConfig(salt="registry"))
        with self.assertRaises(ValueError):
            SourceRegistry([ctx, ctx])
        with self.assertRaises(ValueError):
            SourceRegistry([InMemorySource({})])


class LayeringTest(unittest.TestCase):
    """Sources own references; only the boundary redacts content."""

    @staticmethod
    def imported_modules(module: str) -> set[str]:
        tree = ast.parse((PACKAGE_ROOT / f"{module}.py").read_text(encoding="utf-8"))
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[-1])
            elif isinstance(node, ast.Import):
                names.update(alias.name.split(".")[-1] for alias in node.names)
        return names

    def test_source_adapters_do_not_import_the_redaction_boundary(self) -> None:
        for module in ("filesystem", "github", "sources"):
            with self.subTest(module=module):
                self.assertTrue({"redaction", "rendering"}.isdisjoint(self.imported_modules(module)))

    def test_retrieval_does_not_walk_the_filesystem_itself(self) -> None:
        self.assertNotIn("filesystem", self.imported_modules("retrieval"))

    def test_redaction_stays_source_agnostic(self) -> None:
        imported = self.imported_modules("redaction")
        self.assertTrue({"filesystem", "github", "sources", "rendering"}.isdisjoint(imported))


class McpSurfaceTest(TempRootMixin, unittest.TestCase):
    """The agent-visible MCP surface does not depend on which sources are registered."""

    def test_tools_and_resource_templates_are_unchanged(self) -> None:
        templates = load_snapshot(RESOURCE_TEMPLATES_SNAPSHOT)
        for github in (False, True):
            write_redaction_config(self.root, github=github)
            for writes, snapshot in ((False, TOOLS_READ_ONLY_SNAPSHOT), (True, TOOLS_WITH_WRITES_SNAPSHOT)):
                with self.subTest(github=github, enable_writes=writes):
                    mcp = server.RedactedContextMcp(
                        root=self.root, config_path=None, mode="strict", include_private=False, enable_writes=writes
                    )
                    self.assertEqual(mcp.list_tools(), load_snapshot(snapshot))
                    self.assertEqual(mcp.list_resource_templates(), templates)


if __name__ == "__main__":
    unittest.main()
