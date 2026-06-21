from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core, server
from redacted_context_mcp.github import opaque_github_user
from redacted_context_mcp.models import RedactionConfig
from tests.fixtures import CLIENT_NAME, ORGANIZATION_NAME, PERSON_ONE, PERSON_TWO, PROJECT_TERM, write_redaction_config


class FakeHttpResponse:
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "FakeHttpResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class GitHubIssueTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.env_patch = patch.dict(os.environ, {"REDACTED_CONTEXT_STATE_DIR": self.state_tmp.name})
        self.env_patch.start()
        write_redaction_config(self.root, github=True)
        self.config = core.load_config(self.root, None)
        self.ctx = core.RedactedContext(self.root, self.config)
        self.redactor = core.Redactor(self.config)

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()
        self.state_tmp.cleanup()

    def run_command(self, command: object, args: Namespace) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            command(args, self.ctx, self.redactor)  # type: ignore[operator]
        return output.getvalue()

    def test_github_issue_list_is_redacted_and_uses_token_env(self) -> None:
        issue = {
            "number": 7,
            "state": "open",
            "title": f"{CLIENT_NAME} data task for {PERSON_ONE}",
            "updated_at": "2026-06-11T10:00:00Z",
            "comments": 2,
            "labels": [{"name": ORGANIZATION_NAME}, {"name": "Azure"}],
            "user": {"login": "person-one"},
        }

        with patch.dict(os.environ, {"REDCTX_TEST_GITHUB_TOKEN": "secret-token"}):
            with patch("redacted_context_mcp.github.urllib.request.urlopen", return_value=FakeHttpResponse([issue])) as urlopen:
                output = self.run_command(
                    core.command_github_issues,
                    Namespace(repo_alias="context", state="open", label=[], limit=10),
                )

        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer secret-token")
        self.assertIn("context#7", output)
        self.assertIn("Azure", output)
        for raw in [CLIENT_NAME, PERSON_ONE, ORGANIZATION_NAME, "client-alpha", "private-context"]:
            self.assertNotIn(raw, output)

    def test_github_issue_detail_and_comments_are_redacted(self) -> None:
        issue = {
            "number": 9,
            "state": "open",
            "title": f"{PROJECT_TERM} follow-up",
            "created_at": "2026-06-10T10:00:00Z",
            "updated_at": "2026-06-11T10:00:00Z",
            "body": f"{PERSON_ONE} asked {ORGANIZATION_NAME} about {CLIENT_NAME} rollout.",
            "labels": [{"name": CLIENT_NAME}],
            "assignees": [{"login": "person-two"}],
            "user": {"login": "person-one"},
        }
        comments = [
            {
                "created_at": "2026-06-11T12:00:00Z",
                "body": f"{PERSON_TWO} confirmed {PROJECT_TERM}.",
                "user": {"login": "person-two"},
            }
        ]

        with patch(
            "redacted_context_mcp.github.urllib.request.urlopen",
            side_effect=[FakeHttpResponse(issue), FakeHttpResponse(comments)],
        ):
            output = self.run_command(
                core.command_github_issue,
                Namespace(
                    repo_alias="context",
                    number=9,
                    comments=True,
                    max_comments=10,
                    max_body_chars=2000,
                ),
            )

        self.assertIn("issue: #9", output)
        self.assertIn("author: user_", output)
        self.assertIn("body_untrusted_external:", output)
        self.assertIn("comment_untrusted_external:", output)
        self.assertIn("assignees: 1", output)
        for raw in [
            CLIENT_NAME,
            PERSON_ONE,
            PERSON_TWO,
            ORGANIZATION_NAME,
            PROJECT_TERM,
            "person-one",
            "person-two",
            "client-alpha",
            "private-context",
        ]:
            self.assertNotIn(raw, output)

    def test_github_user_alias_is_salt_and_repo_scoped(self) -> None:
        user = {"login": "same-user"}

        first = opaque_github_user(user, RedactionConfig(salt="salt-one"), "context")
        same = opaque_github_user(user, RedactionConfig(salt="salt-one"), "context")
        different_salt = opaque_github_user(user, RedactionConfig(salt="salt-two"), "context")
        different_repo = opaque_github_user(user, RedactionConfig(salt="salt-one"), "other")

        self.assertEqual(first, same)
        self.assertNotEqual(first, different_salt)
        self.assertNotEqual(first, different_repo)
        self.assertRegex(first, r"^user_[0-9a-f]{16}$")

    def test_mcp_exposes_github_issue_tools(self) -> None:
        mcp = server.RedactedContextMcp(
            root=self.root,
            config_path=None,
            mode="strict",
            include_private=False,
        )

        names = {tool["name"] for tool in mcp.list_tools()["tools"]}

        self.assertIn("redctx_github_list_issues", names)
        self.assertIn("redctx_github_read_issue", names)


if __name__ == "__main__":
    unittest.main()
