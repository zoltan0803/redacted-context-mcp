from __future__ import annotations

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core, github, server
from redacted_context_mcp.defaults import PLACEHOLDER_CATEGORY_PATTERN, PLACEHOLDER_RE
from redacted_context_mcp.github import opaque_github_user
from redacted_context_mcp.models import RedactionConfig
from tests.fixtures import (
    CLIENT_NAME,
    ORGANIZATION_NAME,
    PERSON_ONE,
    PERSON_TWO,
    PROJECT_TERM,
    FakeHttpResponse,
    write_redaction_config,
)


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

    def test_github_body_truncation_does_not_split_placeholders(self) -> None:
        body = f"asked by {PERSON_ONE} about the rollout."
        comment_body = f"asked by {PERSON_TWO} in a comment."
        redacted_body = self.redactor.redact(body)
        redacted_comment = self.redactor.redact(comment_body)
        match = PLACEHOLDER_RE.search(redacted_body)
        comment_match = PLACEHOLDER_RE.search(redacted_comment)
        assert match is not None and comment_match is not None
        self.assertTrue(match.group().startswith("[PERSON_"))
        # One max_body_chars applies to both bodies, so both placeholders must share a span.
        self.assertEqual(match.span(), comment_match.span())
        prefix = redacted_body[: match.start()]
        self.assertEqual(prefix, "asked by ")
        self.assertEqual(redacted_comment[: comment_match.start()], prefix)
        category_start = re.compile(rf"\[(?:{PLACEHOLDER_CATEGORY_PATTERN})_")
        issue = {"number": 9, "state": "open", "title": "t", "body": body, "user": {"login": "person-one"}}
        comments = [{"created_at": "2026-06-11T12:00:00Z", "body": comment_body, "user": {"login": "person-two"}}]

        for offset in range(1, len(match.group())):
            with self.subTest(offset=offset):
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
                            max_body_chars=match.start() + offset,
                        ),
                    )

                self.assertIn(f"body_untrusted_external:\n{prefix}\n[TRUNCATED]\n", output)
                self.assertIn(f"comment_untrusted_external:\n{prefix}\n[TRUNCATED]\n", output)
                for fragment in category_start.finditer(output):
                    self.assertIsNotNone(PLACEHOLDER_RE.match(output, fragment.start()))

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

    def make_mcp(self) -> server.RedactedContextMcp:
        return server.RedactedContextMcp(root=self.root, config_path=None, mode="strict", include_private=False)

    def test_non_integer_number_and_comment_count_are_never_printed(self) -> None:
        # Numeric fields are printed without redaction, so a crafted upstream
        # payload must not be able to smuggle text through them.
        crafted = {"number": CLIENT_NAME, "comments": ORGANIZATION_NAME}
        detail_args = Namespace(repo_alias="context", number=7, comments=False, max_comments=0, max_body_chars=100)
        urlopen = "redacted_context_mcp.github.urllib.request.urlopen"

        with patch(urlopen, return_value=FakeHttpResponse([crafted])):
            cli_list = self.run_command(
                core.command_github_issues, Namespace(repo_alias="context", state="open", label=[], limit=5)
            )
        with patch(urlopen, return_value=FakeHttpResponse(crafted)):
            cli_detail = self.run_command(core.command_github_issue, detail_args)
        mcp = self.make_mcp()
        with patch(urlopen, return_value=FakeHttpResponse([crafted])):
            mcp_list = mcp.call_tool("redctx_github_list_issues", {"repo_alias": "context"})
        with patch(urlopen, return_value=FakeHttpResponse(crafted)):
            mcp_detail = mcp.call_tool("redctx_github_read_issue", {"repo_alias": "context", "number": 7})

        self.assertFalse(mcp_list["isError"])
        self.assertFalse(mcp_detail["isError"])
        self.assertEqual(mcp_list["content"][0]["text"], cli_list)
        self.assertEqual(mcp_detail["content"][0]["text"], cli_detail)
        self.assertTrue(cli_list.startswith("context#?\tstate=\tupdated=\tcomments=0\t"))
        self.assertIn("issue: #?\n", cli_detail)
        for output in (cli_list, cli_detail, json.dumps(mcp_list), json.dumps(mcp_detail)):
            self.assertNotIn(CLIENT_NAME, output)
            self.assertNotIn(ORGANIZATION_NAME, output)

    def test_numeric_fields_accept_only_non_negative_integers(self) -> None:
        for value in (True, False, -1, 1.0, "7", None, [7], {"n": 7}):
            with self.subTest(value=value):
                issue = github.github_issue_from_api("context", {"number": value, "comments": value})
                self.assertIsNone(issue.number)
                self.assertEqual(issue.comment_count, 0)
                self.assertEqual(issue.ref, "context#?")
        issue = github.github_issue_from_api("context", {"number": 12, "comments": 3, "assignees": "x"})
        self.assertEqual((issue.number, issue.comment_count, issue.assignee_count), (12, 3, 0))
        self.assertEqual(issue.ref, "context#12")

    def test_oversized_github_response_fails_closed(self) -> None:
        cap = 64
        exact = b"[]" + b" " * (cap - 2)
        urlopen = "redacted_context_mcp.github.urllib.request.urlopen"
        list_args = Namespace(repo_alias="context", state="open", label=[], limit=5)
        with patch.object(github, "GITHUB_MAX_RESPONSE_BYTES", cap):
            with patch(urlopen, return_value=FakeHttpResponse(None, body=exact)):
                self.assertEqual(self.run_command(core.command_github_issues, list_args), "")
            with patch(urlopen, return_value=FakeHttpResponse(None, body=exact + b" ")):
                with self.assertRaises(SystemExit) as caught:
                    self.run_command(core.command_github_issues, list_args)
            with patch(urlopen, return_value=FakeHttpResponse(None, body=exact + b" " * 1000)):
                result = self.make_mcp().call_tool("redctx_github_list_issues", {"repo_alias": "context"})
        self.assertEqual(str(caught.exception), "GitHub response too large.")
        self.assertEqual(str(caught.exception), github.GITHUB_RESPONSE_TOO_LARGE_MESSAGE)
        self.assertTrue(result["isError"])
        self.assertEqual(result["content"][0]["text"], "GitHub response too large.")
        self.assertEqual(github.GITHUB_MAX_RESPONSE_BYTES, 8 * 1024 * 1024)

    def test_github_response_read_is_bounded(self) -> None:
        response = FakeHttpResponse([])
        with patch.object(response, "read", wraps=response.read) as read:
            with patch("redacted_context_mcp.github.urllib.request.urlopen", return_value=response):
                self.run_command(core.command_github_issues, Namespace(repo_alias="context", state="open", label=[], limit=5))
        read.assert_called_once_with(github.GITHUB_MAX_RESPONSE_BYTES + 1)


if __name__ == "__main__":
    unittest.main()
