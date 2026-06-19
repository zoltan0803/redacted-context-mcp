from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tests.fixtures import PUBLIC_TECH, RAW_PRIVATE_VALUES, write_knowledgebase


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV = {
    **os.environ,
    "PYTHONPATH": str(PROJECT_ROOT / "src"),
}


class RedactedContextMcpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write_knowledgebase(self.root)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "redacted_context_mcp.server", "--root", str(self.root)],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PROJECT_ROOT,
            env=ENV,
        )
        self.next_id = 1

    def tearDown(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        if self.proc.stdout:
            self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()
        self.tmp.cleanup()

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        request_id = self.next_id
        self.next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        self.assertTrue(line, "MCP server closed stdout")
        response = json.loads(line)
        self.assertEqual(response["id"], request_id)
        return response

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self.rpc("tools/call", {"name": name, "arguments": arguments})
        self.assertNotIn("error", response)
        return response["result"]

    def test_initialize_and_list_tools(self) -> None:
        response = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        )

        self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")
        self.assertIn("tools", response["result"]["capabilities"])
        self.assertIn("resources", response["result"]["capabilities"])

        tools = self.rpc("tools/list")["result"]["tools"]
        names = {tool["name"] for tool in tools}
        self.assertIn("redctx_read", names)
        self.assertIn("redctx_search", names)
        read_tool = next(tool for tool in tools if tool["name"] == "redctx_read")
        self.assertTrue(read_tool["annotations"]["readOnlyHint"])
        self.assertFalse(read_tool["inputSchema"]["additionalProperties"])

    def test_list_read_and_search_are_redacted(self) -> None:
        listing = self.call_tool("redctx_list", {"path": "context"})
        listing_text = listing["content"][0]["text"]
        ref = listing_text.split()[0]

        self.assertIn("@p_", listing_text)
        self.assertNotIn("Sample", listing_text)
        self.assertNotIn("Alpha", listing_text)

        read = self.call_tool("redctx_read", {"path": ref})
        read_text = read["content"][0]["text"]
        self.assertFalse(read["isError"])
        for raw in RAW_PRIVATE_VALUES:
            self.assertNotIn(raw, read_text)
        self.assertRegex(read_text, r"\[CLIENT_[0-9a-f]{8}\]")
        self.assertIn("Azure", read_text)
        self.assertIn(PUBLIC_TECH, read_text)

        search = self.call_tool("redctx_search", {"query": "policy", "paths": ["context"]})
        search_text = search["content"][0]["text"]
        self.assertFalse(search["isError"])
        self.assertIn("policy controls", search_text)
        self.assertNotIn("Sample", search_text)

    def test_excluded_direct_path_returns_tool_error_without_secret(self) -> None:
        result = self.call_tool("redctx_search", {"query": "secret", "paths": ["personal/secret.md"]})
        text = result["content"][0]["text"]

        self.assertTrue(result["isError"])
        self.assertIn("excluded by policy", text)
        self.assertNotIn("Raw secret", text)

    def test_invalid_tool_arguments_return_tool_errors(self) -> None:
        cases = [
            (
                "redctx_search",
                {"query": "policy", "paths": ["context"], "context": -1},
                "context must be at least 0",
            ),
            (
                "redctx_search",
                {"query": "policy", "paths": ["context"], "max_results": 0},
                "max_results must be at least 1",
            ),
            (
                "redctx_github_list_issues",
                {"state": "pending"},
                "state must be one of: open, closed, all",
            ),
            (
                "redctx_search",
                {"query": "policy", "paths": [123]},
                "paths[0] must be a string",
            ),
            (
                "redctx_read",
                {"path": "context", "max_chars": True},
                "max_chars must be an integer",
            ),
        ]

        for tool_name, arguments, message in cases:
            with self.subTest(tool_name=tool_name, arguments=arguments):
                result = self.call_tool(tool_name, arguments)
                self.assertTrue(result["isError"])
                self.assertIn(message, result["content"][0]["text"])

    def test_resources_list_and_read_are_redacted(self) -> None:
        resources = self.rpc("resources/list")["result"]["resources"]
        self.assertTrue(resources)
        resource = resources[0]

        self.assertTrue(resource["uri"].startswith("redctx://p_"))
        self.assertTrue(resource["name"].startswith("@p_"))
        self.assertNotIn("Client Alpha", json.dumps(resource))

        read = self.rpc("resources/read", {"uri": resource["uri"]})["result"]
        text = read["contents"][0]["text"]

        self.assertRegex(text, r"\[CLIENT_[0-9a-f]{8}\]")
        for raw in RAW_PRIVATE_VALUES:
            self.assertNotIn(raw, text)


if __name__ == "__main__":
    unittest.main()
