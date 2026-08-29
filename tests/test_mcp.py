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
MODERN_PROTOCOL_VERSION = "2026-07-28"
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"
ENV = {
    **os.environ,
    "PYTHONPATH": str(PROJECT_ROOT / "src"),
}


class RedactedContextMcpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state_dir = Path(self.state_tmp.name)
        write_knowledgebase(self.root)
        self.proc: subprocess.Popen[str] | None = None
        self.start_server()

    def start_server(self, *extra_args: str) -> None:
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "redacted_context_mcp.server",
                "--root",
                str(self.root),
                *extra_args,
            ],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PROJECT_ROOT,
            env={**ENV, "REDACTED_CONTEXT_STATE_DIR": str(self.state_dir)},
        )
        self.next_id = 1

    def tearDown(self) -> None:
        self.stop_server()
        self.tmp.cleanup()
        self.state_tmp.cleanup()

    def stop_server(self) -> None:
        if self.proc is None:
            return
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
        self.proc = None

    def restart_server(self, *extra_args: str) -> None:
        self.stop_server()
        self.start_server(*extra_args)

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.proc is not None
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

    def raw_rpc(self, method: str, params: Any) -> dict[str, Any]:
        assert self.proc is not None
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        request_id = self.next_id
        self.next_id += 1
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
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

    def modern_params(self, **values: Any) -> dict[str, Any]:
        return {
            **values,
            "_meta": {
                PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
                CLIENT_INFO_META_KEY: {"name": "test", "version": "0"},
                CLIENT_CAPABILITIES_META_KEY: {},
            },
        }

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
        self.assertFalse(read_tool["annotations"]["openWorldHint"])
        self.assertFalse(read_tool["inputSchema"]["additionalProperties"])
        self.assertIn("outputSchema", read_tool)
        github_tool = next(tool for tool in tools if tool["name"] == "redctx_github_list_issues")
        self.assertTrue(github_tool["annotations"]["openWorldHint"])
        self.assertNotIn("redctx_submit_doc", names)

    def test_modern_discover_reports_only_modern_versions(self) -> None:
        response = self.rpc("server/discover", self.modern_params())
        self.assertNotIn("error", response)
        result = response["result"]

        self.assertEqual(result["resultType"], "complete")
        self.assertEqual(result["supportedVersions"], [MODERN_PROTOCOL_VERSION])
        self.assertIn("tools", result["capabilities"])
        self.assertIn("resources", result["capabilities"])
        self.assertEqual(result["cacheScope"], "public")
        self.assertGreater(result["ttlMs"], 0)
        server_info = result["_meta"][SERVER_INFO_META_KEY]
        self.assertEqual(server_info["name"], "redacted-context")
        self.assertEqual(server_info["version"], "0.7.0")

    def test_modern_tools_and_resources_use_modern_result_shapes(self) -> None:
        tools_result = self.rpc("tools/list", self.modern_params())["result"]
        self.assertEqual(tools_result["resultType"], "complete")
        self.assertEqual(tools_result["cacheScope"], "public")
        self.assertGreater(tools_result["ttlMs"], 0)
        self.assertIn(SERVER_INFO_META_KEY, tools_result["_meta"])

        call_result = self.rpc(
            "tools/call",
            self.modern_params(name="redctx_doctor", arguments={}),
        )["result"]
        self.assertEqual(call_result["resultType"], "complete")
        self.assertIn(SERVER_INFO_META_KEY, call_result["_meta"])
        self.assertNotIn("ttlMs", call_result)
        self.assertNotIn("cacheScope", call_result)

        resources_result = self.rpc("resources/list", self.modern_params())["result"]
        self.assertEqual(resources_result["resultType"], "complete")
        self.assertEqual(resources_result["cacheScope"], "private")
        self.assertEqual(resources_result["ttlMs"], 0)

        uri = resources_result["resources"][0]["uri"]
        read_result = self.rpc(
            "resources/read",
            self.modern_params(uri=uri),
        )["result"]
        self.assertEqual(read_result["resultType"], "complete")
        self.assertEqual(read_result["cacheScope"], "private")
        self.assertEqual(read_result["ttlMs"], 0)
        for raw in RAW_PRIVATE_VALUES:
            self.assertNotIn(raw, json.dumps(read_result))

        templates_result = self.rpc(
            "resources/templates/list",
            self.modern_params(),
        )["result"]
        self.assertEqual(templates_result["resultType"], "complete")
        self.assertEqual(templates_result["cacheScope"], "public")
        self.assertGreater(templates_result["ttlMs"], 0)

    def test_modern_client_info_is_optional(self) -> None:
        response = self.rpc(
            "server/discover",
            {
                "_meta": {
                    PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
                    CLIENT_CAPABILITIES_META_KEY: {},
                }
            },
        )
        self.assertNotIn("error", response)
        self.assertEqual(response["result"]["resultType"], "complete")

    def test_modern_requests_validate_metadata_and_protocol_version(self) -> None:
        cases = [
            (
                "server/discover",
                {},
                -32602,
                "require params._meta",
            ),
            (
                "server/discover",
                {"_meta": {PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION}},
                -32602,
                CLIENT_CAPABILITIES_META_KEY,
            ),
            (
                "tools/list",
                {
                    "_meta": {
                        PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
                        CLIENT_CAPABILITIES_META_KEY: [],
                    }
                },
                -32602,
                CLIENT_CAPABILITIES_META_KEY,
            ),
            (
                "tools/list",
                {
                    "_meta": {
                        PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_VERSION,
                        CLIENT_CAPABILITIES_META_KEY: {},
                        CLIENT_INFO_META_KEY: {"name": "test"},
                    }
                },
                -32602,
                "requires string name and version",
            ),
        ]
        for method, params, code, message in cases:
            with self.subTest(method=method, params=params):
                error = self.rpc(method, params)["error"]
                self.assertEqual(error["code"], code)
                self.assertIn(message, error["message"])

        unsupported = self.rpc(
            "tools/list",
            {
                "_meta": {
                    PROTOCOL_VERSION_META_KEY: "2099-01-01",
                    CLIENT_CAPABILITIES_META_KEY: {},
                }
            },
        )["error"]
        self.assertEqual(unsupported["code"], -32022)
        self.assertEqual(unsupported["data"]["requested"], "2099-01-01")
        self.assertEqual(unsupported["data"]["supported"], [MODERN_PROTOCOL_VERSION])

    def test_falsey_non_object_params_and_arguments_are_rejected(self) -> None:
        params_error = self.raw_rpc("tools/list", [])["error"]
        self.assertEqual(params_error["code"], -32602)
        self.assertIn("params must be an object", params_error["message"])

        arguments_error = self.rpc(
            "tools/call",
            {"name": "redctx_doctor", "arguments": []},
        )["error"]
        self.assertEqual(arguments_error["code"], -32602)
        self.assertIn("object arguments", arguments_error["message"])

    def test_legacy_progress_metadata_is_not_misclassified_as_modern(self) -> None:
        result = self.rpc(
            "tools/list",
            {"_meta": {"progressToken": "legacy-token"}},
        )["result"]
        self.assertIn("tools", result)
        self.assertNotIn("resultType", result)

    def test_modern_ping_is_not_supported_but_legacy_ping_remains_available(self) -> None:
        modern_error = self.rpc("ping", self.modern_params())["error"]
        self.assertEqual(modern_error["code"], -32601)
        self.assertEqual(self.rpc("ping")["result"], {})

    def test_modern_resource_errors_do_not_emit_legacy_reserved_code(self) -> None:
        missing_uri = "redctx://p_deadbeefdead"
        legacy_missing = self.rpc(
            "resources/read",
            {"uri": missing_uri},
        )["error"]
        self.assertEqual(legacy_missing["code"], -32002)

        modern_missing = self.rpc(
            "resources/read",
            self.modern_params(uri=missing_uri),
        )["error"]
        self.assertEqual(modern_missing["code"], -32602)
        self.assertEqual(modern_missing["message"], legacy_missing["message"])

        self.restart_server("--max-traversal-entries", "0")
        legacy_limit = self.rpc("resources/list")["error"]
        self.assertEqual(legacy_limit["code"], -32002)

        modern_limit = self.rpc("resources/list", self.modern_params())["error"]
        self.assertEqual(modern_limit["code"], -32602)
        self.assertEqual(modern_limit["message"], legacy_limit["message"])

    def test_modern_opaque_resource_uri_survives_process_restart(self) -> None:
        resources = self.rpc("resources/list", self.modern_params())["result"]["resources"]
        uri = resources[0]["uri"]
        before = self.rpc(
            "resources/read",
            self.modern_params(uri=uri),
        )["result"]["contents"][0]

        self.restart_server()

        after = self.rpc(
            "resources/read",
            self.modern_params(uri=uri),
        )["result"]["contents"][0]
        self.assertEqual(after["uri"], uri)
        self.assertEqual(after["text"], before["text"])

    def test_initialize_never_negotiates_the_modern_era(self) -> None:
        response = self.rpc(
            "initialize",
            {
                "protocolVersion": MODERN_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "legacy-test", "version": "0"},
            },
        )
        self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")
        self.assertNotIn("resultType", response["result"])

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
        self.assertEqual(read["structuredContent"]["text"], read_text)
        for raw in RAW_PRIVATE_VALUES:
            self.assertNotIn(raw, read_text)
        self.assertRegex(read_text, r"\[CLIENT_[0-9a-f]{32}\]")
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

        self.assertRegex(text, r"\[CLIENT_[0-9a-f]{32}\]")
        for raw in RAW_PRIVATE_VALUES:
            self.assertNotIn(raw, text)

    def test_submit_doc_is_available_only_when_writes_enabled(self) -> None:
        result = self.call_tool(
            "redctx_submit_doc",
            {"target_path": "drafts/summary.md", "text": "hello"},
        )

        self.assertTrue(result["isError"])
        self.assertIn("Writes are disabled", result["content"][0]["text"])

        self.restart_server("--enable-writes", "--write-subdir", "incoming")
        tools = self.rpc("tools/list")["result"]["tools"]
        submit_tool = next(tool for tool in tools if tool["name"] == "redctx_submit_doc")
        self.assertFalse(submit_tool["annotations"]["readOnlyHint"])
        self.assertTrue(submit_tool["annotations"]["destructiveHint"])

    def test_submit_doc_rehydrates_and_writes_under_configured_subdir(self) -> None:
        self.restart_server("--enable-writes", "--write-subdir", "incoming")
        listing = self.call_tool("redctx_list", {"path": "context"})["content"][0]["text"]
        ref = listing.split()[0]
        redacted = self.call_tool("redctx_read", {"path": ref})["content"][0]["text"]

        result = self.call_tool(
            "redctx_submit_doc",
            {
                "target_path": "drafts/summary.md",
                "text": redacted,
            },
        )

        self.assertFalse(result["isError"])
        summary = result["content"][0]["text"]
        self.assertIn("Wrote rehydrated document", summary)
        self.assertIn("@p_", summary)
        self.assertNotIn("Client Alpha", summary)

        written_file = self.root / "incoming" / "drafts" / "summary.md"
        self.assertTrue(written_file.exists())
        written = written_file.read_text(encoding="utf-8")
        self.assertIn("Client Alpha", written)
        self.assertIn("Taylor Reed", written)
        self.assertIn("Jordan Vale", written)
        self.assertNotRegex(written, r"\[(?:CLIENT|PERSON|ORG)_[0-9a-f]{32}\]")

    def test_submit_doc_rejects_unsafe_paths_unresolved_tokens_and_overwrite(self) -> None:
        self.restart_server("--enable-writes", "--write-subdir", "incoming")
        unsafe = self.call_tool(
            "redctx_submit_doc",
            {"target_path": "../escape.md", "text": "hello"},
        )
        self.assertTrue(unsafe["isError"])
        self.assertIn("relative file path", unsafe["content"][0]["text"])
        self.assertFalse((self.root / "escape.md").exists())

        unresolved = self.call_tool(
            "redctx_submit_doc",
            {"target_path": "drafts/unresolved.md", "text": "Hello [PERSON_deadbeef]."},
        )
        self.assertTrue(unresolved["isError"])
        self.assertIn("Unresolved redaction token", unresolved["content"][0]["text"])
        self.assertFalse((self.root / "incoming" / "drafts" / "unresolved.md").exists())

        existing = self.root / "incoming" / "drafts" / "existing.md"
        existing.parent.mkdir(parents=True)
        existing.write_text("old", encoding="utf-8")
        conflict = self.call_tool(
            "redctx_submit_doc",
            {"target_path": "drafts/existing.md", "text": "new"},
        )
        self.assertTrue(conflict["isError"])
        self.assertIn("Target already exists", conflict["content"][0]["text"])
        self.assertEqual(existing.read_text(encoding="utf-8"), "old")

        overwrite = self.call_tool(
            "redctx_submit_doc",
            {"target_path": "drafts/existing.md", "text": "new", "overwrite": True},
        )
        self.assertFalse(overwrite["isError"])
        self.assertEqual(existing.read_text(encoding="utf-8"), "new")


if __name__ == "__main__":
    unittest.main()
