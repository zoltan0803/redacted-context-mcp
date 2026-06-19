from __future__ import annotations

import io
import json
import contextlib
import tempfile
import urllib.error
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core


class FakeOllamaResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "FakeOllamaResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class FakeDiscoveryClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def extract(self, *, rel_path: str, text: str) -> core.DiscoveryResult:
        self.calls.append((rel_path, text))
        return core.DiscoveryResult(
            clients=("Example Customer", "EC"),
            organizations=("Example Partners",),
            people=("Alice Example",),
            terms=("Project Orion",),
        )


class DiscoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "context").mkdir()
        (self.root / "personal").mkdir()
        (self.root / "context" / "note.md").write_text(
            "Example Customer met Alice Example from Example Partners.\n",
            encoding="utf-8",
        )
        (self.root / "personal" / "secret.md").write_text("Raw secret\n", encoding="utf-8")
        self.ctx = core.RedactedContext(self.root, core.RedactionConfig())

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_parse_discovery_response_accepts_json_wrapped_in_text(self) -> None:
        result = core.parse_discovery_response(
            'Here is JSON: {"clients":["Example Customer"],"organizations":["GitHub","Example Partners"],'
            '"people":["Regional Director","Alice Example","Bob Example (CIO)","Tom"],'
            '"terms":["Project Orion","M09","notes.md","Automated validation findings","pytest"],'
            '"allow":["Terraform"]}'
        )

        self.assertEqual(result.clients, ("Example Customer",))
        self.assertEqual(result.organizations, ("Example Partners",))
        self.assertEqual(result.people, ("Alice Example", "Bob Example"))
        self.assertEqual(result.terms, ("Project Orion",))
        self.assertEqual(result.allow, ("pytest",))

    def test_discover_entities_uses_client_and_respects_excludes(self) -> None:
        client = FakeDiscoveryClient()
        result = core.discover_entities(
            self.ctx,
            paths=["context"],
            globs=["*.md"],
            client=client,  # type: ignore[arg-type]
            max_files=10,
            max_chars_per_file=1000,
        )

        self.assertEqual(result.clients, ("Example Customer", "EC"))
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0][0], "context/note.md")
        self.assertNotIn("Raw secret", client.calls[0][1])

    def test_format_discovery_toml(self) -> None:
        output = core.format_discovery_toml(
            core.DiscoveryResult(
                clients=("Example Customer",),
                organizations=("Example Partners",),
                people=("Alice Example",),
                terms=("Project Orion",),
                allow=("GitHub",),
            ),
            source_note="test",
        )

        self.assertIn("[redaction]", output)
        self.assertIn('"Example Customer"', output)
        self.assertIn('"Alice Example"', output)
        self.assertIn('"GitHub"', output)
        self.assertIn("# Review before use", output)

    def test_command_discover_json_format(self) -> None:
        output = io.StringIO()
        result = core.DiscoveryResult(
            clients=("Example Customer",),
            organizations=("Example Partners",),
            people=("Alice Example",),
            terms=("Project Orion",),
        )

        with patch("redacted_context_mcp.core.OllamaDiscoveryClient", return_value=object()):
            with patch("redacted_context_mcp.core.discover_entities", return_value=result):
                with contextlib.redirect_stdout(output):
                    status = core.command_discover(
                        Namespace(
                            provider="ollama",
                            endpoint="http://localhost:11434",
                            model="gemma4:e4b",
                            timeout=1.0,
                            raw_discovery=False,
                            paths=["context"],
                            glob=["*.md"],
                            max_files=10,
                            max_chars_per_file=1000,
                            format="json",
                            output=None,
                            force=False,
                        ),
                        self.ctx,
                        core.Redactor(core.RedactionConfig()),
                    )

        self.assertEqual(status, 0)
        parsed = json.loads(output.getvalue())
        self.assertEqual(parsed["clients"], ["Example Customer"])
        self.assertEqual(parsed["people"], ["Alice Example"])

    def test_ollama_http_error_reports_model_name(self) -> None:
        client = core.OllamaDiscoveryClient(endpoint="http://localhost:11434", model="gemma:e4b", timeout=1)
        error = urllib.error.HTTPError(
            url="http://localhost:11434/api/generate",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=io.BytesIO(b'{"error":"model gemma:e4b not found"}'),
        )

        with patch("redacted_context_mcp.discovery.urllib.request.urlopen", side_effect=error):
            with self.assertRaises(SystemExit) as raised:
                client.extract(rel_path="context/example.md", text="Example")

        message = str(raised.exception)
        self.assertIn("gemma:e4b", message)
        self.assertIn("ollama list", message)

    def test_ollama_retries_with_strict_prompt_after_parse_failure(self) -> None:
        client = core.OllamaDiscoveryClient(endpoint="http://localhost:11434", model="gemma4:e4b", timeout=1)
        responses = [
            FakeOllamaResponse({"response": "I found some names but cannot format them."}),
            FakeOllamaResponse(
                {
                    "response": json.dumps(
                        {
                            "clients": ["Example Customer"],
                            "organizations": [],
                            "people": ["Alice Example"],
                            "terms": [],
                            "allow": [],
                        }
                    )
                }
            ),
        ]

        with patch("redacted_context_mcp.discovery.urllib.request.urlopen", side_effect=responses) as urlopen:
            result = client.extract(rel_path="context/example.md", text="Example Customer met Alice Example.")

        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(result.clients, ("Example Customer",))
        self.assertEqual(result.people, ("Alice Example",))


if __name__ == "__main__":
    unittest.main()
