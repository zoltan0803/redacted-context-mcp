from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import os
from pathlib import Path

from tests.fixtures import PUBLIC_TECH, RAW_PRIVATE_VALUES, write_knowledgebase


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV = {
    **os.environ,
    "PYTHONPATH": str(PROJECT_ROOT / "src"),
}


class RedactedContextCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write_knowledgebase(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "redacted_context_mcp.core", "--root", str(self.root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            cwd=PROJECT_ROOT,
            env=ENV,
        )

    def test_ls_redacts_paths_and_returns_opaque_id(self) -> None:
        result = self.run_cli("ls", "context")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("@p_", result.stdout)
        self.assertNotIn("Sample", result.stdout)
        self.assertNotIn("Alpha", result.stdout)

    def test_cat_accepts_opaque_id_and_redacts_content(self) -> None:
        listing = self.run_cli("ls", "context").stdout
        ref = listing.split()[0]
        result = self.run_cli("cat", ref)

        self.assertEqual(result.returncode, 0, result.stderr)
        for raw in RAW_PRIVATE_VALUES:
            self.assertNotIn(raw, result.stdout)
        self.assertRegex(result.stdout, r"\[CLIENT_[0-9a-f]{8}\]")
        self.assertRegex(result.stdout, r"\[PERSON_[0-9a-f]{8}\]")
        self.assertRegex(result.stdout, r"\[EMAIL_[0-9a-f]{8}\]")
        self.assertIn("Azure", result.stdout)
        self.assertIn(PUBLIC_TECH, result.stdout)

    def test_grep_searches_redacted_text(self) -> None:
        result = self.run_cli("grep", "policy", "context", "--ignore-case")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("@p_", result.stdout)
        self.assertIn("policy controls", result.stdout)
        self.assertNotIn("Sample", result.stdout)

    def test_outside_root_is_rejected(self) -> None:
        result = self.run_cli("cat", str(self.root.parent / "outside.md"))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside root", result.stderr)

    def test_excluded_direct_path_is_rejected(self) -> None:
        result = self.run_cli("grep", "secret", "personal/secret.md")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("excluded by policy", result.stderr)
        self.assertNotIn("Raw secret", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
