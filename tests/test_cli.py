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

    def test_rehydrate_requires_raw_output_acknowledgement(self) -> None:
        redacted_file = self.root / "redacted-output.md"
        redacted_file.write_text("[CLIENT_00000000]\n", encoding="utf-8")

        result = self.run_cli("rehydrate", str(redacted_file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("allow-raw-output", result.stderr)

    def test_rehydrate_file_restores_redacted_text(self) -> None:
        listing = self.run_cli("ls", "context").stdout
        ref = listing.split()[0]
        redacted = self.run_cli("cat", ref)
        self.assertEqual(redacted.returncode, 0, redacted.stderr)
        redacted_file = self.root / "redacted-output.md"
        redacted_file.write_text(redacted.stdout, encoding="utf-8")

        result = self.run_cli("rehydrate", str(redacted_file), "--allow-raw-output")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Client Alpha", result.stdout)
        self.assertIn("Taylor Reed", result.stdout)
        self.assertIn("Jordan Vale", result.stdout)
        self.assertIn("Riverton Partners", result.stdout)
        self.assertNotRegex(result.stdout, r"\[(?:CLIENT|PERSON|ORG)_[0-9a-f]{8}\]")

    def test_rehydrate_folder_writes_output_tree(self) -> None:
        listing = self.run_cli("ls", "context").stdout
        ref = listing.split()[0]
        redacted = self.run_cli("cat", ref)
        self.assertEqual(redacted.returncode, 0, redacted.stderr)
        redacted_dir = self.root / "redacted-folder"
        redacted_dir.mkdir()
        (redacted_dir / "note.md").write_text(redacted.stdout, encoding="utf-8")
        output_dir = self.root / "rehydrated-folder"

        result = self.run_cli(
            "rehydrate",
            str(redacted_dir),
            "--output",
            str(output_dir),
            "--allow-raw-output",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Rehydrated 1 text file", result.stdout)
        output = (output_dir / "note.md").read_text(encoding="utf-8")
        self.assertIn("Client Alpha", output)
        self.assertIn("Taylor Reed", output)

    def test_rehydrate_folder_rejects_output_inside_input_folder(self) -> None:
        redacted_dir = self.root / "redacted-folder"
        redacted_dir.mkdir()
        (redacted_dir / "note.md").write_text("[CLIENT_00000000]\n", encoding="utf-8")

        result = self.run_cli(
            "rehydrate",
            str(redacted_dir),
            "--output",
            str(redacted_dir / "out"),
            "--allow-raw-output",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not be inside the input folder", result.stderr)


if __name__ == "__main__":
    unittest.main()
