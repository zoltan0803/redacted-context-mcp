from __future__ import annotations

import unittest

from redacted_context_mcp.models import RedactionConfig
from redacted_context_mcp.paths import path_id
from redacted_context_mcp.redaction import Redactor


class RedactionBenchmarkTest(unittest.TestCase):
    def test_secret_and_identifier_leak_benchmark(self) -> None:
        raw_values = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",
            "sk-abcdefghijklmnopqrstuvwxyz123456",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "superSecret1234",
            "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
            "123-45-6789",
            "4111 1111 1111 1111",
            "10.12.30.4",
            "550e8400-e29b-41d4-a716-446655440000",
            "private.internal",
        ]
        text = f"""
AWS key: {raw_values[0]}
GitHub token: {raw_values[1]}
OpenAI token: {raw_values[2]}
Authorization: {raw_values[3]}
password = {raw_values[4]}
PEM:
{raw_values[5]}
SSN: {raw_values[6]}
Card: {raw_values[7]}
Host IP: {raw_values[8]}
Trace id: {raw_values[9]}
Domain: {raw_values[10]}
"""
        redacted = Redactor(RedactionConfig(salt="test-salt")).redact(text)

        for raw in raw_values:
            self.assertNotIn(raw, redacted)
        self.assertRegex(redacted, r"\[SECRET_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[SSN_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[CARD_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[IP_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[ID_[0-9a-f]{32}\]")
        self.assertRegex(redacted, r"\[DOMAIN_[0-9a-f]{32}\]")

    def test_placeholders_are_stable_for_same_salt(self) -> None:
        config = RedactionConfig(people=("Alice Example",), salt="same-salt")
        first = Redactor(config).redact("Alice Example met Alice Example.")
        second = Redactor(config).redact("Alice Example met Alice Example.")

        self.assertEqual(first, second)
        self.assertEqual(first.count("[PERSON_"), 2)

    def test_path_ids_are_salted_and_stable(self) -> None:
        rel = "context/Client Alpha notes.md"

        self.assertEqual(path_id(rel, "salt-one"), path_id(rel, "salt-one"))
        self.assertNotEqual(path_id(rel, "salt-one"), path_id(rel, "salt-two"))
        self.assertRegex(path_id(rel, "salt-one"), r"^p_[0-9a-f]{12}$")


if __name__ == "__main__":
    unittest.main()
