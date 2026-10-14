from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from redacted_context_mcp import core
from redacted_context_mcp.config import load_config
from redacted_context_mcp.discovery import propose_alias_groups
from redacted_context_mcp.models import AliasGroup


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}
STAKEHOLDERS = "# Stakeholders\n\nAvery Example is Product owner.\nMorgan Sample coordinates the review.\n"
EMAIL = (
    "Hi team,\n\nReach me at avery@example.com.\nMorgan, please loop in morgan.sample@example.com.\n\n"
    "Thank you, Avery\n"
)
PEOPLE = ("Avery Example", "Morgan Sample")
EXPECTED = (("Avery Example", ("Avery", "avery@example.com")), ("Morgan Sample", ("Morgan", "morgan.sample@example.com")))


class FakeOllamaResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.body = json.dumps({"response": json.dumps(payload)}).encode("utf-8")

    def __enter__(self) -> "FakeOllamaResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class StaticClient:
    """Discovery client that returns one fixed result for every document."""

    def __init__(self, result: core.DiscoveryResult) -> None:
        self.result = result

    def extract(self, *, rel_path: str, text: str) -> core.DiscoveryResult:
        del rel_path, text
        return self.result


class TempRoot(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / "kb"
        self.root.mkdir()
        self.state = Path(self.tmp.name).resolve() / "state"
        environment = patch.dict(os.environ, {
            "REDACTED_CONTEXT_SALT": "",
            "REDACTED_CONTEXT_TERMS": "",
            "REDACTED_CONTEXT_DETECTOR_PROFILE": "",
            "REDACTED_CONTEXT_STATE_DIR": str(self.state),
        })
        environment.start()
        self.addCleanup(environment.stop)

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        return path

    def load_groups(self, text: str) -> tuple[AliasGroup, ...]:
        """Round-trip config text through the real loader."""
        return load_config(self.root, self.write("loaded.toml", text)).alias_groups


class ProposalHeuristicsTest(unittest.TestCase):
    def test_first_name_and_email_proposals(self) -> None:
        self.assertEqual(propose_alias_groups([STAKEHOLDERS, EMAIL], PEOPLE), EXPECTED)

    def test_first_name_only_used_inside_the_full_name_is_not_proposed(self) -> None:
        self.assertEqual(propose_alias_groups([STAKEHOLDERS], PEOPLE), ())

    def test_ambiguous_first_names_produce_no_proposal(self) -> None:
        signed = "Thank you, Avery\n"
        cases = {
            "two proposed people": (["Avery Example", "Avery Stone"], ()),
            "a configured namesake": (["Avery Example"], ("Avery Stone",)),
            "a surname elsewhere": (["Avery Example"], ("Jo Avery",)),
        }
        for name, (people, known) in cases.items():
            with self.subTest(name):
                self.assertEqual(propose_alias_groups([signed], people, known_people=known), ())
        with self.subTest("unknown surname in the text"):
            self.assertEqual(propose_alias_groups([signed + "Avery Jones called.\n"], ["Avery Example"]), ())

    def test_common_words_are_not_proposed_as_first_names(self) -> None:
        self.assertEqual(propose_alias_groups(["Thanks, Will\nI will check.\n"], ["Will Example"]), ())
        self.assertEqual(propose_alias_groups(["Thanks, June\n"], ["June Example"]), ())

    def test_email_local_part_shapes(self) -> None:
        accepted = (
            "avery.example@example.com",
            "example_avery@example.com",
            "averyexample@example.com",
            "aexample@example.com",
            "a.example@example.com",
            "avery+review@example.com",
        )
        for email in accepted:
            with self.subTest(email=email):
                self.assertEqual(propose_alias_groups([f"Mail {email} now."], ["Avery Example"]), (("Avery Example", (email,)),))
        for email in ("info@example.com", "averye@example.com", "example@example.com", "ave@example.com"):
            with self.subTest(email=email):
                self.assertEqual(propose_alias_groups([f"Mail {email} now."], ["Avery Example"]), ())

    def test_ambiguous_email_local_parts_produce_no_proposal(self) -> None:
        text = "Mail a.example@example.com or avery@example.com.\n"
        self.assertEqual(propose_alias_groups([text], ["Avery Example", "Alex Example", "Avery Stone"]), ())


class DiscoverDraftTest(TempRoot):
    def setUp(self) -> None:
        super().setUp()
        self.write("stakeholders.md", STAKEHOLDERS)
        self.write("email.md", EMAIL)
        self.ctx = core.RedactedContext(self.root, core.RedactionConfig())

    def discover(self, client: object, **kwargs: object) -> core.DiscoveryResult:
        return core.discover_entities(
            self.ctx, paths=[], globs=["*.md"], client=client,  # type: ignore[arg-type]
            max_files=10, max_chars_per_file=10_000, **kwargs,
        )

    def test_draft_proposes_groups_that_load(self) -> None:
        result = self.discover(StaticClient(core.DiscoveryResult(people=PEOPLE)), propose_aliases=True)
        self.assertEqual(result.aliases, EXPECTED)
        self.assertEqual(result.dropped_aliases, 0)
        draft = core.format_discovery_toml(result, source_note="test")
        self.assertIn("[redaction.aliases]", draft)
        self.assertIn("Check every link", draft)
        self.assertEqual(
            self.load_groups(draft),
            tuple(AliasGroup("PERSON", canonical, aliases) for canonical, aliases in EXPECTED),
        )

    def test_known_people_make_a_first_name_ambiguous(self) -> None:
        result = self.discover(
            StaticClient(core.DiscoveryResult(people=PEOPLE)),
            propose_aliases=True,
            known_people=("Avery Stone",),
        )
        # Both the standalone first name and the first-name-only address are withheld.
        self.assertEqual(result.aliases, EXPECTED[1:])

    def test_invalid_and_conflicting_proposals_are_dropped_and_counted(self) -> None:
        self.write("single/notes.md", "Avery Example, Morgan Sample, Python, Email, Nobody Here and Nobody. Thanks, Avery\n")
        suggested = core.DiscoveryResult(
            people=PEOPLE,
            allow=("Python",),
            aliases=(
                ("Avery Example", ("Avery", "Python", "Email", "Morgan Sample", "Ave Q. Never")),
                ("Nobody Here", ("Nobody",)),
                ("Morgan Sample", ("Avery",)),
            ),
        )
        result = core.discover_entities(
            self.ctx, paths=["single"], globs=[], client=StaticClient(suggested),  # type: ignore[arg-type]
            max_files=10, max_chars_per_file=10_000,
        )
        self.assertEqual(result.aliases, (("Avery Example", ("Avery",)),))
        # "Ave Q. Never" does not occur; then the draft check drops Python (a
        # built-in allow term), Email (reserved), Morgan Sample (a canonical
        # value), Nobody (its canonical value is not a listed name), and the
        # second group's Avery (already an alias of the first group).
        self.assertEqual(result.dropped_aliases, 6)
        draft = core.format_discovery_toml(result, source_note="test")
        self.assertIn("# Alias proposals dropped as unsourced, invalid, or conflicting: 6", draft)
        for raw in ("Nobody", "Ave Q", "Email", "Python"):
            self.assertNotIn(raw, draft)
        self.load_groups(draft)

    def discover_orgs(self, text: str, suggested: core.DiscoveryResult) -> core.DiscoveryResult:
        self.write("orgs/notes.md", text)
        return core.discover_entities(
            self.ctx, paths=["orgs"], globs=[], client=StaticClient(suggested),  # type: ignore[arg-type]
            max_files=10, max_chars_per_file=10_000, propose_aliases=True,
        )

    def test_person_shaped_organizations_do_not_make_a_first_name_ambiguous(self) -> None:
        # Post-processing keeps a person-shaped organization out of people, so it
        # never counts as a namesake in the alias ambiguity checks.
        result = self.discover_orgs(
            "Avery Example leads the pilot with Avery Lantern Labs.\nReach her at avery@example.com.\n",
            core.DiscoveryResult(people=("Avery Example",), organizations=("Avery Lantern Labs",)),
        )
        self.assertEqual(result.aliases, (("Avery Example", ("avery@example.com",)),))
        self.assertEqual((result.people, result.organizations), (("Avery Example",), ("Avery Lantern Labs",)))

    def test_person_shaped_organizations_get_no_email_alias(self) -> None:
        result = self.discover_orgs(
            "The Harbor Lantern desk takes intake at harbor.lantern@example.com.\n",
            core.DiscoveryResult(organizations=("Harbor Lantern",)),
        )
        self.assertEqual((result.aliases, result.dropped_aliases), ((), 0))
        self.assertEqual((result.people, result.organizations), ((), ("Harbor Lantern",)))

    def test_raw_discovery_skips_heuristics_but_keeps_model_suggestions(self) -> None:
        suggested = core.DiscoveryResult(people=PEOPLE, aliases=(("Morgan Sample", ("Morgan",)),))
        result = self.discover(StaticClient(suggested), postprocess=False, propose_aliases=False)
        self.assertEqual(result.aliases, (("Morgan Sample", ("Morgan",)),))

    def test_model_suggestions_must_occur_in_the_sample(self) -> None:
        client = core.OllamaDiscoveryClient(endpoint="http://localhost:11434", model="m", timeout=1)
        response = FakeOllamaResponse({
            "clients": [], "organizations": [], "terms": [], "allow": [],
            "people": ["Avery Example"],
            "aliases": {"Avery Example": ["Avery", "Ave", "avery.x@example.com", 7]},
        })
        with patch("redacted_context_mcp.discovery.urllib.request.urlopen", return_value=response):
            result = client.extract(rel_path="email.md", text="Avery Example wrote. Thanks, Avery")
        self.assertEqual(result.aliases, (("Avery Example", ("Avery",)),))
        self.assertEqual(result.dropped_aliases, 3)

    def test_malformed_model_aliases_are_counted(self) -> None:
        result = core.parse_discovery_response(json.dumps({"people": ["Avery Example"], "aliases": ["Avery"]}))
        self.assertEqual((result.aliases, result.dropped_aliases), ((), 1))
        self.assertIn("aliases", core.build_discovery_prompt(rel_path="a.md", text="x"))
        self.assertIn('"aliases":{}', core.build_strict_discovery_prompt(rel_path="a.md", text="x"))

    def test_command_discover_json_lists_aliases_and_drop_count(self) -> None:
        output = io.StringIO()
        result = core.DiscoveryResult(people=PEOPLE, aliases=EXPECTED, dropped_aliases=2)
        with patch("redacted_context_mcp.core.OllamaDiscoveryClient", return_value=object()):
            with patch("redacted_context_mcp.core.discover_entities", return_value=result):
                with contextlib.redirect_stdout(output):
                    core.command_discover(
                        Namespace(
                            provider="ollama", endpoint=None, model=None, timeout=1.0, raw_discovery=False,
                            paths=[], glob=[], max_files=10, max_chars_per_file=1000, max_total_raw_bytes=10_000,
                            fail_on_truncation=False, format="json", output=None, force=False,
                        ),
                        self.ctx,
                        core.Redactor(core.RedactionConfig()),
                    )
        parsed = json.loads(output.getvalue())
        self.assertEqual(parsed["aliases"]["Avery Example"], ["Avery", "avery@example.com"])
        self.assertEqual(parsed["dropped_alias_proposals"], 2)


class DiscoverUpdateAliasTest(TempRoot):
    EXISTING = (
        "# reviewed config\n"
        "[redaction]\n"
        'people = ["Avery Example", "Morgan Sample", "Jordan Vale"]\n'
        "\n"
        "[redaction.aliases]  # who is who\n"
        '"Avery Example" = ["Avery"]  # signs emails\n'
        "# Morgan has none yet\n"
        "\n"
        "[github.repos.context]\n"
        'owner = "o"\n'
        'repo = "r"\n'
    )
    DISCOVERED = core.DiscoveryResult(
        aliases=(
            ("Avery Example", ("Avery", "avery@example.com")),
            ("Morgan Sample", ("Morgan", "Avery")),
            ("Unknown Person", ("Unknown",)),
        ),
        dropped_aliases=1,
    )

    def update(self, existing: str, discovery: core.DiscoveryResult, **kwargs: object) -> core.DiscoveryUpdate:
        return core.build_discovery_update(existing, discovery, **kwargs)

    @staticmethod
    def aliases_table(text: str) -> str:
        return text[text.index("[redaction.aliases]") :]

    def test_discovered_aliases_are_merged_only_with_the_opt_in_flag(self) -> None:
        without = self.update(self.EXISTING, self.DISCOVERED)
        self.assertEqual(self.aliases_table(without.config_text), self.aliases_table(self.EXISTING))
        self.assertIn("allow = []\n\n[redaction.aliases]", without.config_text)
        self.assertEqual(without.alias_counts, {"seed": 0, "discovered": 0, "dropped": 0})

        merged = self.update(self.EXISTING, self.DISCOVERED, include_discovered_aliases=True)
        self.assertEqual(merged.alias_counts, {"seed": 0, "discovered": 2, "dropped": 3})
        self.assertIn('"Avery Example" = ["Avery", "avery@example.com"]\n# Morgan has none yet\n', merged.config_text)
        self.assertIn('"Morgan Sample" = ["Morgan"]\n\n[github.repos.context]', merged.config_text)
        self.assertIn("[redaction.aliases]  # who is who\n", merged.config_text)
        self.assertNotIn("Unknown", merged.config_text)
        self.assertEqual(
            self.load_groups(merged.config_text),
            (
                AliasGroup("PERSON", "Avery Example", ("Avery", "avery@example.com")),
                AliasGroup("PERSON", "Morgan Sample", ("Morgan",)),
            ),
        )
        again = self.update(merged.config_text, self.DISCOVERED, include_discovered_aliases=True)
        self.assertFalse(again.changed)

    def test_merge_never_removes_or_rewrites_existing_groups(self) -> None:
        conflicting = core.DiscoveryResult(
            aliases=(("Morgan Sample", ("Avery",)), ("Avery", ("Avery Example",)), ("Jordan Vale", ("Morgan Sample",)))
        )
        update = self.update(self.EXISTING, conflicting, include_discovered_aliases=True)
        self.assertEqual(self.aliases_table(update.config_text), self.aliases_table(self.EXISTING))
        self.assertEqual(update.alias_counts, {"seed": 0, "discovered": 0, "dropped": 3})

    def test_new_aliases_table_is_created_when_missing(self) -> None:
        discovery = core.DiscoveryResult(people=PEOPLE, aliases=EXPECTED)
        for existing in ("", '[redaction]\nallow = ["Python"]\n', 'people = ["Avery Example"]\n'):
            with self.subTest(existing=existing):
                update = self.update(existing, discovery, include_discovered_aliases=True)
                groups = self.load_groups(update.config_text)
                self.assertEqual([group.aliases for group in groups], [aliases for _canonical, aliases in EXPECTED])
                header = "[aliases]" if existing.startswith("people") else "[redaction.aliases]"
                self.assertIn(f"\n{header}\n", update.config_text)

    def test_inline_alias_tables_are_not_rewritten(self) -> None:
        existing = '[redaction]\npeople = ["Avery Example"]\naliases = { "Avery Example" = ["Avery"] }\n'
        with self.assertRaises(ValueError) as raised:
            self.update(existing, core.DiscoveryResult(aliases=EXPECTED[:1]), include_discovered_aliases=True)
        self.assertNotIn("Avery", str(raised.exception))
        unchanged = self.update(existing, core.DiscoveryResult(aliases=EXPECTED[:1])).config_text
        self.assertIn('aliases = { "Avery Example" = ["Avery"] }\n', unchanged)
        self.assertEqual(self.load_groups(unchanged), (AliasGroup("PERSON", "Avery Example", ("Avery",)),))

    def test_seed_aliases_are_carried_into_the_output(self) -> None:
        seed = (
            '[redaction]\npeople = ["Morgan Sample", "Avery Example"]\n\n'
            '[redaction.aliases]\n"Morgan Sample" = ["Morgan", "Avery"]\n"Avery Example" = ["avery@example.com"]\n'
        )
        update = self.update(self.EXISTING, core.DiscoveryResult(), seed_text=seed)
        self.assertEqual(update.alias_counts, {"seed": 2, "discovered": 0, "dropped": 1})
        self.assertEqual(
            self.load_groups(update.config_text),
            (
                AliasGroup("PERSON", "Avery Example", ("Avery", "avery@example.com")),
                AliasGroup("PERSON", "Morgan Sample", ("Morgan",)),
            ),
        )

    def test_merge_only_cli_reports_seed_alias_counts(self) -> None:
        self.write(".agent-context-redactor.toml", self.EXISTING)
        self.write("seed.toml", '[redaction]\n\n[redaction.aliases]\n"Morgan Sample" = ["Morgan", "Avery"]\n')
        output = io.StringIO()
        args = Namespace(
            input_jsonl=None, merge_only=True, max_files=10, max_chars_per_document=1_000, max_total_chars=10_000,
            endpoint=None, model=None, timeout=1.0, output_config=".agent-context-redactor.toml",
            seed_config="seed.toml", include_discovered_allow=False, include_discovered_aliases=False,
            dry_run=False, check=False,
        )
        with contextlib.redirect_stdout(output):
            status = core.command_discover_update(args, core.RedactedContext(self.root, core.RedactionConfig()), None)
        self.assertEqual(status, 0)
        self.assertIn('alias_counts: {"discovered":0,"dropped":1,"seed":1}\n', output.getvalue())
        self.assertNotIn("Morgan", output.getvalue())
        config = (self.root / ".agent-context-redactor.toml").read_text(encoding="utf-8")
        self.assertIn('"Morgan Sample" = ["Morgan"]', config)


class DiscoverAliasCliTest(TempRoot):
    RULES = (
        "[[patterns]]\n"
        'category = "PERSON"\n'
        "regex = '\\b(?:Avery Example|Morgan Sample)\\b'\n"
    )

    def setUp(self) -> None:
        super().setUp()
        self.write("stakeholders.md", STAKEHOLDERS)
        self.write("email.md", EMAIL)
        self.rules = Path(self.tmp.name).resolve() / "rules.toml"
        self.rules.write_text(self.RULES, encoding="utf-8")

    def run_cli(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", "redacted_context_mcp.core", "--root", str(self.root), *args],
            input=stdin, text=True, capture_output=True, check=False, cwd=PROJECT_ROOT,
            env={**ENV, "REDACTED_CONTEXT_STATE_DIR": str(self.state)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_discover_with_a_local_detector_drafts_alias_groups(self) -> None:
        draft = self.run_cli("discover", "--detector", f"patterns={self.rules}", "--glob", "*.md").stdout
        self.assertIn('"Avery Example" = ["Avery", "avery@example.com"]', draft)
        self.assertEqual(len(self.load_groups(draft)), 2)
        raw = self.run_cli("discover", "--detector", f"patterns={self.rules}", "--raw-discovery").stdout
        self.assertNotIn("[redaction.aliases]", raw)

    def test_discover_update_merges_aliases_only_when_asked(self) -> None:
        documents = "".join(
            json.dumps({"path": name, "text": text}) + "\n" for name, text in (("s.md", STAKEHOLDERS), ("e.md", EMAIL))
        )
        common = ("discover-update", "--input-jsonl", "-", "--detector", f"patterns={self.rules}")
        plain = self.run_cli(*common, stdin=documents)
        self.assertIn('alias_counts: {"discovered":0,"dropped":0,"seed":0}', plain.stdout)
        config = self.root / ".agent-context-redactor.toml"
        self.assertNotIn("aliases", config.read_text(encoding="utf-8"))

        merged = self.run_cli(*common, "--include-discovered-aliases", stdin=documents)
        self.assertIn('alias_counts: {"discovered":4,"dropped":0,"seed":0}', merged.stdout)
        self.assertNotIn("Avery", merged.stdout + merged.stderr)
        self.assertEqual(len(self.load_groups(config.read_text(encoding="utf-8"))), 2)


if __name__ == "__main__":
    unittest.main()
