"""Local-LLM assisted redaction-term discovery."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Iterable

from .config import dedupe
from .defaults import (
    COUNTRY_OR_REGION_ONLY,
    DEFAULT_ALLOW_TERMS,
    DISCOVERY_KEYS,
    FILENAME_OR_EXTENSION_RE,
    GENERIC_ORG_WORDS,
    GENERIC_TERM_PATTERNS,
    NON_PERSON_NAME_WORDS,
    REFERENCE_ID_RE,
    RESERVED_PLACEHOLDER_WORDS,
    ROLE_WORDS,
)
from .filesystem import RedactedContext, iter_target_files, read_text_file
from .limits import OperationLimitError
from .models import DiscoveryParseError, DiscoveryResult
from .paths import rel_posix, resolve_under_root

class OllamaDiscoveryClient:
    def __init__(self, *, endpoint: str, model: str, timeout: float, postprocess: bool = True):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.postprocess = postprocess

    @property
    def generate_url(self) -> str:
        if self.endpoint.endswith("/api/generate"):
            return self.endpoint
        return f"{self.endpoint}/api/generate"

    def extract(self, *, rel_path: str, text: str) -> DiscoveryResult:
        prompt = build_discovery_prompt(rel_path=rel_path, text=text)
        content = self.generate(prompt)
        try:
            return parse_discovery_response(content, postprocess=self.postprocess)
        except DiscoveryParseError:
            retry_prompt = build_strict_discovery_prompt(rel_path=rel_path, text=text)
            retry_content = self.generate(retry_prompt)
            try:
                return parse_discovery_response(retry_content, postprocess=self.postprocess)
            except DiscoveryParseError as exc:
                raise SystemExit(
                    "Local LLM did not return a JSON object after a stricter retry. "
                    "Try a smaller --max-chars-per-file value such as 4000, or use "
                    "a different model that follows JSON mode more reliably."
                ) from exc

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        }
        request = urllib.request.Request(
            self.generate_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            detail = extract_ollama_error(body)
            reason = f" {exc.reason}" if exc.reason else ""
            raise SystemExit(
                f"Ollama request failed for model '{self.model}' ({exc.code}{reason}). "
                f"{detail}Run `ollama list` to see installed model names, or "
                f"`ollama pull {self.model}` to install this exact tag."
            ) from exc
        except urllib.error.URLError as exc:
            raise SystemExit(
                f"Could not reach local Ollama at {self.endpoint}. Start Ollama and try again."
            ) from exc
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SystemExit("Ollama returned invalid JSON.") from exc
        if data.get("error"):
            raise SystemExit(
                f"Ollama returned an error for model '{self.model}': {data['error']}. "
                "Run `ollama list` to see installed model names."
            )
        return str(data.get("response", ""))


def extract_ollama_error(body: str) -> str:
    if not body.strip():
        return ""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        detail = body.strip()
    else:
        detail = str(data.get("error", "")).strip()
    if not detail:
        return ""
    return f"{detail}. "


def build_discovery_prompt(*, rel_path: str, text: str) -> str:
    return (
        "You are extracting sensitive names for a local redaction configuration. "
        "The text never leaves this machine. Return only a JSON object with exactly "
        "these keys: clients, organizations, people, terms, allow. Each value must "
        "be an array of exact strings copied from the input.\n\n"
        "Definitions:\n"
        "- clients: customer/client/account legal names, brand names, and acronyms only. "
        "Do not include vendors, people, countries, regions, or generic department words.\n"
        "- organizations: private partner, vendor, supplier, employer, or third-party "
        "organization names. Do not include public cloud products, open-source tools, "
        "job titles, roles, people, or generic departments.\n"
        "- people: full human names only. Do not include job titles, roles, single first "
        "names, field labels, or notes in parentheses.\n"
        "- terms: private project codenames, internal programme names, private system names, "
        "private source-system names, private dataset names, and private acronyms. Do not "
        "include meeting IDs, ticket IDs, filenames, file extensions, generic architecture "
        "terms, generic workflow/process names, GDPR concepts, or common technology terms.\n"
        "- allow: public technology names, public cloud products, open-source tools, ordinary "
        "architecture/process vocabulary, and generic domain words that should not be redacted.\n\n"
        "Do not invent values. Prefer exact original casing. When unsure, omit the value.\n\n"
        f"Path: {rel_path}\n\n"
        "Text:\n"
        f"{text}\n"
    )


def build_strict_discovery_prompt(*, rel_path: str, text: str) -> str:
    return (
        "Return exactly one JSON object and no other text. "
        "The object must have this exact shape:\n"
        '{"clients":[],"organizations":[],"people":[],"terms":[],"allow":[]}\n\n'
        "Use arrays of strings only. Copy exact strings from the text. "
        "Use empty arrays when no value is found. Do not include markdown, comments, "
        "analysis, explanations, code fences, or extra keys.\n\n"
        "clients: customer/client/account legal names, brand names, and acronyms.\n"
        "organizations: private partner, vendor, supplier, employer, or third-party names.\n"
        "people: full human names only.\n"
        "terms: private project codenames, internal programme/system/dataset names, and private acronyms.\n"
        "allow: public technologies, open-source tools, public cloud products, and generic vocabulary.\n\n"
        f"Path: {rel_path}\n\n"
        "Text:\n"
        f"{text}\n"
    )


def parse_discovery_response(text: str, *, postprocess: bool = True) -> DiscoveryResult:
    data = parse_json_object(text)
    values: dict[str, tuple[str, ...]] = {}
    for key in DISCOVERY_KEYS:
        raw_values = data.get(key, [])
        if not isinstance(raw_values, list):
            raw_values = []
        values[key] = clean_discovered_terms(str(item) for item in raw_values)
    result = DiscoveryResult(**values)
    return postprocess_discovery_result(result) if postprocess else result


def parse_json_object(text: str) -> dict[str, object]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise DiscoveryParseError("Local LLM did not return a JSON object.")
        try:
            data = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise DiscoveryParseError("Local LLM did not return a parseable JSON object.") from exc
    if not isinstance(data, dict):
        raise DiscoveryParseError("Local LLM response must be a JSON object.")
    return data


def clean_discovered_terms(values: Iterable[str]) -> tuple[str, ...]:
    cleaned: list[str] = []
    for value in values:
        value = re.sub(r"\s+", " ", value.strip().strip("\"'`"))
        if not value:
            continue
        if len(value) < 2 or len(value) > 120:
            continue
        if "\n" in value or "\r" in value:
            continue
        if value.casefold() in RESERVED_PLACEHOLDER_WORDS:
            continue
        cleaned.append(value)
    return dedupe(cleaned)


def postprocess_discovery_result(result: DiscoveryResult, *, include_single_names: bool = False) -> DiscoveryResult:
    buckets: dict[str, list[str]] = {key: [] for key in DISCOVERY_KEYS}

    def add(key: str, value: str) -> None:
        cleaned = normalize_discovery_value(value)
        if cleaned:
            buckets[key].append(cleaned)

    for value in result.clients:
        if should_drop_discovered_value(value):
            continue
        if is_public_or_allowed_term(value):
            continue
        elif is_probable_person(value, include_single_names=include_single_names):
            add("people", normalize_person_name(value))
        elif is_country_or_region_only(value) or is_generic_org_value(value):
            continue
        else:
            add("clients", value)

    for value in result.organizations:
        if should_drop_discovered_value(value):
            continue
        if is_public_or_allowed_term(value):
            continue
        elif is_probable_person(value, include_single_names=include_single_names):
            add("people", normalize_person_name(value))
        elif is_country_or_region_only(value) or is_role_or_title(value) or is_generic_org_value(value):
            continue
        else:
            add("organizations", value)

    for value in result.people:
        person = normalize_person_name(value)
        if should_drop_discovered_value(person) or is_role_or_title(person):
            continue
        if is_probable_person(person, include_single_names=include_single_names):
            add("people", person)

    for value in result.terms:
        if should_drop_discovered_value(value):
            continue
        if is_public_or_allowed_term(value):
            continue
        if is_likely_tool_or_package_name(value):
            add("allow", value)
        elif is_probable_person(value, include_single_names=include_single_names):
            add("people", normalize_person_name(value))
        elif is_generic_discovery_term(value):
            continue
        else:
            add("terms", value)

    for value in result.allow:
        if not should_drop_discovered_value(value) and not is_public_or_allowed_term(value):
            add("allow", value)

    return DiscoveryResult(
        clients=dedupe(buckets["clients"]),
        organizations=dedupe(buckets["organizations"]),
        people=dedupe(buckets["people"]),
        terms=dedupe(buckets["terms"]),
        allow=dedupe(buckets["allow"]),
    )


def normalize_discovery_value(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().strip("\"'`"))


def normalize_person_name(value: str) -> str:
    value = normalize_discovery_value(value)
    value = re.sub(r"\s+\([^)]*\)\s*$", "", value).strip()
    return value


def should_drop_discovered_value(value: str) -> bool:
    value = normalize_discovery_value(value)
    key = value.casefold()
    if not value or key in RESERVED_PLACEHOLDER_WORDS:
        return True
    if "likely" in key or "typo" in key or "placeholder" in key:
        return True
    if FILENAME_OR_EXTENSION_RE.search(value) or "/" in value or "\\" in value:
        return True
    if REFERENCE_ID_RE.match(value):
        return True
    return False


def is_public_or_allowed_term(value: str) -> bool:
    key = normalize_discovery_value(value).casefold()
    return key in {term.casefold() for term in DEFAULT_ALLOW_TERMS}


def is_likely_tool_or_package_name(value: str) -> bool:
    value = normalize_discovery_value(value)
    return bool(re.fullmatch(r"[a-z][a-z0-9._-]{2,30}", value))


def is_country_or_region_only(value: str) -> bool:
    return normalize_discovery_value(value).casefold() in COUNTRY_OR_REGION_ONLY


def is_generic_org_value(value: str) -> bool:
    return normalize_discovery_value(value).casefold() in GENERIC_ORG_WORDS


def is_role_or_title(value: str) -> bool:
    key = normalize_discovery_value(value).casefold()
    return any(role in key for role in ROLE_WORDS)


def is_generic_discovery_term(value: str) -> bool:
    value = normalize_discovery_value(value)
    key = value.casefold()
    if is_country_or_region_only(value) or is_generic_org_value(value):
        return True
    if is_role_or_title(value):
        return True
    return any(re.search(pattern, key, re.IGNORECASE) for pattern in GENERIC_TERM_PATTERNS)


def is_probable_person(value: str, *, include_single_names: bool) -> bool:
    value = normalize_person_name(value)
    if not value or any(char.isdigit() for char in value):
        return False
    if is_role_or_title(value) or is_public_or_allowed_term(value):
        return False
    tokens = [token for token in re.split(r"\s+", value) if token]
    if len(tokens) < 2 and not include_single_names:
        return False
    if len(tokens) > 5:
        return False
    if any(token.strip(".,;:()[]{}").casefold() in NON_PERSON_NAME_WORDS for token in tokens):
        return False
    return all(is_name_token(token) for token in tokens)


def is_name_token(token: str) -> bool:
    token = token.strip(".,;:()[]{}")
    if not token:
        return False
    if token.casefold() in COUNTRY_OR_REGION_ONLY:
        return False
    letters = [char for char in token if char.isalpha()]
    if not letters:
        return False
    if len(letters) > 1 and "".join(letters).isupper():
        return False
    return letters[0].isupper()


def merge_discovery_results(results: Iterable[DiscoveryResult], *, postprocess: bool = True) -> DiscoveryResult:
    merged: dict[str, list[str]] = {key: [] for key in DISCOVERY_KEYS}
    for result in results:
        for key, values in result.as_dict().items():
            merged[key].extend(values)
    result = DiscoveryResult(
        clients=dedupe(merged["clients"]),
        organizations=dedupe(merged["organizations"]),
        people=dedupe(merged["people"]),
        terms=dedupe(merged["terms"]),
        allow=dedupe(merged["allow"]),
    )
    return postprocess_discovery_result(result) if postprocess else result


def discover_entities(
    ctx: RedactedContext,
    *,
    paths: list[str],
    globs: list[str],
    client: OllamaDiscoveryClient,
    max_files: int,
    max_chars_per_file: int,
    max_total_raw_bytes: int | None = None,
    postprocess: bool = True,
) -> DiscoveryResult:
    results: list[DiscoveryResult] = []
    total_bytes = 0
    for index, path in enumerate(iter_target_files(ctx, paths, globs)):
        if index >= max_files:
            break
        rel = rel_posix(path, ctx.root)
        text, bytes_read, truncated = read_discovery_sample(path, max_bytes=max_chars_per_file)
        total_bytes += bytes_read
        if max_total_raw_bytes is not None and total_bytes > max_total_raw_bytes:
            raise OperationLimitError("Discovery total byte limit exceeded.")
        if truncated:
            text += "\n[TRUNCATED DISCOVERY SAMPLE]\n"
        results.append(client.extract(rel_path=rel, text=text))
    return merge_discovery_results(results, postprocess=postprocess)


def read_discovery_sample(path, *, max_bytes: int) -> tuple[str, int, bool]:
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    return data.decode("utf-8-sig", errors="replace"), len(data), truncated


def format_discovery_toml(result: DiscoveryResult, *, source_note: str) -> str:
    return (
        "# Generated by redctx discover.\n"
        "# Review before use; this file intentionally contains sensitive terms.\n"
        f"# Source: {source_note}\n\n"
        "[redaction]\n"
        f"clients = {format_toml_array(result.clients)}\n"
        f"organizations = {format_toml_array(result.organizations)}\n"
        f"people = {format_toml_array(result.people)}\n"
        f"terms = {format_toml_array(result.terms)}\n"
        f"allow = {format_toml_array(result.allow)}\n"
    )


def format_toml_array(values: Iterable[str]) -> str:
    values = tuple(values)
    if not values:
        return "[]"
    encoded = ",\n  ".join(json.dumps(value, ensure_ascii=False) for value in values)
    return f"[\n  {encoded}\n]"


def write_discovery_output(ctx: RedactedContext, output: str, destination: str | None, *, force: bool) -> None:
    if destination is None:
        print(output, end="" if output.endswith("\n") else "\n")
        return
    path = resolve_under_root(ctx.root, destination, allow_missing=True)
    if path.exists() and not force:
        raise SystemExit("Output file already exists. Use --force to overwrite.")
    path.write_text(output, encoding="utf-8")
    print(f"Wrote discovery output to {path.relative_to(ctx.root).as_posix()}")
