"""Validate the frozen bibliography inventory and its manuscript audit.

The standalone artifact checks the frozen inventory against reference_audit.csv.
When --bib and --tex-root are supplied from the complete project package, the
same program also parses the current BibTeX file and all manuscript TeX files,
so citation coverage is checked against the publication sources themselves.
This is an integrity check over recorded metadata; it does not perform network
resolution and does not claim to reread every cited paper.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DOI_RE = re.compile(r"^10\.\d{4,9}/[-._;()/:A-Z0-9]+$", re.IGNORECASE)
CITE_RE = re.compile(
    r"\\cite[A-Za-z*]*\s*(?:\[[^\]]*\]\s*){0,2}\{([^{}]+)\}", re.MULTILINE
)


def _balanced_block(text: str, start: int) -> tuple[str, int]:
    """Return the contents and end index of a braced block starting at start."""
    if start >= len(text) or text[start] != "{":
        raise ValueError("expected opening brace")
    depth = 0
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:index], index + 1
            if depth < 0:
                break
    raise ValueError("unbalanced BibTeX braces")


def _split_top_level(text: str, delimiter: str = ",") -> list[str]:
    pieces: list[str] = []
    begin = 0
    depth = 0
    quote = False
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"' and depth == 0:
            quote = not quote
        elif not quote:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif char == delimiter and depth == 0:
                pieces.append(text[begin:index])
                begin = index + 1
    pieces.append(text[begin:])
    return pieces


def _unwrap(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == "{" and value[-1] == "}":
        inner, end = _balanced_block(value, 0)
        if end == len(value):
            return inner.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].strip()
    return value


def parse_bibtex(text: str) -> dict[str, dict[str, Any]]:
    """Parse the braced/quoted BibTeX subset used by the manuscript."""
    entries: dict[str, dict[str, Any]] = {}
    cursor = 0
    marker = re.compile(r"@([A-Za-z]+)\s*\{")
    while True:
        match = marker.search(text, cursor)
        if match is None:
            break
        body, end = _balanced_block(text, match.end() - 1)
        parts = _split_top_level(body)
        if not parts:
            raise ValueError("empty BibTeX entry")
        key = parts[0].strip()
        if not key or key in entries:
            raise ValueError(f"invalid or duplicate BibTeX key: {key!r}")
        fields: dict[str, str] = {}
        for piece in parts[1:]:
            if not piece.strip():
                continue
            if "=" not in piece:
                raise ValueError(f"malformed field in {key}: {piece!r}")
            name, value = piece.split("=", 1)
            field = name.strip().lower()
            if not field or field in fields:
                raise ValueError(f"invalid or duplicate field {field!r} in {key}")
            fields[field] = _unwrap(value)
        entries[key] = {"entry_type": match.group(1).lower(), "fields": fields}
        cursor = end
    return entries


def _norm(value: str) -> str:
    return " ".join(value.split())


def cited_keys(tex_paths: Iterable[Path]) -> set[str]:
    found: set[str] = set()
    for path in tex_paths:
        text = path.read_text()
        for match in CITE_RE.finditer(text):
            found.update(key.strip() for key in match.group(1).split(",") if key.strip())
    return found


def entry_identifier(entry: dict[str, Any]) -> tuple[str, str]:
    fields = entry["fields"]
    doi = fields.get("doi", "").strip()
    if doi:
        if not DOI_RE.fullmatch(doi):
            raise ValueError(f"invalid DOI syntax: {doi}")
        return "doi", f"https://doi.org/{doi}"
    url = fields.get("url", "").strip()
    how = fields.get("howpublished", "").lower()
    if "arxiv.org/abs/" in url or "arxiv:" in how:
        return "arxiv", url
    if entry["entry_type"] == "techreport" and url:
        return "technical_report", url
    raise ValueError("entry has neither DOI, arXiv identifier, nor technical-report URL")


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def validate(
    *,
    inventory_path: Path,
    audit_path: Path,
    bib_path: Path | None = None,
    tex_root: Path | None = None,
) -> dict[str, Any]:
    inventory_rows = load_csv(inventory_path)
    audit_rows = load_csv(audit_path)
    inventory = {row["citation_key"]: row for row in inventory_rows}
    audit = {row["citation_key"]: row for row in audit_rows}
    if len(inventory) != len(inventory_rows):
        raise ValueError("duplicate citation key in reference inventory")
    if len(audit) != len(audit_rows):
        raise ValueError("duplicate citation key in reference audit")
    if set(inventory) != set(audit):
        raise ValueError("reference inventory and audit key sets differ")
    if len(inventory) < 55:
        raise ValueError("reference-count floor is not met")

    identifiers: dict[str, str] = {}
    types: dict[str, int] = {"doi": 0, "arxiv": 0, "technical_report": 0}
    for key, row in inventory.items():
        identifier = row["publication_identifier"].strip()
        kind = row["identifier_type"].strip()
        if kind not in types:
            raise ValueError(f"unknown identifier type for {key}: {kind}")
        if identifier in identifiers:
            raise ValueError(f"duplicate publication identifier: {key}, {identifiers[identifier]}")
        identifiers[identifier] = key
        types[kind] += 1
        if kind == "doi" and not identifier.startswith("https://doi.org/"):
            raise ValueError(f"noncanonical DOI URL for {key}")
        audit_row = audit[key]
        for field in ("title", "authors", "year", "publication_identifier"):
            if _norm(row[field]) != _norm(audit_row[field]):
                raise ValueError(f"inventory/audit mismatch for {key}: {field}")
        if audit_row["access_date"] != "2026-09-16":
            raise ValueError(f"stale access date for {key}")
        if not audit_row["manuscript_locations"].strip() or not audit_row["citation_context"].strip():
            raise ValueError(f"missing manuscript citation evidence for {key}")

    expected = {"doi": 55, "arxiv": 2, "technical_report": 1}
    if types != expected:
        raise ValueError(f"unexpected identifier distribution: {types}")

    live_checked = False
    citation_occurrences = sum(int(row.get("citation_occurrences", "0") or 0) for row in inventory_rows)
    if bib_path is not None or tex_root is not None:
        if bib_path is None or tex_root is None:
            raise ValueError("--bib and --tex-root must be supplied together")
        entries = parse_bibtex(bib_path.read_text())
        tex_paths = sorted(path for path in tex_root.rglob("*.tex") if path.is_file())
        used = cited_keys(tex_paths)
        if set(entries) != set(inventory) or used != set(inventory):
            raise ValueError("BibTeX, manuscript citation, and inventory key sets differ")
        live_counts = {key: 0 for key in inventory}
        live_locations = {key: [] for key in inventory}
        for path in tex_paths:
            text = path.read_text()
            relative = path.relative_to(tex_root).as_posix()
            for match in CITE_RE.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                for key in (item.strip() for item in match.group(1).split(",")):
                    if not key:
                        continue
                    live_counts[key] += 1
                    location = f"{relative}:{line}"
                    if location not in live_locations[key]:
                        live_locations[key].append(location)
        for key, entry in entries.items():
            row = inventory[key]
            kind, identifier = entry_identifier(entry)
            if kind != row["identifier_type"] or identifier != row["publication_identifier"]:
                raise ValueError(f"BibTeX identifier differs from inventory for {key}")
            fields = entry["fields"]
            for field in ("title", "author", "year"):
                target = "authors" if field == "author" else field
                if _norm(fields.get(field, "")) != _norm(row[target]):
                    raise ValueError(f"BibTeX metadata differs from inventory for {key}: {field}")
            if live_counts[key] != int(row["citation_occurrences"]):
                raise ValueError(f"citation count differs from inventory for {key}")
            if audit[key]["manuscript_locations"] != "; ".join(live_locations[key]):
                raise ValueError(f"manuscript locations differ from audit for {key}")
            if key not in audit[key]["citation_context"]:
                raise ValueError(f"citation context does not identify {key}")
        citation_occurrences = sum(live_counts.values())
        live_checked = True

    return {
        "status": "pass",
        "references": len(inventory),
        "identifier_distribution": types,
        "unique_publication_identifiers": len(identifiers),
        "all_references_cited": True,
        "citation_occurrences": citation_occurrences,
        "audit_access_date": "2026-09-16",
        "current_manuscript_parsed": live_checked,
        "scope": (
            "Offline integrity check over the frozen bibliography inventory, audit, and, when supplied, "
            "the current BibTeX and TeX sources. Formal metadata was manually rechecked against DOI, "
            "publisher, or author records on 2026-09-16; this command performs no live resolution and "
            "does not claim a new full-paper reread of every source."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, default=ROOT / "reference_inventory.csv")
    parser.add_argument("--audit", type=Path, default=ROOT / "reference_audit.csv")
    parser.add_argument("--bib", type=Path)
    parser.add_argument("--tex-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = validate(
        inventory_path=args.inventory,
        audit_path=args.audit,
        bib_path=args.bib,
        tex_root=args.tex_root,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
