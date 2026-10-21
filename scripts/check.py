#!/usr/bin/env python3
"""Static checks shared by the pre-commit hook and CI.

No corpus, network, or third-party packages.  Exit 0 means the repo is
internally consistent:

  * every Python file compiles
  * every dataset in the registry has a catalog entry and real table
  * every catalog table exists in the schema
  * docs mention every user-facing command
  * no tabs / trailing whitespace in sources
  * every shipped manifest carries the release-please version
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crowbar import catalog, datasets, indexer  # noqa: E402

SOURCE_DIRS = ["crowbar", "tests", "scripts", "mcp", "bin"]
DOCS = ["README.md", "AGENTS.md", "docs/DATASETS.md", "docs/MAP.md"]
COMMANDS = ["search", "cve", "product", "kev", "exploit", "nuclei", "msf",
            "models", "attack", "cwe", "capec", "os", "advisory", "code",
            "bin", "debian", "poc", "sources", "map", "stats", "where", "sql",
            "doctor", "sync", "build", "update", "verify", "link", "unlink"]
errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)


def check_compile() -> None:
    for directory in SOURCE_DIRS:
        for path in sorted((ROOT / directory).rglob("*.py")):
            try:
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
            except SyntaxError as exc:
                fail(f"compile: {path.relative_to(ROOT)}:{exc.lineno}: {exc.msg}")


def check_catalog() -> None:
    schema = indexer.SCHEMA
    tables = set(re.findall(r"CREATE (?:VIRTUAL )?TABLE (?:IF NOT EXISTS )?(\w+)", schema))
    for name in catalog.TABLES:
        if name not in tables:
            fail(f"catalog table {name!r} is not in the schema")
    for dataset in datasets.registry(with_extra=True, with_bulk=True):
        info = catalog.describe(dataset.name)
        if not info["tables"]:
            fail(f"dataset {dataset.name!r} has no catalog tables")
        if not info["path"]:
            fail(f"dataset {dataset.name!r} has no catalog path")
        if dataset.group not in catalog.GROUPS:
            fail(f"dataset {dataset.name!r} has unknown group {dataset.group!r}")
    for group in catalog.GROUPS:
        if not any(d.group == group for d in
                   datasets.registry(with_extra=True, with_bulk=True)):
            fail(f"catalog group {group!r} has no datasets")


def check_docs() -> None:
    text = "\n".join((ROOT / d).read_text(encoding="utf-8")
                     for d in DOCS if (ROOT / d).exists())
    for command in COMMANDS:
        if not re.search(rf"crowbar {re.escape(command)}\b", text):
            fail(f"docs never mention 'crowbar {command}'")
    for doc in DOCS:
        if not (ROOT / doc).exists():
            fail(f"missing doc: {doc}")


def check_whitespace() -> None:
    paths: list[pathlib.Path] = []
    for directory in SOURCE_DIRS:
        paths += [p for p in (ROOT / directory).rglob("*")
                  if p.is_file() and p.suffix in (".py", ".sh")]
    paths += [ROOT / d for d in DOCS if (ROOT / d).exists()]
    paths.append(ROOT / "Makefile")
    for path in paths:
        if ".git" in path.parts:
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8",
                                                errors="replace").splitlines(), 1):
            if line.rstrip() != line:
                fail(f"trailing whitespace: {path.relative_to(ROOT)}:{n}")
            if "\t" in line and path.suffix not in (".py", "") and path.name != "Makefile":
                fail(f"tab: {path.relative_to(ROOT)}:{n}")


def check_versions() -> None:
    """release-please bumps these together; a hand edit to one drifts the rest."""
    want = json.loads((ROOT / ".release-please-manifest.json").read_text())["."]
    def grab(rel: str, pattern: str) -> str | None:
        m = re.search(pattern, (ROOT / rel).read_text(), re.M)
        return m[1] if m else None   # a missing marker reports as drift, not a crash

    found = {"crowbar/__init__.py": grab("crowbar/__init__.py", r'__version__ = "([^"]+)"'),
             "plugin.yaml": grab("plugin.yaml", r"^version: (\S+)"),
             "flake.nix": grab("flake.nix", r'version = "([^"]+)"; # x-release-please-version')}
    for rel in ("package.json", "server.json", "gemini-extension.json",
                ".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
        found[rel] = json.loads((ROOT / rel).read_text())["version"]
    found["server.json packages[0]"] = json.loads((ROOT / "server.json").read_text())["packages"][0]["version"]
    for rel, got in found.items():
        if got != want:
            fail(f"version drift: {rel} is {got}, release manifest says {want}")
    # the MCP registry proves PyPI ownership by finding this marker in the package README
    name = json.loads((ROOT / "server.json").read_text())["name"]
    if f"mcp-name: {name}" not in (ROOT / "README.md").read_text():
        fail(f"README.md lacks the MCP registry marker 'mcp-name: {name}'")


def main() -> int:
    check_versions()
    check_compile()
    check_catalog()
    check_docs()
    check_whitespace()
    if errors:
        print(f"check: {len(errors)} problem(s)")
        for err in errors:
            print(f"  - {err}")
        return 1
    datasets_n = len(datasets.registry(with_extra=True, with_bulk=True))
    print(f"check: ok · {datasets_n} datasets · {len(catalog.TABLES)} tables "
          f"· {len(catalog.GROUPS)} groups · {len(COMMANDS)} commands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
