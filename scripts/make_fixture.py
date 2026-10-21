#!/usr/bin/env python3
"""Create a tiny synthetic harness home (index + every table) for CI or demos.

Usage:
    python3 scripts/make_fixture.py /tmp/hv-fixture [--force]
    CROWBAR_HOME=/tmp/hv-fixture ./bin/crowbar stats
    CROWBAR_HOME=/tmp/hv-fixture ./bin/crowbar cve CVE-2021-44228

The fixture is ~200 KB and contains one or two rows per table plus every FTS
index, so CLI/MCP code paths run without the 3.3 GB corpus.
"""
from __future__ import annotations

import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.support import make_fixture_db  # noqa: E402


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    dest = pathlib.Path(argv[0]).expanduser().resolve()
    force = "--force" in argv[1:]
    if dest.exists() and any(dest.iterdir()):
        if not force:
            print(f"{dest} is not empty (use --force)")
            return 1
        shutil.rmtree(dest)
    (dest / "index").mkdir(parents=True, exist_ok=True)
    (dest / "data").mkdir(parents=True, exist_ok=True)
    db = make_fixture_db(dest / "index" / "crowbar.db")
    print(f"fixture ready: {db}")
    print(f"  CROWBAR_HOME={dest} ./bin/crowbar stats")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
