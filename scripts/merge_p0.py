#!/usr/bin/env python3
"""Apply the approved P0 merge to the crowbar index.

The merge is schema v3 (CVE List v5 CNA records + public PoC discovery +
provenance) on top of the existing NVD-derived corpus.  It never overwrites an
existing NVD description or CVSS score: CNA data is stored side by side in
`cve_cna` / `cve_cna_ref` / `cve_cna_product`.

    python scripts/merge_p0.py --dry-run          # plan only
    python scripts/merge_p0.py --work index/crowbar.db.p0   # merge into a copy
    python scripts/merge_p0.py --promote          # swap the copy into place

The live index is never touched unless --promote is given, and the previous
file is kept as index/crowbar.db.pre-p0 for rollback (scripts/rollback_index.sh).
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import shutil
import sqlite3
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crowbar import intel, paths  # noqa: E402

TABLES = ("cve", "cve_cna", "cve_cna_ref", "cve_cna_product", "cve_meta", "poc",
          "poc_orphan", "cve_alias", "source_state", "cve_cwe", "cve_product",
          "cve_ref", "cpe_match")


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(con: sqlite3.Connection) -> dict:
    out = {}
    for t in TABLES:
        try:
            out[t] = con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
        except sqlite3.DatabaseError:
            out[t] = None
    try:
        out["schema"] = con.execute(
            "SELECT value FROM meta WHERE key='schema'").fetchone()[0]
    except sqlite3.DatabaseError:
        out["schema"] = "?"
    return out


def diff(before: dict, after: dict) -> list[tuple[str, int, int]]:
    rows = []
    for t in TABLES:
        b, a = before.get(t), after.get(t)
        if a is None:
            continue
        if b != a:
            rows.append((t, b or 0, a))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", help="index file to merge into (default: index/crowbar.db.p0)")
    ap.add_argument("--promote", action="store_true",
                    help="swap the merged file over index/crowbar.db")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    ap.add_argument("--force", action="store_true", help="reload even if sha256 matches")
    args = ap.parse_args()

    live = paths.DB
    work = pathlib.Path(args.work) if args.work else paths.INDEX / "crowbar.db.p0"

    cve_tar = paths.DATA / "intel/cveorg/cvelistV5-main.tar.gz"
    poc_tar = paths.DATA / "intel/poc-in-github/PoC-in-GitHub-master.tar.gz"

    print("P0 merge plan")
    print(f"  live index   {live}  ({human(live.stat().st_size)})")
    print(f"  work copy    {work}")
    print(f"  CVE List v5  {cve_tar.name}  "
          f"{human(cve_tar.stat().st_size) if cve_tar.exists() else 'MISSING'}")
    print(f"  PoC-in-GitHub {poc_tar.name}  "
          f"{human(poc_tar.stat().st_size) if poc_tar.exists() else 'MISSING'}")
    print("  schema       v2 -> v3 (cve_cna, cve_cna_ref, cve_cna_product, cve_meta,")
    print("                poc, poc_orphan, cve_alias, source_state)")
    print("  policy       NVD description/CVSS never overwritten; CNA stored side by side")
    print("  dedupe       cve_cwe / cve_product / cpe_match / cve_ref get unique indexes")
    print("  safety       no downloaded code is executed; archives are parsed as data")
    if args.dry_run:
        print("\ndry run - nothing written")
        return 0

    if not work.exists():
        shutil.copy2(live, work)
        print(f"\ncopied live index -> {work}")

    con = sqlite3.connect(work, timeout=300)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=DELETE")
    before = snapshot(con)

    t0 = time.time()
    intel.migrate(con, progress=print)
    counts = intel.load_all(con, progress=print, force=args.force)
    con.commit()

    after = snapshot(con)
    print(f"\nmerge finished in {round(time.time() - t0, 1)}s")
    print(f"  new CVE rows       {counts.get('cveorg', 0):,}")
    print(f"  PoC repositories   {counts.get('poc', 0):,}")
    print(f"  deprecated CWE     {counts.get('cwe_stubs', 0):,} stubs")
    print(f"  alias rows         {counts.get('aliases', 0):,}")
    print("\n  table                        before          after")
    for t, b, a in diff(before, after):
        print(f"  {t:<26} {b:>12,} {a:>14,}")

    con.execute("PRAGMA optimize")
    con.commit()
    con.close()

    digest = sha256(work)
    print(f"\n  merged sha256    {digest}")
    work.with_suffix(work.suffix + ".sha256").write_text(
        f"{digest}  {work.name}\n")

    if args.promote:
        backup = paths.INDEX / "crowbar.db.pre-p0"
        if not backup.exists():
            shutil.copy2(live, backup)
            print(f"  backup           {backup}")
        tmp = paths.INDEX / "crowbar.db.new"
        shutil.copy2(work, tmp)
        tmp.replace(live)
        print(f"  promoted         {live}")
        paths.save_state(schema=paths.SCHEMA_VERSION)   # freshness lives in the DB's meta rows
        print(f"  state.json       schema={paths.SCHEMA_VERSION}")
    else:
        print(f"\nnot promoted - review the diff, then run: "
              f"python scripts/merge_p0.py --work {work} --promote")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
