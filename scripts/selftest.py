#!/usr/bin/env python3
"""End-to-end sanity checks. Exit 0 = healthy.  Usage: python3 scripts/selftest.py"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crowbar import db, paths, query  # noqa: E402

HV = ROOT / "bin" / "crowbar"
results: list[tuple[bool, str, str]] = []


def check(name: str, cond, detail: str = "") -> None:
    results.append((bool(cond), name, str(detail)))


def main() -> int:
    if not paths.DB.exists():
        print("FAIL: no index - run: hv sync && hv build")
        return 1

    con = db.connect()
    check(f"schema v{paths.SCHEMA_VERSION}", db.schema_version(con) == paths.SCHEMA_VERSION)
    check("integrity", con.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
    s = query.stats(con)
    n = s.get("cve", 0)
    check("cve rows > 300k", n > 300_000, f"{n:,}")
    check("cpe ranges > 1M", s.get("cpe_match", 0) > 1_000_000, f"{s.get('cpe_match', 0):,}")
    check("kev", s.get("cve_kev", 0) > 1000)
    check("epss coverage > 80%", s.get("cve_with_epss", 0) > n * 0.8)
    check("exploit links", s.get("cve_with_exploit", 0) > 10_000)
    check("nuclei", s.get("nuclei", 0) > 5_000)
    check("msf", s.get("msf", 0) > 1_000)
    check("models", s.get("model", 0) > 1_000)
    check("attack multi-domain", s.get("attack", 0) > 700)

    rows = query.search(con, "log4j jndi", limit=5)
    check("search finds log4shell", any(r["id"] == "CVE-2021-44228" for r in rows))

    d = query.get_cve(con, "CVE-2021-44228")
    check("cve kev", d["kev"] == 1)
    check("cve cvss", d["cvss"] == 10.0)
    check("cve epss", (d["epss"] or 0) > 0.9)
    check("cve exploits", len(d["exploits"]) > 0, len(d["exploits"]))
    check("cve nuclei", len(d["nuclei"]) > 0, len(d["nuclei"]))
    check("cve cpe ranges", len(d["affects"]) > 0, len(d["affects"]))

    hits = query.products(con, "nginx", version="1.18.0", limit=5)
    check("version-aware product match", len(hits) > 0, len(hits))
    old = query.products(con, "nginx", version="99.99.99", limit=5)
    check("version filter excludes non-matches", len(old) < len(query.products(con, "nginx", limit=50)))

    check("kev listing", len(query.kev_list(con, limit=3)) == 3)
    check("exploit search", len(query.exploit_search(con, "log4j", 3)) > 0)
    check("nuclei search", len(query.nuclei_search(con, "log4j", 3)) > 0)
    check("msf search", len(query.msf_search(con, "ms17", 3)) > 0)
    check("models", len(query.models_list(con, "claude", None, 3)) == 3)
    check("attack", len(query.attack_lookup(con, "T1059", 1)) == 1)
    check("cwe", query.cwe_get(con, "79")["id"] == "CWE-79")
    check("sql", len(query.sql_readonly(con, "SELECT id FROM cve LIMIT 3", 3)) == 3)

    # schema v3 surfaces
    cna = con.execute("SELECT count(*) FROM cve_cna").fetchone()[0]
    check("cna records", cna > 100_000, f"{cna:,}")
    pocs = con.execute("SELECT count(*) FROM poc").fetchone()[0]
    check("public pocs", pocs > 1_000, f"{pocs:,}")
    check("poc-linked cves",
          con.execute("SELECT count(*) FROM cve_meta WHERE has_poc=1").fetchone()[0] > 1_000)
    check("source provenance",
          con.execute("SELECT count(*) FROM source_state").fetchone()[0] > 0)
    check("poc search", len(query.poc_search(con, "log4j", limit=3)) > 0)
    check("no nvd clobber",
          con.execute("SELECT count(*) FROM cve WHERE description IS NULL OR description=''")
          .fetchone()[0] == 0)
    con.close()

    # MCP handshake
    msgs = ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
            '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
            '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":'
            '{"name":"cb_stats","arguments":{}}}\n')
    res = subprocess.run([sys.executable, str(ROOT / "mcp/server.py")], input=msgs,
                         capture_output=True, text=True, timeout=120)
    out = {json.loads(ln)["id"]: json.loads(ln) for ln in res.stdout.splitlines() if ln.strip()}
    check("mcp initialize", out.get(1, {}).get("result", {}).get("serverInfo", {}).get("name") == "crowbar")
    tools = {t["name"] for t in out.get(2, {}).get("result", {}).get("tools", [])}
    check("mcp tools", len(tools) >= 18 and {"cb_os", "cb_advisory", "cb_code",
                                              "cb_binary", "cb_debian", "cb_tables",
                                              "cb_poc", "cb_sources"} <= tools,
          f"{len(tools)} tools")
    check("mcp stats", out.get(3, {}).get("result", {}).get("isError") is False)

    # link / unlink in a scratch project
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(HV), "link", tmp], capture_output=True, check=True)
        link = pathlib.Path(tmp) / ".crowbar"
        from crowbar.cli import _find_home
        check("link creates symlink",
              link.is_symlink() and link.resolve() == _find_home().resolve(),
              str(link.resolve()))
        r = subprocess.run([str(link / "bin" / "hv"), "search", "openssl", "--limit", "1", "--json"],
                           capture_output=True, text=True, timeout=60)
        check("linked cli works", r.returncode == 0 and json.loads(r.stdout or "[]"))
        subprocess.run([sys.executable, str(HV), "unlink", tmp], capture_output=True, check=True)
        check("unlink removes symlink", not link.exists() and not link.is_symlink())

    failed = [r for r in results if not r[0]]
    for ok, name, detail in results:
        print(f"{'ok  ' if ok else 'FAIL'} {name:32s} {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
