"""Corpus tests: exercise the real index, generated from its own rows.

Skipped automatically when `index/crowbar.db` is absent (CI runs the fixture suite).
Target: >1000 independent cases covering every table and surface.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from crowbar import datasets, db, paths, query  # noqa: E402
from tests import support  # noqa: E402

CORPUS = support.corpus_available()
CON = support.connect() if CORPUS else None
S: dict[str, list] = {}

# The index's tier decides which sources it carries; a test for a missing source skips.
TIER = datasets.load_manifest().get("tier") if CORPUS else None
HAVE = datasets.tier_groups(TIER) if TIER in datasets.TIER_NAMES[:-1] else None   # None: every source
full_nvd = unittest.skipIf(TIER == "lite", "tier lite keeps only the last 2 NVD years")


def needs(*groups: str):
    missing = sorted(set(groups) - HAVE) if HAVE is not None else []
    return unittest.skipIf(bool(missing), f"tier {TIER} has no {', '.join(missing)}")


def _sample(table: str, col: str, n: int, where: str = "", order: str | None = None) -> list:
    total = CON.execute(f"SELECT count(*) FROM {table} {where}").fetchone()[0]
    if not total:
        return []
    step = max(1, total // n)
    out, off = [], 0
    while len(out) < n and off < total:
        row = CON.execute(
            f"SELECT {col} FROM {table} {where} ORDER BY {order or col} "
            f"LIMIT 1 OFFSET ?", (off,)).fetchone()
        if row and row[0] not in out:
            out.append(row[0])
        off += step
    return out


def _load_samples() -> None:
    global CON
    CON = support.connect()
    S["cves"] = _sample("cve", "id", 400)
    S["products"] = []
    for cid in S["cves"][:400]:
        r = CON.execute("SELECT product FROM cve_product WHERE cve_id=? LIMIT 1",
                        (cid,)).fetchone()
        if r and r[0] and r[0] not in S["products"]:
            S["products"].append(r[0])
        if len(S["products"]) >= 60:
            break
    S["version_rows"] = [dict(r) for r in CON.execute(
        "SELECT * FROM cpe_match WHERE (v_start_incl != '' OR v_end_incl != '' "
        "OR v_start_excl != '' OR v_end_excl != '') LIMIT 200")]
    S["searches"] = []
    for cid in S["cves"]:
        r = CON.execute("SELECT description FROM cve WHERE id=?", (cid,)).fetchone()
        if not r or not r[0]:
            continue
        toks = sorted(set(re.findall(r"[A-Za-z]{6,}", r[0])), key=len, reverse=True)
        if toks and toks[0].lower() not in S["searches"]:
            S["searches"].append(toks[0].lower())
        if len(S["searches"]) >= 80:
            break
    S["exploits"] = []
    for eid in _sample("exploit", "id", 80):
        r = CON.execute("SELECT description FROM exploit WHERE id=?", (eid,)).fetchone()
        toks = re.findall(r"[A-Za-z]{4,}", (r[0] if r else "") or "")
        if toks:
            S["exploits"].append((eid, max(toks, key=len).lower()))
    S["nuclei"] = _sample("nuclei", "id", 60)
    S["msf"] = _sample("msf", "name", 60)
    S["cwe"] = _sample("cwe", "id", 60)
    S["capec"] = _sample("capec", "id", 60)
    S["attack"] = _sample("attack", "id", 60, order="id")
    S["models"] = _sample("model", "id", 60, order="provider, id")
    S["advisories"] = _sample("advisory", "package", 80, "WHERE package != ''")
    S["ranges"] = _sample("package_range", "advisory_id", 80)
    S["debian"] = _sample("debian", "package", 60)
    S["os"] = _sample("os_advisory", "cve", 80, "WHERE cve != ''")
    S["toolkit"] = _sample("toolkit", "name", 60)
    S["kev"] = _sample("kev", "vendor", 60)


def tearDownModule():
    if CON is not None:
        CON.close()



if CORPUS:
    _load_samples()


def add(cls, suffix: str, fn) -> None:
    def test(self, _fn=fn):
        _fn(self)
    test.__name__ = f"test_{suffix}"
    setattr(cls, test.__name__, test)


# ------------------------------------------------------------------ CVEs
@unittest.skipUnless(CORPUS, 'no corpus index')
class TestCorpusCVE(unittest.TestCase):
    pass


def _cve(cid):
    def run(self):
        c = query.get_cve(CON, cid)
        self.assertEqual(c["id"], cid)
        self.assertIn("description", c)
        self.assertIsInstance(c["cwe"], list)
        self.assertIsInstance(c["affects"], list)
    return run


for i, cid in enumerate(S.get("cves", [])[:150]):
    add(TestCorpusCVE, f"cve_{i:03d}", _cve(cid))


def _search(term):
    def run(self):
        rows = query.search(CON, term, limit=10)
        self.assertIsInstance(rows, list)
        self.assertTrue(rows, f"no hit for sampled term {term!r}")
        self.assertTrue(all("id" in r for r in rows))
    return run


for i, term in enumerate(S.get("searches", [])[:80]):
    add(TestCorpusCVE, f"search_{i:03d}", _search(term))


# ------------------------------------------------------------------ products
@unittest.skipUnless(CORPUS, 'no corpus index')
class TestCorpusProducts(unittest.TestCase):
    pass


def _product(name):
    def run(self):
        rows = query.products(CON, name, limit=5)
        self.assertIsInstance(rows, list)
        # products() returns CVE rows, keyed by CVE id, selected via a
        # product/vendor LIKE on cpe_match - so every returned CVE must have
        # such a match. (Empty is allowed: the sample name comes from
        # cve_product, which isn't always mirrored in cpe_match.)
        q = f"%{name.lower()}%"
        for r in rows:
            hit = CON.execute(
                "SELECT 1 FROM cpe_match WHERE cve_id=? AND (product LIKE ? OR vendor LIKE ?) "
                "LIMIT 1", (r["id"], q, q)).fetchone()
            self.assertIsNotNone(
                hit, f"{r['id']} returned for product {name!r} with no matching CPE")
    return run


for i, name in enumerate(S.get("products", [])[:40]):
    add(TestCorpusProducts, f"product_{i:03d}", _product(name))


def _version_triplet(row):
    def run(self):
        if row["v_start_incl"]:
            self.assertTrue(query.version_affected(row, row["v_start_incl"]))
        if row["v_end_incl"]:
            self.assertTrue(query.version_affected(row, row["v_end_incl"]))
        if row["v_end_excl"]:
            self.assertFalse(query.version_affected(row, row["v_end_excl"]))
        if row["v_start_excl"]:
            self.assertFalse(query.version_affected(row, row["v_start_excl"]))
        self.assertIn(":", query.range_label(row))
    return run


for i, row in enumerate(S.get("version_rows", [])[:120]):
    if any(row[k] for k in ("v_start_incl", "v_end_incl", "v_start_excl", "v_end_excl")):
        add(TestCorpusProducts, f"bounds_{i:03d}", _version_triplet(row))


# ------------------------------------------------------------------ intel
@unittest.skipUnless(CORPUS, 'no corpus index')
class TestCorpusIntel(unittest.TestCase):
    pass


def _exploit(eid, term):
    def run(self):
        rows = query.exploit_search(CON, term, limit=20)
        self.assertIsInstance(rows, list)
        self.assertTrue(rows, f"no exploit results for {term!r}")
        # `term` is a real token from an exploit description, so every FTS hit
        # must be on-topic. Match on the 4-char stem to tolerate porter
        # stemming (the exact `eid` is often ranked out of the top 20).
        stem = term[:4]
        for r in rows:
            blob = " ".join(str(r.get(k) or "")
                            for k in ("description", "tags", "codes", "file")).lower()
            self.assertIn(stem, blob, f"exploit {r.get('id')} unrelated to {term!r}")
    return run


for i, (eid, term) in enumerate(S.get("exploits", [])[:60]):
    add(TestCorpusIntel, f"exploit_{i:03d}", _exploit(eid, term))


def _nuclei(tid):
    def run(self):
        rows = query.nuclei_search(CON, tid, limit=10)
        self.assertTrue(rows)
        self.assertTrue(any(tid in r["id"] for r in rows))
    return run


for i, tid in enumerate(S.get("nuclei", [])[:50]):
    add(TestCorpusIntel, f"nuclei_{i:03d}", _nuclei(tid))


def _msf(name):
    def run(self):
        rows = query.msf_search(CON, name, limit=20)
        self.assertTrue(rows)
        self.assertTrue(any(r["name"].lower() == name.lower() for r in rows))
    return run


for i, name in enumerate(S.get("msf", [])[:50]):
    add(TestCorpusIntel, f"msf_{i:03d}", _msf(name))


def _cwe(cid):
    def run(self):
        d = query.cwe_get(CON, cid)
        self.assertEqual(d["id"], cid)
    return run


for i, cid in enumerate(S.get("cwe", [])[:50]):
    add(TestCorpusIntel, f"cwe_{i:03d}", _cwe(cid))


def _capec(cid):
    def run(self):
        rows = query.capec_search(CON, cid)
        self.assertTrue(rows)
        self.assertTrue(any(r["id"] == cid for r in rows))
    return run


for i, cid in enumerate(S.get("capec", [])[:50]):
    add(TestCorpusIntel, f"capec_{i:03d}", _capec(cid))


def _attack(tid):
    def run(self):
        rows = query.attack_lookup(CON, tid)
        self.assertTrue(rows)
        self.assertTrue(any(r["id"] == tid for r in rows))
    return run


for i, tid in enumerate(S.get("attack", [])[:50]):
    add(TestCorpusIntel, f"attack_{i:03d}", _attack(tid))


def _model(mid):
    def run(self):
        rows = query.models_list(CON, mid, limit=10)
        self.assertTrue(rows)
        self.assertTrue(any(r["id"] == mid for r in rows))
    return run


for i, mid in enumerate(S.get("models", [])[:50]):
    add(TestCorpusIntel, f"model_{i:03d}", _model(mid))


def _kev(vendor):
    def run(self):
        rows = query.kev_list(CON, vendor, limit=10)
        self.assertTrue(rows)
    return run


for i, vendor in enumerate(S.get("kev", [])[:50]):
    add(TestCorpusIntel, f"kev_{i:03d}", _kev(vendor))


# ------------------------------------------------------------------ bulk
@unittest.skipUnless(CORPUS, 'no corpus index')
class TestCorpusBulk(unittest.TestCase):
    pass


def _advisory(pkg):
    def run(self):
        rows = query.advisory_search(CON, package=pkg)
        self.assertTrue(rows)
        self.assertTrue(all(r["package"] == pkg.lower() for r in rows))
        self.assertTrue(any(r.get("ranges") for r in rows))
    return run


for i, pkg in enumerate(S.get("advisories", [])[:60]):
    add(TestCorpusBulk, f"advisory_{i:03d}", _advisory(pkg))


def _range2(aid):
    def run(self):
        rows = CON.execute(
            "SELECT ecosystem, package, introduced, fixed, last_affected "
            "FROM package_range WHERE advisory_id=? LIMIT 5", (aid,)).fetchall()
        self.assertTrue(rows)
    return run


for i, aid in enumerate(S.get("ranges", [])[:60]):
    add(TestCorpusBulk, f"range_{i:03d}", _range2(aid))


def _debian(pkg):
    def run(self):
        rows = query.debian_lookup(CON, pkg)
        self.assertTrue(rows)
        self.assertTrue(all("fixed" in r for r in rows))
    return run


for i, pkg in enumerate(S.get("debian", [])[:50]):
    add(TestCorpusBulk, f"debian_{i:03d}", _debian(pkg))


def _os(cve):
    def run(self):
        rows = query.os_search(CON, cve)
        self.assertTrue(rows)
        self.assertTrue(all(r["cve"] == cve for r in rows if r["cve"]))
    return run


for i, cve in enumerate(S.get("os", [])[:60]):
    add(TestCorpusBulk, f"os_{i:03d}", _os(cve))


def _toolkit(name):
    def run(self):
        rows = query.toolkit_search(CON, name, limit=10)
        self.assertTrue(rows)
        self.assertTrue(any(r["name"].lower() == name.lower() for r in rows))
    return run


for i, name in enumerate(S.get("toolkit", [])[:60]):
    add(TestCorpusBulk, f"toolkit_{i:03d}", _toolkit(name))


CODE_TERMS = ["http", "socket", "buffer", "printf", "payload", "admin",
              "password", "shell", "system", "exec", "connect", "request"]


def _code(term):
    def run(self):
        rows = query.code_search(CON, term, limit=10)
        self.assertTrue(rows)
        self.assertTrue(all(r["path"] for r in rows))
    return run


for i, term in enumerate(CODE_TERMS):
    add(TestCorpusBulk, f"code_{i:03d}", needs("exploitdb")(_code(term)))


# ------------------------------------------------------------------ invariants
@unittest.skipUnless(CORPUS, 'no corpus index')
class TestCorpusIntegrity(unittest.TestCase):
    @full_nvd
    def test_cve_count(self):
        self.assertGreaterEqual(db.counts(CON)["cve"], 400_000)

    @full_nvd
    def test_cpe_ranges(self):
        self.assertGreaterEqual(db.counts(CON)["cpe_match"], 2_000_000)

    @full_nvd
    def test_kev_join(self):
        missing = CON.execute(
            "SELECT count(*) FROM kev k LEFT JOIN cve c ON c.id=k.cve WHERE c.id IS NULL"
        ).fetchone()[0]
        self.assertEqual(missing, 0)

    def test_no_duplicate_cves(self):
        n = CON.execute("SELECT count(*) - count(DISTINCT id) FROM cve").fetchone()[0]
        self.assertEqual(n, 0)

    def test_cve_id_shape(self):
        bad = CON.execute(
            "SELECT count(*) FROM cve WHERE id NOT GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9]*'"
        ).fetchone()[0]
        self.assertEqual(bad, 0)

    def test_year_matches_published(self):
        bad = CON.execute(
            "SELECT count(*) FROM cve WHERE published != '' "
            "AND year != cast(substr(published,1,4) as integer)").fetchone()[0]
        self.assertEqual(bad, 0)

    def test_cwe_shape(self):
        bad = CON.execute(
            "SELECT count(*) FROM cve_cwe WHERE cwe NOT GLOB 'CWE-[0-9]*'").fetchone()[0]
        self.assertEqual(bad, 0)

    def test_fts_cve_sync(self):
        a = CON.execute("SELECT count(*) FROM cve").fetchone()[0]
        b = CON.execute("SELECT count(*) FROM cve_fts").fetchone()[0]
        self.assertEqual(a, b)

    def test_fts_exploit_sync(self):
        a = CON.execute("SELECT count(*) FROM exploit").fetchone()[0]
        b = CON.execute("SELECT count(*) FROM exploit_fts").fetchone()[0]
        self.assertEqual(a, b)

    def test_fts_nuclei_sync(self):
        a = CON.execute("SELECT count(*) FROM nuclei").fetchone()[0]
        b = CON.execute("SELECT count(*) FROM nuclei_fts").fetchone()[0]
        self.assertEqual(a, b)

    @needs("osv")
    def test_advisory_present(self):
        self.assertGreater(db.counts(CON)["advisory"], 100_000)

    @needs("osv")
    def test_package_ranges_present(self):
        self.assertGreater(db.counts(CON)["package_range"], 100_000)

    @needs("vendor")
    def test_os_windows(self):
        self.assertGreater(CON.execute(
            "SELECT count(*) FROM os_advisory WHERE platform='windows'").fetchone()[0], 10_000)

    @needs("vendor")
    def test_os_ios(self):
        self.assertGreater(CON.execute(
            "SELECT count(*) FROM os_advisory WHERE platform='ios'").fetchone()[0], 100)

    @needs("vendor")
    def test_os_macos(self):
        self.assertGreater(CON.execute(
            "SELECT count(*) FROM os_advisory WHERE platform='macos'").fetchone()[0], 100)

    @needs("debian")
    def test_debian_rows(self):
        self.assertGreater(db.counts(CON)["debian"], 10_000)

    @needs("toolkit")
    def test_toolkit_rows(self):
        self.assertGreater(db.counts(CON)["toolkit"], 500)

    @needs("exploitdb")
    def test_exploit_code_rows(self):
        self.assertGreater(CON.execute(
            "SELECT count(*) FROM exploit_code_fts").fetchone()[0], 10_000)

    @needs("metasploit")
    def test_msf_cves_linked(self):
        self.assertGreater(CON.execute("SELECT count(*) FROM cve_msf").fetchone()[0], 100)

    def test_msf_cve_flag_consistent(self):
        bad = CON.execute(
            "SELECT count(*) FROM cve WHERE has_msf=1 AND id NOT IN "
            "(SELECT cve_id FROM cve_msf)").fetchone()[0]
        self.assertEqual(bad, 0)

    def test_exploit_flag_consistent(self):
        bad = CON.execute(
            "SELECT count(*) FROM cve WHERE has_exploit=1 AND id NOT IN "
            "(SELECT cve_id FROM cve_exploit)").fetchone()[0]
        self.assertEqual(bad, 0)

    def test_nuclei_flag_consistent(self):
        bad = CON.execute(
            "SELECT count(*) FROM cve WHERE has_nuclei=1 AND id NOT IN "
            "(SELECT cve_id FROM cve_nuclei)").fetchone()[0]
        self.assertEqual(bad, 0)

    def test_kev_flag_consistent(self):
        bad = CON.execute(
            "SELECT count(*) FROM cve WHERE kev=1 AND id NOT IN (SELECT cve FROM kev)"
        ).fetchone()[0]
        self.assertEqual(bad, 0)

    def test_ssvc_values(self):
        vals = {r[0] for r in CON.execute("SELECT DISTINCT exploitation FROM ssvc")}
        self.assertTrue(vals <= {"none", "poc", "active", ""}, vals)

    def test_cvss_range(self):
        bad = CON.execute(
            "SELECT count(*) FROM cve WHERE cvss IS NOT NULL AND (cvss < 0 OR cvss > 10)"
        ).fetchone()[0]
        self.assertEqual(bad, 0)

    def test_epss_range(self):
        bad = CON.execute(
            "SELECT count(*) FROM cve WHERE epss IS NOT NULL AND (epss < 0 OR epss > 1)"
        ).fetchone()[0]
        self.assertEqual(bad, 0)

    def test_severities(self):
        vals = {r[0] for r in CON.execute("SELECT DISTINCT severity FROM cve")}
        self.assertTrue(vals <= {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", ""}, vals)

    def test_descriptions_nonempty(self):
        n = CON.execute(
            "SELECT count(*) FROM cve WHERE status != 'Rejected' AND description = ''"
        ).fetchone()[0]
        self.assertEqual(n, 0)

    def test_manifest_paths_exist(self):
        m = datasets.load_manifest().get("datasets", {})
        self.assertTrue(m)
        missing = [name for name, v in m.items()
                   if v.get("path") and not (paths.DATA / v["path"]).exists()]
        self.assertEqual(missing, [])

    def test_state_schema(self):
        self.assertEqual(paths.state().get("schema"), paths.SCHEMA_VERSION)

    def test_stats_payload(self):
        s = db.counts(CON)
        source = {"cve": "nvd", "kev": "kev", "exploit": "exploitdb", "nuclei": "nuclei",
                  "msf": "metasploit", "attack": "attack", "cwe": "cwe", "capec": "capec",
                  "model": "models", "advisory": "osv", "os_advisory": "vendor", "toolkit": "toolkit"}
        for t, group in source.items():
            self.assertIn(t, s)
            if HAVE is None or group in HAVE:
                self.assertGreater(s[t], 0, t)


# ------------------------------------------------------------------ CLI
@unittest.skipUnless(CORPUS, 'no corpus index')
class TestCorpusCLI(unittest.TestCase):
    def json(self, *args):
        return support.run_cb_json(*args)

    @full_nvd
    def test_stats(self):
        self.assertGreater(self.json("stats")["cve"], 400_000)

    def test_cve(self):
        cid = S["cves"][0]
        self.assertEqual(self.json("cve", cid)["id"], cid)

    def test_search(self):
        self.assertTrue(self.json("search", "remote code execution", "--limit", "5"))

    def test_product(self):
        self.assertIsInstance(self.json("product", S["products"][0], "--limit", "3"), list)

    def test_kev(self):
        self.assertTrue(self.json("kev", "--limit", "3"))

    @needs("exploitdb")
    def test_exploit(self):
        self.assertTrue(self.json("exploit", "remote", "--limit", "3"))

    @needs("nuclei")
    def test_nuclei(self):
        self.assertTrue(self.json("nuclei", "cve", "--limit", "3"))

    @needs("metasploit")
    def test_msf(self):
        self.assertTrue(self.json("msf", "windows", "--limit", "3"))

    @needs("models")
    def test_models(self):
        self.assertTrue(self.json("models", "--limit", "3"))

    @needs("attack")
    def test_attack(self):
        self.assertTrue(self.json("attack", "T1059"))

    def test_cwe(self):
        self.assertTrue(self.json("cwe", "79"))

    @needs("capec")
    def test_capec(self):
        self.assertTrue(self.json("capec", "injection", "--limit", "3"))

    @needs("vendor")
    def test_os(self):
        self.assertTrue(self.json("os", "--platform", "windows", "--limit", "3"))

    @needs("osv")
    def test_advisory(self):
        self.assertTrue(self.json("advisory", f"--package={S['advisories'][0]}", "--limit", "3"))

    @needs("exploitdb")
    def test_code(self):
        self.assertTrue(self.json("code", "http", "--limit", "3"))

    @needs("toolkit")
    def test_bin(self):
        self.assertTrue(self.json("bin", "curl", "--limit", "3"))

    @needs("debian")
    def test_debian(self):
        self.assertTrue(self.json("debian", S["debian"][0]))

    def test_map(self):
        rows = self.json("map")
        self.assertGreaterEqual(len(rows), 40)
        self.assertTrue(all(r["tables"] for r in rows))

    @full_nvd
    def test_sql(self):
        rows = self.json("sql", "select count(*) as n from cve")
        self.assertGreater(rows[0]["n"], 400_000)

    def test_where(self):
        self.assertTrue(self.json("where")["db"].endswith("crowbar.db"))

    def test_doctor(self):
        p = support.run_hv("doctor")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_unknown_cve_exits_nonzero(self):
        p = support.run_hv("cve", "CVE-1999-99999")
        self.assertNotEqual(p.returncode, 0)

    def test_bad_sql_exits_nonzero(self):
        p = support.run_hv("sql", "delete from cve")
        self.assertNotEqual(p.returncode, 0)


# ------------------------------------------------------------------ MCP
@unittest.skipUnless(CORPUS, 'no corpus index')
class TestCorpusMCP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = subprocess.Popen(
            [sys.executable, str(support.ROOT / "mcp" / "server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=dict(os.environ))
        cls.n = 0
        cls.request("initialize", {"protocolVersion": "2025-06-18"})

    @classmethod
    def tearDownClass(cls):
        cls.proc.stdin.close()
        cls.proc.wait(timeout=10)

    @classmethod
    def request(cls, method, params=None):
        cls.n += 1
        cls.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": cls.n, "method": method, "params": params or {}}) + "\n")
        cls.proc.stdin.flush()
        return json.loads(cls.proc.stdout.readline())

    def call(self, name, args=None):
        r = self.request("tools/call", {"name": name, "arguments": args or {}})
        self.assertFalse(r["result"].get("isError"), r)
        return json.loads(r["result"]["content"][0]["text"])

    def test_tools(self):
        r = self.request("tools/list")
        self.assertGreaterEqual(len(r["result"]["tools"]), 15)

    @full_nvd
    def test_stats(self):
        self.assertGreater(self.call("cb_stats")["cve"], 400_000)

    def test_search(self):
        self.assertTrue(self.call("cb_search", {"query": "remote code execution"}))

    def test_cve(self):
        self.assertEqual(self.call("cb_cve", {"id": S["cves"][0]})["id"], S["cves"][0])

    def test_product(self):
        self.assertIsInstance(self.call("cb_product", {"name": S["products"][0]}), list)

    def test_kev(self):
        self.assertTrue(self.call("cb_kev", {"limit": 3}))

    @needs("exploitdb")
    def test_exploit(self):
        self.assertTrue(self.call("cb_exploit", {"query": "remote", "limit": 3}))

    @needs("nuclei")
    def test_nuclei(self):
        self.assertTrue(self.call("cb_nuclei", {"query": "cve", "limit": 3}))

    @needs("metasploit")
    def test_msf(self):
        self.assertTrue(self.call("cb_msf", {"query": "windows", "limit": 3}))

    @needs("models")
    def test_models(self):
        self.assertTrue(self.call("cb_models", {"limit": 3}))

    @needs("attack")
    def test_attack(self):
        self.assertTrue(self.call("cb_attack", {"query": "T1059"}))

    def test_cwe(self):
        self.assertTrue(self.call("cb_cwe", {"query": "79"}))

    @needs("vendor")
    def test_os(self):
        self.assertTrue(self.call("cb_os", {"platform": "windows", "limit": 3}))

    @needs("osv")
    def test_advisory(self):
        self.assertTrue(self.call("cb_advisory", {"package": S["advisories"][0]}))

    @needs("exploitdb")
    def test_code(self):
        self.assertTrue(self.call("cb_code", {"query": "http", "limit": 3}))

    @needs("toolkit")
    def test_binary(self):
        self.assertTrue(self.call("cb_binary", {"query": "curl", "limit": 3}))

    @needs("debian")
    def test_debian(self):
        self.assertTrue(self.call("cb_debian", {"package": S["debian"][0]}))

    def test_tables(self):
        self.assertIn("cve", self.call("cb_tables")["tables"])

    @full_nvd
    def test_sql(self):
        self.assertGreater(self.call("cb_sql", {"query": "select count(*) as n from cve"})[0]["n"],
                           400_000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
