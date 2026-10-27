"""Fast tests: fixture DB, every table, query, CLI and MCP surface.

No corpus or network required; CI runs this file.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from crowbar import catalog, datasets, db, paths, query  # noqa: E402
from tests import support  # noqa: E402

HOME: pathlib.Path
DB: pathlib.Path
CON: sqlite3.Connection


def setUpModule():
    global HOME, DB, CON
    HOME, DB = support.make_fixture_home()
    CON = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    CON.row_factory = sqlite3.Row


def tearDownModule():
    CON.close()


class TestSchema(unittest.TestCase):
    def test_schema_tables(self):
        names = {r[0] for r in CON.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        required = {"cve", "cve_cwe", "cve_product", "cpe_match", "cve_ref",
                    "cve_exploit", "cve_nuclei", "cve_msf", "kev", "exploit",
                    "shellcode", "nuclei", "msf", "attack", "cwe", "capec",
                    "model", "ssvc", "advisory", "package_range", "debian",
                    "os_advisory", "toolkit", "exploit_code_fts", "toolkit_fts",
                    "cve_fts", "exploit_fts", "nuclei_fts", "model_fts", "meta",
                    "cve_cna", "cve_meta", "poc", "poc_orphan", "cve_alias",
                    "source_state"}
        self.assertEqual(required - names, set())

    def test_fts_counts_match_base_tables(self):
        pairs = [("cve", "cve_fts"), ("exploit", "exploit_fts"),
                 ("nuclei", "nuclei_fts")]
        for base, fts in pairs:
            with self.subTest(base=base):
                a = CON.execute(f"SELECT count(*) FROM {base}").fetchone()[0]
                b = CON.execute(f"SELECT count(*) FROM {fts}").fetchone()[0]
                self.assertEqual(a, b)

    def test_catalog_tables_exist(self):
        names = {r[0] for r in CON.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        missing = [t for t in catalog.TABLES if t not in names]
        self.assertEqual(missing, [])


class TestCatalog(unittest.TestCase):
    def test_every_registry_group_has_a_map(self):
        for d in datasets.registry(with_extra=True, with_bulk=True):
            with self.subTest(dataset=d.name):
                g = catalog.describe(d.name)
                self.assertTrue(g["tables"], f"{d.name} has no mapped tables")
                self.assertTrue(g["path"])

    def test_group_of(self):
        cases = {
            "nvd-2024": "nvd", "osv-npm": "osv", "exploitdb-full": "exploitdb",
            "attack-ics": "attack", "metasploit": "metasploit", "msf-source": "metasploit",
            "gtfobins": "toolkit", "lolbas": "toolkit", "payloads": "toolkit",
            "debian-tracker": "debian", "msrc": "vendor", "apple": "vendor",
            "kev": "kev", "epss": "epss", "cwe": "cwe", "capec": "capec",
        }
        for name, group in cases.items():
            with self.subTest(name=name):
                self.assertEqual(catalog.group_of(name), group)
                self.assertIn(group, catalog.GROUPS)

    def test_registry_names_unique(self):
        names = [d.name for d in datasets.registry(with_extra=True, with_bulk=True)]
        self.assertEqual(len(names), len(set(names)))

    def test_tier_values(self):
        for d in datasets.registry(with_extra=True, with_bulk=True):
            with self.subTest(dataset=d.name):
                self.assertIn(d.tier, ("core", "extra", "bulk"))

    def test_plan_core_only(self):
        names = {d.name for d in datasets.plan()}
        self.assertIn("kev", names)
        self.assertIn("msrc", names)          # vendor feeds are core
        self.assertNotIn("osv-npm", names)    # bulk stays opt-in
        self.assertNotIn("attack-ics", names)

    def test_plan_bulk(self):
        names = {d.name for d in datasets.plan(with_bulk=True)}
        self.assertIn("osv-npm", names)
        self.assertIn("exploitdb-full", names)
        self.assertIn("attack-ics", names)


class TestVersioning(unittest.TestCase):
    def check(self, version, start=None, end=None, start_excl=None, end_excl=None):
        row = {"version": "*", "v_start_incl": start, "v_start_excl": start_excl,
               "v_end_incl": end, "v_end_excl": end_excl}
        return query.version_affected(row, version)

    def test_bounds(self):
        cases = [
            ("1.18.0", True, dict(start="0.6.18", end="1.20.1")),
            ("1.21.0", False, dict(start="0.6.18", end="1.20.1")),
            ("0.6.17", False, dict(start="0.6.18", end="1.20.1")),
            ("1.20.1", True, dict(start="0.6.18", end="1.20.1")),
            ("9.8", False, dict(start="8.5", end_excl="9.8")),
            ("9.7p1", True, dict(start="8.5", end_excl="9.8")),
            ("8.5", False, dict(start_excl="8.5", end="9.8")),
            ("8.6", True, dict(start_excl="8.5", end="9.8")),
            ("2.15.0", True, dict(start="2.0", end="2.15.0")),
            ("2.0", True, dict(start="2.0", end="2.15.0")),
        ]
        for version, expected, bounds in cases:
            with self.subTest(version=version, bounds=bounds):
                self.assertEqual(self.check(version, **bounds), expected)

    def test_exact_version(self):
        row = {"version": "18.2", "v_start_incl": "", "v_start_excl": "",
               "v_end_incl": "", "v_end_excl": ""}
        self.assertTrue(query.version_affected(row, "18.2"))
        self.assertFalse(query.version_affected(row, "18.3"))

    def test_vkey_order(self):
        self.assertLess(query.vkey("1.2.3"), query.vkey("1.10.0"))
        self.assertLess(query.vkey("1.2.3"), query.vkey("1.2.3p1"))


class TestQuery(unittest.TestCase):
    def test_search_hit(self):
        rows = query.search(CON, "log4j")
        self.assertTrue(rows)
        self.assertEqual(rows[0]["id"], "CVE-2021-44228")

    def test_search_filters(self):
        self.assertTrue(all(r["kev"] == 1 for r in query.search(CON, "", kev=True)))
        self.assertTrue(all(r["severity"] == "HIGH" for r in query.search(CON, "", severity="HIGH")))
        self.assertTrue(all(r["year"] == 2021 for r in query.search(CON, "", year=2021)))
        self.assertTrue(all((r["epss"] or 0) >= 0.5 for r in query.search(CON, "", epss=0.5)))

    def test_search_fts_narrowing(self):
        # AND semantics: a term that does not occur returns no rows, not everything
        self.assertEqual(query.search(CON, "log4j zzzznotpresent"), [])

    def test_search_product_filter(self):
        rows = query.search(CON, "", product="nginx")
        self.assertEqual([r["id"] for r in rows], ["CVE-2023-1111"])

    def test_search_fts_with_filters(self):
        # filters apply after the FTS top-N subquery; "cve" matches every fixture row
        self.assertEqual({r["id"] for r in query.search(CON, "cve", kev=True)},
                         {"CVE-2021-44228", "CVE-2017-0144"})
        self.assertEqual([r["id"] for r in query.search(CON, "", cwe="cwe-787")], ["CVE-2023-1111"])
        self.assertEqual([r["id"] for r in query.search(CON, "cve", cwe="CWE-502")], ["CVE-2021-44228"])

    def test_get_cve_full(self):
        c = query.get_cve(CON, "2021-44228")
        self.assertEqual(c["id"], "CVE-2021-44228")
        for key in ("cwe", "products", "affects", "references", "exploits",
                    "nuclei", "metasploit", "ssvc", "os", "advisories", "debian",
                    "pocs", "poc_count", "cna", "aliases", "published_year", "cve_year"):
            self.assertIn(key, c)
        self.assertEqual(c["cwe"], ["CWE-502"])
        self.assertEqual(len(c["affects"]), 1)
        self.assertEqual(len(c["advisories"]), 1)
        self.assertEqual(c["poc_count"], 2)
        self.assertEqual(c["pocs"][0]["repo"], "example/log4shell")

    def test_search_poc_filter(self):
        rows = query.search(CON, "", poc=True)
        self.assertEqual({r["id"] for r in rows}, {"CVE-2021-44228", "CVE-2017-0144"})
        self.assertTrue(all(r["poc_count"] >= 1 for r in rows))

    def test_get_cve_missing(self):
        with self.assertRaises(KeyError):
            query.get_cve(CON, "CVE-1999-0000")

    def test_products_version_hit(self):
        rows = query.products(CON, "nginx", "1.18.0")
        self.assertEqual([r["id"] for r in rows], ["CVE-2023-1111"])
        self.assertIn("f5:nginx", rows[0]["matched"][0])

    def test_products_version_miss(self):
        self.assertEqual(query.products(CON, "nginx", "1.21.0"), [])

    def test_products_exact_version(self):
        self.assertTrue(query.products(CON, "iphone_os", "18.2"))
        self.assertEqual(query.products(CON, "iphone_os", "18.3"), [])

    def test_kev(self):
        rows = query.kev_list(CON, "log4j")
        self.assertEqual(rows[0]["cve"], "CVE-2021-44228")

    def test_exploit_search(self):
        rows = query.exploit_search(CON, "log4j")
        self.assertEqual(rows[0]["id"], "50592")

    def test_nuclei_search(self):
        rows = query.nuclei_search(CON, "log4j")
        self.assertEqual(rows[0]["id"], "CVE-2021-44228")

    def test_nuclei_domain_filter(self):
        rows = query.nuclei_search(CON, "cve", domain="network")
        self.assertEqual([r["id"] for r in rows], ["CVE-2024-2222"])

    def test_msf_search(self):
        rows = query.msf_search(CON, "log4")
        self.assertEqual(rows[0]["name"], "log4shell")
        self.assertIn("CVE-2021-44228", rows[0]["cves"])

    def test_models(self):
        rows = query.models_list(CON)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["id"], "gpt-test")  # cheaper first

    def test_attack(self):
        rows = query.attack_lookup(CON, "T1059")
        self.assertEqual(rows[0]["name"], "Command and Scripting Interpreter")

    def test_attack_domain(self):
        self.assertEqual(query.attack_lookup(CON, "T0800", domain="enterprise"), [])

    def test_cwe_by_id(self):
        self.assertEqual(query.cwe_get(CON, "502")["name"],
                         "Deserialization of Untrusted Data")
        self.assertEqual(query.cwe_get(CON, "CWE-787")["id"], "CWE-787")

    def test_cwe_search(self):
        self.assertTrue(query.cwe_get(CON, "buffer"))

    def test_capec(self):
        self.assertEqual(query.capec_search(CON, "SQL")[0]["id"], "CAPEC-66")

    def test_os_platform(self):
        rows = query.os_search(CON, platform="windows")
        self.assertEqual(rows[0]["impact"], "RCE")

    def test_os_impact_and_query(self):
        self.assertTrue(query.os_search(CON, "iOS", impact="RCE") == [])
        self.assertTrue(query.os_search(CON, "Windows"))

    def test_os_exploited_flag(self):
        self.assertEqual(query.os_search(CON, exploited=True), [])

    def test_advisory_package(self):
        rows = query.advisory_search(CON, package="log4js")
        self.assertEqual(rows[0]["id"], "GHSA-jfh8-c2jp-5v3q")
        self.assertEqual(rows[0]["ranges"][0]["fixed"], "2.15.0")

    def test_advisory_ecosystem(self):
        ids = [r["id"] for r in query.advisory_search(CON, ecosystem="PyPI")]
        self.assertEqual(ids, ["PYSEC-2023-1"])

    def test_code_search(self):
        rows = query.code_search(CON, "jndi")
        self.assertEqual(rows[0]["exploit_id"], "50592")
        self.assertIn("jndi", rows[0]["snippet"].lower())

    def test_toolkit_search(self):
        rows = query.toolkit_search(CON, "awk")
        self.assertEqual(rows[0]["name"], "awk")
        self.assertEqual(rows[0]["source"], "gtfobins")

    def test_toolkit_source_filter(self):
        self.assertEqual(query.toolkit_search(CON, "certutil", source="gtfobins"), [])
        self.assertTrue(query.toolkit_search(CON, "certutil", source="lolbas"))

    def test_debian(self):
        rows = query.debian_lookup(CON, "log4j")
        self.assertEqual(rows[0]["fixed"], "2.17.1-1")
        self.assertEqual(len(query.debian_lookup(CON, "log4j", "CVE-2021-44228")), 1)

    def test_sql_readonly_select(self):
        rows = query.sql_readonly(CON, "select id from cve order by id")
        self.assertEqual(len(rows), 5)

    def test_sql_readonly_limit(self):
        self.assertEqual(len(query.sql_readonly(CON, "select id from cve", 2)), 2)

    def test_sql_rejects_writes(self):
        for q in ("delete from cve", "insert into cve(id) values ('x')",
                  "update cve set kev=0", "drop table cve"):
            with self.subTest(q=q):
                with self.assertRaises(ValueError):
                    query.sql_readonly(CON, q)

    def test_db_counts(self):
        c = db.counts(CON)
        self.assertEqual(c["cve"], 5)
        self.assertEqual(c["kev"], 1)

    def test_cve_year_consistency(self):
        bad = CON.execute(
            "select id from cve where year != cast(substr(id,5,4) as integer)").fetchall()
        self.assertEqual(bad, [])


class TestCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parser = __import__("crowbar.cli", fromlist=["build_parser"]).build_parser()
        sub = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)][0]
        cls.commands = sorted(sub.choices)

    def test_help_all_commands(self):
        for cmd in self.commands:
            with self.subTest(cmd=cmd):
                p = support.run_hv(cmd, "--help", home=str(HOME))
                self.assertEqual(p.returncode, 0, p.stderr)

    def json(self, *args):
        return support.run_cb_json(*args, home=str(HOME))

    def test_cve(self):
        self.assertEqual(self.json("cve", "CVE-2021-44228")["id"], "CVE-2021-44228")

    def test_home_screen(self):
        p = support.run_hv(home=str(HOME))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("crowbar trending", p.stdout)

    def test_trending_new_bench(self):
        self.assertEqual(self.json("trending")[0]["id"], "CVE-2021-44228")
        self.assertIn("published", self.json("new", "--since", "2024-01-01"))
        self.assertTrue(all(r["median_ms"] is not None for r in self.json("bench", "--runs", "1")["results"]))

    def test_search(self):
        self.assertTrue(self.json("search", "log4j"))

    def test_product_version(self):
        rows = self.json("product", "nginx", "--version", "1.18.0")
        self.assertEqual(rows[0]["id"], "CVE-2023-1111")

    def test_kev(self):
        self.assertEqual(self.json("kev")[0]["cve"], "CVE-2021-44228")

    def test_exploit(self):
        self.assertTrue(self.json("exploit", "log4j"))

    def test_nuclei(self):
        self.assertTrue(self.json("nuclei", "log4j"))

    def test_msf(self):
        self.assertTrue(self.json("msf", "log4"))

    def test_models(self):
        self.assertEqual(len(self.json("models")), 2)

    def test_attack(self):
        self.assertEqual(self.json("attack", "T1059")[0]["id"], "T1059")

    def test_cwe(self):
        self.assertEqual(self.json("cwe", "502")["id"], "CWE-502")

    def test_capec(self):
        self.assertTrue(self.json("capec", "SQL"))

    def test_os(self):
        self.assertTrue(self.json("os", "--platform", "windows"))

    def test_advisory(self):
        self.assertTrue(self.json("advisory", "--package", "log4js"))

    def test_code(self):
        self.assertTrue(self.json("code", "jndi"))

    def test_bin(self):
        self.assertTrue(self.json("bin", "awk"))

    def test_debian(self):
        self.assertTrue(self.json("debian", "log4j"))

    def test_map(self):
        rows = self.json("map")
        self.assertGreaterEqual(len(rows), 40)
        self.assertTrue(all("tables" in r for r in rows))

    def test_stats(self):
        self.assertEqual(self.json("stats")["cve"], 5)

    def test_where(self):
        self.assertEqual(self.json("where")["db"], str(HOME / "index" / "crowbar.db"))

    def test_sql(self):
        rows = self.json("sql", "select count(*) as n from cve")
        self.assertEqual(rows[0]["n"], 5)

    def test_doctor(self):
        p = support.run_hv("doctor", home=str(HOME))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_text_output_runs(self):
        for cmd in (["cve", "CVE-2021-44228"], ["stats"], ["map"], ["os", "--platform", "ios"]):
            with self.subTest(cmd=cmd):
                p = support.run_hv(*cmd, home=str(HOME))
                self.assertEqual(p.returncode, 0, p.stderr)


class TestMCP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env = dict(os.environ, CROWBAR_HOME=str(HOME))
        cls.proc = subprocess.Popen(
            [sys.executable, str(support.ROOT / "mcp" / "server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env)
        cls.n = 0
        cls.init = cls.request("initialize", {"protocolVersion": "2025-06-18"})

    @classmethod
    def tearDownClass(cls):
        cls.proc.stdin.close()
        cls.proc.wait(timeout=10)

    @classmethod
    def request(cls, method, params=None):
        cls.n += 1
        msg = {"jsonrpc": "2.0", "id": cls.n, "method": method, "params": params or {}}
        cls.proc.stdin.write(json.dumps(msg) + "\n")
        cls.proc.stdin.flush()
        line = cls.proc.stdout.readline()
        return json.loads(line)

    def call(self, name, args=None):
        r = self.request("tools/call", {"name": name, "arguments": args or {}})
        self.assertFalse(r["result"].get("isError"), r)
        return json.loads(r["result"]["content"][0]["text"])

    def test_initialize(self):
        self.assertIn("serverInfo", self.init["result"])
        self.assertEqual(self.init["result"]["serverInfo"]["name"], "crowbar")

    def test_tools_list(self):
        r = self.request("tools/list")
        names = {t["name"] for t in r["result"]["tools"]}
        for expected in ("cb_search", "cb_cve", "cb_product", "cb_os", "cb_advisory",
                         "cb_code", "cb_binary", "cb_debian", "cb_tables", "cb_sql"):
            self.assertIn(expected, names)

    def test_bad_method(self):
        r = self.request("nope/nope")
        self.assertIn("error", r)

    def test_ping(self):
        self.assertEqual(self.request("ping")["result"], {})

    def test_search(self):
        self.assertTrue(self.call("cb_search", {"query": "log4j"}))

    def test_trending_and_new(self):
        self.assertEqual(self.call("cb_trending")[0]["id"], "CVE-2021-44228")
        self.assertEqual(self.call("cb_new", {"since": "2024-01-01"})["published"]["total"], 2)

    def test_cve(self):
        self.assertEqual(self.call("cb_cve", {"id": "CVE-2021-44228"})["id"],
                         "CVE-2021-44228")

    def test_product(self):
        rows = self.call("cb_product", {"name": "nginx", "version": "1.18.0"})
        self.assertEqual(rows[0]["id"], "CVE-2023-1111")

    def test_kev(self):
        self.assertTrue(self.call("cb_kev", {}))

    def test_exploit(self):
        self.assertTrue(self.call("cb_exploit", {"query": "log4j"}))

    def test_nuclei(self):
        self.assertTrue(self.call("cb_nuclei", {"query": "log4j"}))

    def test_msf(self):
        self.assertTrue(self.call("cb_msf", {"query": "log4"}))

    def test_models(self):
        self.assertEqual(len(self.call("cb_models", {})), 2)

    def test_attack(self):
        self.assertTrue(self.call("cb_attack", {"query": "T1059"}))

    def test_cwe(self):
        self.assertTrue(self.call("cb_cwe", {"query": "502"}))

    def test_os(self):
        self.assertTrue(self.call("cb_os", {"platform": "windows"}))

    def test_advisory(self):
        self.assertTrue(self.call("cb_advisory", {"package": "log4js"}))

    def test_code(self):
        self.assertTrue(self.call("cb_code", {"query": "jndi"}))

    def test_binary(self):
        self.assertTrue(self.call("cb_binary", {"query": "awk"}))

    def test_debian(self):
        self.assertTrue(self.call("cb_debian", {"package": "log4j"}))

    def test_poc(self):
        rows = self.call("cb_poc", {"cve": "CVE-2021-44228", "min_stars": 1})
        self.assertEqual([r["repo"] for r in rows], ["example/log4shell"])
        self.assertIsInstance(self.call("cb_poc", {"top": True}), list)

    def test_tables(self):
        out = self.call("cb_tables", {})
        self.assertIn("cve", out["tables"])
        self.assertIn("osv", out["datasets"])

    def test_sql(self):
        rows = self.call("cb_sql", {"query": "select count(*) as n from cve"})
        self.assertEqual(rows[0]["n"], 5)

    def test_missing_required_arg(self):
        # cb_cve requires `id`; omitting it is a clean -32602, not a crash.
        r = self.request("tools/call", {"name": "cb_cve", "arguments": {}})
        self.assertIn("error", r)
        self.assertEqual(r["error"]["code"], -32602)

    def test_limit_clamped_not_errored(self):
        # A negative limit is -1=unbounded in SQLite; it must be clamped to the
        # schema minimum, not passed through, and must not error.
        r = self.request("tools/call",
                         {"name": "cb_search", "arguments": {"query": "log4j", "limit": -1}})
        self.assertFalse(r["result"].get("isError"), r)



class TestResponseBudget(unittest.TestCase):
    """Phase 2: agent responses stay small and always valid JSON."""

    def test_get_cve_reports_array_totals(self):
        out = query.get_cve(CON, "CVE-2017-0144")
        for key in ("affects_total", "references_total", "products_total"):
            self.assertIn(key, out)
            self.assertIsInstance(out[key], int)
        # capped arrays never exceed the cap
        self.assertLessEqual(len(out["affects"]), query.CVE_ARRAY_CAP)

    def test_fit_response_valid_json_under_limit(self):
        from crowbar import mcp
        text, over = mcp.fit_response({"a": 1, "b": [1, 2, 3]})
        self.assertFalse(over)
        self.assertEqual(json.loads(text)["b"], [1, 2, 3])

    def test_fit_response_overflow_is_valid_json(self):
        from crowbar import mcp
        big = {"rows": ["x" * 1000 for _ in range(mcp.MAX_CHARS // 500)]}
        text, over = mcp.fit_response(big)
        self.assertTrue(over)
        parsed = json.loads(text)  # must not raise
        self.assertEqual(parsed["error"], "result_too_large")

class TestTiers(unittest.TestCase):
    """Phase 3: risk tiers are nested group-sets over plan()."""

    def test_tiers_are_supersets(self):
        names = {t: {d.name for d in datasets.tier_plan(t)} for t in datasets.TIER_NAMES}
        for a, b in zip(datasets.TIER_NAMES, datasets.TIER_NAMES[1:]):
            self.assertTrue(names[a] <= names[b], f"{a} must be a subset of {b}")

    def test_tier_membership(self):
        lite = {d.group for d in datasets.tier_plan("lite")}
        heavy = {d.group for d in datasets.tier_plan("heavy")}
        self.assertIn("kev", lite)
        self.assertNotIn("exploitdb", lite)      # lite stays small
        self.assertIn("exploitdb", heavy)        # heavy adds exploit data
        self.assertIn("vendor", {d.group for d in datasets.tier_plan("extreme")})

    def test_unknown_tier_rejected(self):
        with self.assertRaises(ValueError):
            datasets.tier_plan("ultra")


class TestFreshness(unittest.TestCase):
    """index_status() ages the index from its meta rows; refresh_in_background()
    throttles itself and never starts while another update holds the lock."""

    def setUp(self):
        import tempfile
        from unittest import mock
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="cb-fresh-"))
        self.patches = [mock.patch.object(paths, "INDEX", tmp),
                        mock.patch.object(paths, "DB", tmp / "crowbar.db"),
                        mock.patch.object(paths, "STATE", tmp / "state.json"),
                        mock.patch.object(paths, "MANIFEST", tmp / "manifest.json"),
                        mock.patch.object(datasets.subprocess, "Popen")]
        for p in self.patches:
            p.start()
        self.tmp = tmp
        os.environ.pop("CROWBAR_NO_AUTO_UPDATE", None)
        self.release()

    def tearDown(self):
        self.release()
        for p in self.patches:
            p.stop()
        os.environ["CROWBAR_NO_AUTO_UPDATE"] = "1"

    @staticmethod
    def release():
        while datasets._held:
            datasets._held.pop().close()

    def age(self, days):
        import time
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))
        con = sqlite3.connect(paths.DB)
        con.execute("CREATE TABLE IF NOT EXISTS meta(key PRIMARY KEY, value)")
        con.execute("INSERT OR REPLACE INTO meta VALUES ('updated_at', ?)", (ts,))
        con.execute("INSERT OR REPLACE INTO meta VALUES ('schema', ?)", (str(paths.SCHEMA_VERSION),))
        con.commit()
        con.close()

    def test_state_json_is_not_a_freshness_source(self):
        self.age(10)
        paths.save_state(updated_at="2099-01-01T00:00:00Z")   # stale key from an old install
        self.assertAlmostEqual(datasets.index_status()["age_days"], 10, delta=0.2)

    @unittest.skipIf(sys.platform == "win32", "fcntl lock")
    def test_refresh_waits_for_a_running_update(self):
        import fcntl
        self.age(2)
        other = open(self.tmp / "update.lock", "a")    # another process's update
        fcntl.flock(other, fcntl.LOCK_EX)
        os.utime(self.tmp / "update.lock", (0, 0))       # its throttle hour is long gone
        try:
            self.assertTrue(datasets.update_running())
            self.assertFalse(datasets.acquire_update_lock())
            self.assertFalse(datasets.refresh_in_background())
        finally:
            other.close()
        self.assertFalse(datasets.update_running())
        self.assertTrue(datasets.acquire_update_lock())

    def test_status(self):
        self.assertIsNone(datasets.index_status()["age_days"])
        self.age(10)
        s = datasets.index_status()
        self.assertAlmostEqual(s["age_days"], 10, delta=0.2)
        self.assertTrue(s["stale"])
        self.age(2)
        self.assertFalse(datasets.index_status()["stale"])

    def test_refresh_throttled(self):
        self.age(0.1)
        self.assertFalse(datasets.refresh_in_background())   # fresh
        self.age(2)
        self.assertTrue(datasets.refresh_in_background())
        self.assertFalse(datasets.refresh_in_background())   # lock held for an hour
        self.assertEqual(datasets.subprocess.Popen.call_count, 1)

    def test_refresh_opt_out(self):
        self.age(2)
        os.environ["CROWBAR_NO_AUTO_UPDATE"] = "1"
        self.assertFalse(datasets.refresh_in_background())

    def test_stale_tier_rebuilds_instead_of_patching(self):
        from unittest import mock
        from crowbar import cli
        args = cli.build_parser().parse_args(["update"])
        stale = {"stale": True, "tier": "lite", "age_days": 10}
        with mock.patch.object(datasets, "index_status", return_value=stale), \
                mock.patch.object(cli, "cmd_sync") as sync, mock.patch.object(cli, "cmd_build") as build:
            cli.cmd_update(args)
        self.assertEqual(sync.call_args[0][0].tier, "lite")
        build.assert_called_once()

    def test_stale_without_tier_still_catches_up(self):
        from unittest import mock
        from crowbar import cli
        args = cli.build_parser().parse_args(["update"])
        stale = {"stale": True, "tier": None, "age_days": 30}
        with mock.patch.object(datasets, "index_status", return_value=stale), \
                mock.patch.object(cli, "cmd_sync") as sync, mock.patch.object(cli, "cmd_build") as build:
            cli.cmd_update(args)
        self.assertIsNone(sync.call_args[0][0].tier)
        build.assert_called_once()

    def test_failed_nvd_download_keeps_age_and_records_why(self):
        from unittest import mock
        from crowbar import cli, indexer
        self.age(2)
        args = cli.build_parser().parse_args(["update", "--quiet"])
        failed = [{"name": "nvd-modified", "status": "FAIL", "error": "offline"}]
        with mock.patch.object(datasets, "sync", return_value=failed), \
                mock.patch.object(indexer, "update") as upd, self.assertRaises(ValueError):
            cli.cmd_update(args)
        upd.assert_not_called()
        s = datasets.index_status()
        self.assertAlmostEqual(s["age_days"], 2, delta=0.2)
        self.assertIn("offline", s["last_error"]["error"])
        with mock.patch.object(datasets, "sync", return_value=[]), \
                mock.patch.object(indexer, "update", return_value={"rows_touched": 0, "seconds": 0, "cve": 0}):
            cli.cmd_update(args)
        self.assertIsNone(datasets.index_status()["last_error"])


class TestWhatsMoving(unittest.TestCase):
    """mention table, trending, new_since, data_as_of, and the chatter archive."""

    def test_trending_ranks_by_distinct_sources(self):
        rows = query.trending(CON, days=7)
        self.assertEqual(rows[0]["id"], "CVE-2021-44228")
        self.assertEqual(rows[0]["sources"], 3)
        self.assertNotIn("CVE-2017-0144", {r["id"] for r in rows})   # 40 days old
        self.assertIn("CVE-2017-0144", {r["id"] for r in query.trending(CON, days=60)})

    def test_new_since(self):
        d = query.new_since(CON, since="2024-01-01")
        self.assertEqual({r["id"] for r in d["published"]["rows"]}, {"CVE-2024-2222", "CVE-2025-3333"})
        self.assertEqual(d["published"]["total"], 2)
        self.assertEqual(d["eu_exploited"]["rows"][0]["cve"], "CVE-2021-44228")
        self.assertEqual(query.new_since(CON, since="2099-01-01")["published"]["total"], 0)

    def test_cve_carries_mentions_and_data_age(self):
        self.assertEqual(len(query.get_cve(CON, "CVE-2021-44228")["mentions"]), 3)
        self.assertEqual(query.data_as_of(CON)["cve_published"], "2025-02-02")

    def test_old_index_without_mention_table(self):
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        con.execute("CREATE TABLE cve(id, description, severity, cvss, epss, kev, has_exploit)")
        self.assertEqual(query.trending(con), [])

    def test_archive_merges_and_drops_posts_without_cves(self):
        import tempfile
        from unittest import mock
        from crowbar import chatter
        rss = """<rss><channel>
          <item><title>CVE-2021-44228 again</title><link>https://x/1</link>
                <pubDate>Mon, 26 Oct 2026 02:11:58 GMT</pubDate></item>
          <item><title>no ids here</title><link>https://x/2</link></item>
        </channel></rss>"""
        data = pathlib.Path(tempfile.mkdtemp())
        dest = data / "chatter" / "oss-security.jsonl"
        with mock.patch.object(chatter, "_get", return_value=rss):
            chatter.fetch("oss-security", dest)
            chatter.fetch("oss-security", dest)   # same items: no duplicates
        rows = [json.loads(x) for x in dest.read_text().splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cves"], ["CVE-2021-44228"])
        self.assertEqual(rows[0]["posted_at"], "2026-10-26T02:11:58Z")
        con = sqlite3.connect(":memory:")
        with mock.patch.object(paths, "DATA", data):
            self.assertEqual(chatter.load(con), 1)


class TestMcpFreshnessNote(unittest.TestCase):
    def test_stale_index_adds_a_note_at_most_every_10_minutes(self):
        from unittest import mock
        from crowbar import mcp
        stale = {"stale": True, "age_days": 12, "auto_update": False,
                 "last_error": {"at": "x", "error": "offline"}}
        mcp._checked[0] = 0.0
        with mock.patch.object(datasets, "index_status", return_value=stale), \
                mock.patch.object(paths, "DB", DB):
            note = mcp.check_freshness()
            self.assertIn("12 days old", note)
            self.assertIn("offline", note)
            self.assertIsNone(mcp.check_freshness())   # throttled


class TestOptionalSources(unittest.TestCase):
    def test_failed_chatter_does_not_fail_sync(self):
        from unittest import mock
        from crowbar import cli
        args = cli.build_parser().parse_args(["sync", "--only", "chatter"])
        failed = [{"name": n, "status": "FAIL", "error": "x"} for n in ("hn", "zdi")]
        with mock.patch.object(datasets, "sync", return_value=failed), \
                mock.patch.object(cli, "_writer_lock"):
            cli.cmd_sync(args)   # no SystemExit
        self.assertFalse(any(d.name == "hn" for d in datasets.tier_plan("lite")
                             if not d.optional))


class TestFtsRowid(unittest.TestCase):
    """cve_fts.rowid = fts_rowid(id), so delete_cves drops FTS rows by rowid, not a scan."""

    def setUp(self):
        import gzip
        import shutil
        import tempfile
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="cb-fts-"))
        self.db = tmp / "c.db"
        shutil.copy(DB, self.db)
        self.feed = tmp / "nvdcve-2.0-modified.json.gz"

        def item(cid, desc):
            return {"cve": {"id": cid, "published": "2026-10-01T00:00:00", "vulnStatus": "Modified",
                            "descriptions": [{"lang": "en", "value": desc}],
                            "configurations": [{"nodes": [{"cpeMatch": [{
                                "vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "2.15.0"}]}]}]}}
        doc = {"vulnerabilities": [item("CVE-2021-44228", "Log4Shell re-sent by NVD"),
                                   item("CVE-2026-9999", "brand new widget overflow"),
                                   item("CVE-2026-9999", "listed twice in one feed")]}
        with gzip.open(self.feed, "wt") as fh:
            json.dump(doc, fh)

    def aligned(self, con):
        n = con.execute("SELECT count(*) FROM cve").fetchone()[0]
        self.assertEqual(con.execute("SELECT count(*) FROM cve_fts").fetchone()[0], n)
        from crowbar.indexer import FTS_ROWID_SQL
        self.assertEqual(con.execute("SELECT count(*) FROM cve c JOIN cve_fts f "
                                     f"ON f.rowid={FTS_ROWID_SQL.replace('id', 'c.id')} "
                                     "WHERE f.id=c.id").fetchone()[0], n)

    def test_load_nvd_replace_keeps_rowids_aligned(self):
        from crowbar import indexer
        con = sqlite3.connect(self.db)
        indexer.load_nvd(self.feed, con, {}, set(), replace=True)
        self.aligned(con)
        self.assertEqual(con.execute("SELECT id FROM cve_fts WHERE cve_fts MATCH 'Log4Shell'")
                         .fetchone()[0], "CVE-2021-44228")
        # absent bounds are '' (cpe_match key columns are NOT NULL)
        self.assertEqual(con.execute("SELECT v_start_incl, v_end_excl FROM cpe_match "
                                     "WHERE cve_id='CVE-2026-9999'").fetchone(), ("", "2.15.0"))
        con.execute("VACUUM")   # the build ends with VACUUM: rowids must survive it
        self.aligned(con)
        con.close()

    def test_delete_cves_drops_fts_rows_by_rowid(self):
        from crowbar import indexer
        con = sqlite3.connect(self.db)
        plan = " ".join(r[-1] for r in con.execute(
            "EXPLAIN QUERY PLAN DELETE FROM cve_fts WHERE rowid IN (?)",
            (indexer.fts_rowid("CVE-2017-0144"),)))
        self.assertIn("VIRTUAL TABLE INDEX 0:=", plan)   # FTS5 rowid lookup; a scan is "INDEX 0:"
        indexer.delete_cves(con, ["CVE-2017-0144", "CVE-2023-1111"])
        self.assertEqual(con.execute("SELECT count(*) FROM cve_fts WHERE id IN "
                                     "('CVE-2017-0144','CVE-2023-1111')").fetchone()[0], 0)
        self.aligned(con)
        con.close()

    def test_v3_index_asks_for_a_rebuild(self):
        from unittest import mock
        from crowbar import indexer
        con = sqlite3.connect(self.db)
        con.execute("UPDATE meta SET value='3' WHERE key='schema'")
        con.commit()
        self.assertIn("run: crowbar build", db.schema_error(con))
        con.close()
        with mock.patch.object(paths, "DB", self.db), \
                self.assertRaisesRegex(ValueError, "v3 needs a rebuild: run crowbar build"):
            indexer.update()
        self.assertFalse(self.db.with_suffix(".db.tmp").exists())

    def test_v3_index_doctor_and_update_point_to_build(self):
        import argparse
        from unittest import mock
        from crowbar import cli, datasets, indexer
        home, dbf = support.make_fixture_home()
        con = sqlite3.connect(dbf)
        con.execute("UPDATE meta SET value='3' WHERE key='schema'")
        con.commit()
        con.close()
        doc = json.loads(support.run_hv("doctor", "--json", home=str(home)).stdout)
        self.assertIn(f"index schema v3 != v{paths.SCHEMA_VERSION} - run: crowbar build", doc["problems"])
        args = argparse.Namespace(no_sync=True, jobs=1, extra=False, json=False)
        status = {"tier": None, "stale": False, "age_days": 2}
        with mock.patch.object(paths, "DB", dbf), \
                mock.patch.object(datasets, "index_status", return_value=status), \
                mock.patch.object(cli, "cmd_sync") as sync, mock.patch.object(cli, "cmd_build") as build:
            cli._update(args, indexer)   # rebuilds instead of failing after a sync
        build.assert_called_once()
        sync.assert_not_called()


class TestUpdateKeepsLinks(unittest.TestCase):
    """An NVD re-load must not wipe Nuclei/Metasploit links; EPSS reaches every CVE."""

    def test_delete_cves_keeps_link_tables_and_epss_applies(self):
        import shutil
        import tempfile
        from crowbar import indexer
        db = pathlib.Path(tempfile.mkdtemp()) / "c.db"
        shutil.copy(DB, db)
        con = sqlite3.connect(db)
        indexer.delete_cves(con, ["CVE-2021-44228"])
        self.assertEqual(con.execute("SELECT count(*) FROM cve_nuclei WHERE cve_id='CVE-2021-44228'")
                         .fetchone()[0], 1)
        indexer.apply_epss(con, {"CVE-2017-0144": (0.5, 77.0)})
        self.assertEqual(con.execute("SELECT epss FROM cve WHERE id='CVE-2017-0144'").fetchone()[0], 0.5)
        con.close()

    def test_indexes_apply_to_an_existing_db(self):
        import shutil
        import tempfile
        from crowbar import indexer
        db = pathlib.Path(tempfile.mkdtemp()) / "c.db"
        shutil.copy(DB, db)
        con = sqlite3.connect(db)
        con.execute("CREATE INDEX IF NOT EXISTS cpe_id ON cpe_match(cve_id)")   # retired
        indexer.finish(con)
        names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("cve_kev_epss", names)
        self.assertNotIn("cpe_id", names)
        con.close()


class TestKevEpss(unittest.TestCase):
    """Every KEV row carries EPSS, even when the tier holds no NVD record for it."""

    def kev_file(self):
        import tempfile
        path = pathlib.Path(tempfile.mkdtemp(prefix="cb-kev-")) / "kev.json"
        path.write_text(json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2014-0160", "vendorProject": "OpenSSL", "product": "OpenSSL",
             "vulnerabilityName": "Heartbleed", "dateAdded": "2022-05-04"}]}))
        return path

    def test_kev_rows_get_epss_and_old_schema_migrates(self):
        from crowbar import indexer
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        # a pre-EPSS kev table, as in indexes built before this change
        con.execute("CREATE TABLE kev(cve TEXT PRIMARY KEY, vendor, product, name, date_added,"
                    " ransomware, action, due, notes)")
        con.execute("CREATE TABLE cve(id TEXT PRIMARY KEY, kev INTEGER)")
        con.execute("CREATE TABLE cve_alias(cve_id, alias, source)")
        indexer.load_kev(self.kev_file(), con, {"CVE-2014-0160": (0.94, 0.999)})
        row = con.execute("SELECT epss, epss_pct FROM kev").fetchone()
        self.assertEqual((row["epss"], row["epss_pct"]), (0.94, 0.999))
        # no NVD row: get_cve says it is in KEV instead of a bare "not found"
        with self.assertRaises(KeyError) as ctx:
            query.get_cve(con, "CVE-2014-0160")
        self.assertIn("CISA KEV", ctx.exception.args[0])
        self.assertIn("0.94", ctx.exception.args[0])


class TestResumableDownload(unittest.TestCase):
    """A server that drops every response early must still yield the whole file."""

    def test_resumes_through_repeated_resets(self):
        import http.server
        import tempfile
        import threading
        from unittest import mock
        body = os.urandom(2_000_000)
        chunk = 300_000                      # 7 drops: more than `retries`

        class Flaky(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                start = int(self.headers.get("Range", "bytes=0-")[6:].rstrip("-") or 0)
                self.send_response(206 if start else 200)
                if start:
                    self.send_header("Content-Range", f"bytes {start}-{len(body) - 1}/{len(body)}")
                self.send_header("Content-Length", str(len(body) - start))
                self.end_headers()
                self.wfile.write(body[start:start + chunk])   # then hang up

            def log_message(self, *a):
                pass

        try:
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Flaky)
        except PermissionError:
            self.skipTest("local port binding blocked (sandbox)")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        dest = pathlib.Path(tempfile.mkdtemp(prefix="cb-dl-")) / "f.bin"
        try:
            with mock.patch.object(datasets.time, "sleep"):
                datasets.http_get(f"http://127.0.0.1:{srv.server_port}/f", dest, retries=4)
        finally:
            srv.shutdown()
        self.assertEqual(dest.read_bytes(), body)


class TestMirror(unittest.TestCase):
    """`crowbar pack` output, served over HTTP, must sync back byte-for-byte."""

    def test_pack_then_sync_from_mirror(self):
        import functools
        import http.server
        import tempfile
        import threading
        from unittest import mock
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="cb-mirror-"))
        src, dst, out = tmp / "src", tmp / "dst", tmp / "out"
        kev, nuclei = datasets.plan(only=["kev"])[0], datasets.plan(only=["nuclei"])[0]

        def home(root):
            return mock.patch.multiple(paths, DATA=root / "data", INDEX=root / "index",
                                       MANIFEST=root / "index" / "manifest.json")

        with home(src):
            kev.path.parent.mkdir(parents=True)
            kev.path.write_text('{"vulnerabilities": []}')
            (nuclei.path / "http").mkdir(parents=True)
            (nuclei.path / "http" / "t.yaml").write_text("id: t\n")
            (nuclei.path / ".git").mkdir()
            datasets.save_manifest({"datasets": {
                "kev": {"path": kev.dest, "fetched_at": "2026-01-01T00:00:00Z"},
                "nuclei": {"path": nuclei.dest}}})
            datasets.pack(out)

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = functools.partial(Quiet, directory=str(out))
        try:
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        except PermissionError:
            self.skipTest("local port binding blocked (sandbox)")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        env = {"CROWBAR_MIRROR": f"http://127.0.0.1:{srv.server_port}/"}
        try:
            with home(dst), mock.patch.dict(os.environ, env), \
                    mock.patch.object(datasets.time, "sleep"):
                res = {r["name"]: r for r in datasets.sync([kev, nuclei])}
                self.assertEqual({r["status"] for r in res.values()}, {"ok"})
                self.assertEqual(kev.path.read_text(), '{"vulnerabilities": []}')
                self.assertEqual((nuclei.path / "http" / "t.yaml").read_text(), "id: t\n")
                self.assertFalse((nuclei.path / ".git").exists())
                self.assertEqual(datasets.load_manifest()["datasets"]["kev"]["fetched_at"],
                                 "2026-01-01T00:00:00Z")
                # unchanged mirror: nothing re-downloaded
                self.assertEqual({r["status"] for r in datasets.sync([kev, nuclei])}, {"same"})
                # tampered or missing mirror file: never lands, falls back to upstream
                real_get = datasets.http_get

                def upstream_304(url, dest, **kw):
                    return None if url == kev.url else real_get(url, dest, **kw)

                for broken in ("tamper", "missing"):
                    if broken == "tamper":
                        (out / "kev").write_text("evil")
                    else:
                        (out / "kev").unlink()   # e.g. mid `--clobber` re-upload: 404
                    with mock.patch.object(datasets, "http_get", side_effect=upstream_304) as get, \
                            mock.patch("sys.stderr"):
                        r = datasets.sync([kev], force=True)[0]
                    self.assertEqual(r["status"], "same", broken)
                    self.assertEqual(get.call_args[0][0], kev.url, broken)
                    self.assertEqual(kev.path.read_text(), '{"vulnerabilities": []}')
                    self.assertEqual(list(kev.path.parent.iterdir()), [kev.path], broken)
                # mirrored git dataset (no .git): a later upstream sync re-clones it
                # and swaps it in, and a failed clone keeps the mirrored copy
                def clone(ok):
                    def run(cmd, **kw):
                        if ok and cmd[1] == "clone":
                            (pathlib.Path(cmd[-1]) / ".git").mkdir(parents=True)
                        return subprocess.CompletedProcess(cmd, 0 if ok else 128, "", "boom")
                    return run

                with mock.patch.dict(os.environ, {"CROWBAR_MIRROR": ""}):
                    with mock.patch.object(datasets.subprocess, "run", side_effect=clone(False)):
                        self.assertEqual(datasets.sync([nuclei])[0]["status"], "FAIL")
                    self.assertTrue((nuclei.path / "http" / "t.yaml").exists())
                    with mock.patch.object(datasets.subprocess, "run", side_effect=clone(True)):
                        self.assertEqual(datasets.sync([nuclei])[0]["status"], "ok")
                    self.assertTrue((nuclei.path / ".git").exists())
                    self.assertFalse((nuclei.path / "http").exists())
                    self.assertFalse(nuclei.path.with_name("templates.clone").exists())
                # a dataset the mirror lacks goes upstream (stubbed here)
                epss = datasets.plan(only=["epss"])[0]
                with mock.patch.object(datasets, "http_get", return_value=None) as up:
                    epss.path.parent.mkdir(parents=True)
                    epss.path.write_text("x")
                    datasets.sync([epss])
                up.assert_called_once()
                self.assertEqual(up.call_args[0][0], epss.url)
        finally:
            srv.shutdown()
            srv.server_close()


class TestInstalledRoot(unittest.TestCase):
    def test_installed_root(self):
        # an installed package (no bin/crowbar beside it) must not index into site-packages
        code = ("import pathlib, sys; sys.path.insert(0, sys.argv[1]); "
                "from crowbar import paths; print(paths.ROOT)")
        import shutil
        import tempfile
        site = pathlib.Path(tempfile.mkdtemp(prefix="cb-site-"))
        shutil.copytree(support.ROOT / "crowbar", site / "crowbar")
        env = {k: v for k, v in os.environ.items() if k != "CROWBAR_HOME"}
        out = subprocess.run([sys.executable, "-c", code, str(site)], env=env,
                             capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(out, str(pathlib.Path.home() / ".crowbar"))


class TestExploitOffline(unittest.TestCase):
    """cb_exploit via MCP must never hit the network (it's an offline tool)."""

    def test_exploit_lookup_offline_and_hints_cli(self):
        row = CON.execute("SELECT id FROM exploit LIMIT 1").fetchone()
        out = query.exploit_lookup(CON, str(row[0]))
        self.assertEqual(str(out["id"]), str(row[0]))
        self.assertIn("--fetch", out["fetch"])   # points at the CLI for source

    def test_filter_only_browse(self):
        self.assertTrue(query.nuclei_search(CON, None))
        self.assertEqual(query.toolkit_search(CON, None, "gtfobins")[0]["source"], "gtfobins")
        self.assertTrue(query.attack_lookup(CON))
        self.assertTrue(query.msf_search(CON))

    def test_doctor_json(self):
        p = support.run_hv("doctor", "--json", home=str(HOME))
        r = json.loads(p.stdout)
        self.assertEqual(p.returncode, 0 if r["ok"] else 1)
        self.assertEqual(r["schema"], paths.SCHEMA_VERSION)

    def test_exploit_lookup_missing(self):
        self.assertEqual(query.exploit_lookup(CON, "99999999")["error"], "not_found")


class TestDataQuality(unittest.TestCase):
    """P0 data fixes: MSRC severity from CVSS, Apple exploited, verify on empty DB."""

    def test_sev_from_cvss(self):
        from crowbar import loaders
        self.assertEqual(loaders._sev_from_cvss(9.8), "Critical")
        self.assertEqual(loaders._sev_from_cvss(7.5), "Important")
        self.assertEqual(loaders._sev_from_cvss(5.0), "Moderate")
        self.assertEqual(loaders._sev_from_cvss(2.0), "Low")

    def test_msrc_recovers_severity_from_cvss(self):
        import sqlite3
        import json
        import tempfile
        import os
        from crowbar import loaders
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE os_advisory(source,cve,platform,product,version,"
                    "title,severity,impact,exploited,released,url)")
        rec = [{"cveNumber": "CVE-2026-0001", "cveTitle": "x", "baseScore": 9.1}]
        fd, path = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps(rec).encode())
        os.close(fd)
        loaders.load_msrc(pathlib.Path(path), con)
        os.unlink(path)
        sev = con.execute("SELECT severity FROM os_advisory WHERE cve='CVE-2026-0001'").fetchone()[0]
        self.assertEqual(sev, "Critical")

    def test_verify_fails_on_empty_db(self):
        import tempfile
        from crowbar import cli
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "index").mkdir()
        (d / "index/crowbar.db").write_bytes(b"")          # 0-byte "DB"
        problems = cli._verify(d)
        self.assertTrue(any("crowbar.db" == n for n, _ in problems))


class TestTierCompleteness(unittest.TestCase):
    """Pain-point fix: doctor/build must flag an incomplete tier, not say ready."""

    def test_no_tier_means_no_complaint(self):
        self.assertEqual(datasets.tier_missing(None), [])
        self.assertEqual(datasets.tier_missing("bogus"), [])

    def test_missing_reported_when_manifest_empty(self):
        # against a manifest with no datasets, every tier dataset is "missing"
        import unittest.mock as mock
        with mock.patch.object(datasets, "load_manifest", return_value={"datasets": {}}):
            missing = datasets.tier_missing("lite")
        self.assertIn("kev", missing)
        self.assertIn("epss", missing)


if __name__ == "__main__":
    unittest.main(verbosity=2)
