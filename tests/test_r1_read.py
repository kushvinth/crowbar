"""Round r1 agent 3: read-path tests - connection PRAGMAs, hot-journal recovery,
persistent MCP connection and the FTS top-N relevance search."""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import random
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from crowbar import db, indexer, mcp, paths, query  # noqa: E402
from tests import support  # noqa: E402

HOME: pathlib.Path
DB: pathlib.Path


def setUpModule():
    global HOME, DB
    HOME, DB = support.make_fixture_home()


class TestConnect(unittest.TestCase):
    def setUp(self):
        self._db = paths.DB
        paths.DB = DB

    def tearDown(self):
        paths.DB = self._db

    def test_readonly_pragmas(self):
        con = db.connect()
        try:
            self.assertEqual(con.execute("PRAGMA query_only").fetchone()[0], 1)
            self.assertEqual(con.execute("PRAGMA mmap_size").fetchone()[0], 268435456)
            self.assertEqual(con.execute("PRAGMA cache_size").fetchone()[0], -65536)
            with self.assertRaises(sqlite3.OperationalError):
                con.execute("DELETE FROM meta")
        finally:
            con.close()

    def test_hot_journal_recovery(self):
        """A writer SIGKILLed mid-transaction leaves a hot journal; a ro connect
        must still work and must see the pre-write data."""
        home, dbf = support.make_fixture_home()
        paths.DB = dbf
        before = support.one(
            sqlite3.connect(db.ro_uri(dbf), uri=True), "SELECT description FROM cve WHERE id='CVE-2021-44228'"
        )
        # a 2-page cache spills the dirty pages into the DB file, so the rollback matters
        code = (
            "import sqlite3, sys, time\n"
            f"c = sqlite3.connect({str(dbf)!r}, isolation_level=None)\n"
            "c.execute('PRAGMA cache_size=2'); c.execute('BEGIN')\n"
            "for _ in range(200):\n"
            "    c.execute(\"UPDATE cve SET description = description || ' CLOBBERED'\")\n"
            "c.execute(\"UPDATE cve_fts SET description = description || ' CLOBBERED'\")\n"
            "print('ok', flush=True); time.sleep(60)\n"
        )
        proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "ok")
            os.kill(proc.pid, signal.SIGKILL)
            proc.wait(timeout=10)
            journal = dbf.with_name(dbf.name + "-journal")
            self.assertTrue(journal.exists() and journal.stat().st_size > 0, "journal is not hot")
            # the scenario is real: a bare mode=ro open cannot roll the journal back
            raw = sqlite3.connect(db.ro_uri(dbf), uri=True)
            with self.assertRaises(sqlite3.OperationalError):
                raw.execute("SELECT count(*) FROM cve").fetchone()
            raw.close()
            con = db.connect()
            try:
                self.assertEqual(
                    con.execute("SELECT description FROM cve WHERE id='CVE-2021-44228'").fetchone()[0], before
                )
                self.assertEqual(
                    con.execute("SELECT count(*) FROM cve WHERE description LIKE '%CLOBBERED'").fetchone()[0],
                    0,
                )
            finally:
                con.close()
            self.assertFalse(journal.exists())
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_recover_journal_ignores_missing_and_readonly(self):
        db.recover_journal(DB)  # no journal: no-op
        db.recover_journal(pathlib.Path(tempfile.mkdtemp()) / "nope.db")


def _retitle(dbf: pathlib.Path, text: str) -> None:
    """Rewrite one description in place (same inode, new mtime)."""
    w = sqlite3.connect(dbf)
    w.execute("UPDATE cve SET description=? WHERE id='CVE-2021-44228'", (text,))
    w.commit()
    w.close()


class TestMCPConnection(unittest.TestCase):
    """The server keeps one connection but must follow the file: a swap by
    os.replace (new inode), an in-place rewrite (new mtime) and a damaged file."""

    @classmethod
    def setUpClass(cls):
        cls.home, cls.db = support.make_fixture_home()
        env = dict(os.environ, CROWBAR_HOME=str(cls.home))
        cls.proc = subprocess.Popen(
            [sys.executable, str(support.ROOT / "mcp" / "server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        cls.n = 0
        cls.request("initialize", {"protocolVersion": "2025-06-18"})

    @classmethod
    def tearDownClass(cls):
        cls.proc.stdin.close()
        cls.proc.wait(timeout=10)
        cls.proc.stdout.close()
        cls.proc.stderr.close()

    @classmethod
    def request(cls, method, params=None):
        cls.n += 1
        msg = {"jsonrpc": "2.0", "id": cls.n, "method": method, "params": params or {}}
        cls.proc.stdin.write(json.dumps(msg) + "\n")
        cls.proc.stdin.flush()
        return json.loads(cls.proc.stdout.readline())

    def cve(self, cid="CVE-2021-44228"):
        res = self.request("tools/call", {"name": "cb_cve", "arguments": {"id": cid}})["result"]
        text = res["content"][0]["text"]
        return res, (text if res.get("isError") else json.loads(text))

    def test_follows_swap_and_in_place_rewrite(self):
        _, first = self.cve()
        self.assertIn("Log4j", first["description"])
        # 1. swap: a fresh index built beside the live one, then os.replace'd over it
        new = support.make_fixture_db(self.home / "index" / "crowbar.db.tmp")
        _retitle(new, "swapped index")
        os.replace(new, self.db)
        self.assertEqual(self.cve()[1]["description"], "swapped index")
        # 2. in place: same inode, only the content and mtime change
        _retitle(self.db, "rewritten in place")
        self.assertEqual(self.cve()[1]["description"], "rewritten in place")
        # 3. the file goes bad, then is restored: error once, then a clean reopen
        good = self.db.read_bytes()
        self.db.write_bytes(b"not a database" * 100)
        self.assertTrue(self.cve()[0]["isError"])
        self.db.write_bytes(good)
        res, row = self.cve()
        self.assertFalse(res.get("isError"), res)
        self.assertEqual(row["description"], "rewritten in place")


class TestMCPInProcess(unittest.TestCase):
    def setUp(self):
        self._db = paths.DB
        paths.DB = DB
        mcp.close_connection()

    def tearDown(self):
        mcp.close_connection()
        paths.DB = self._db

    def call(self, cid="CVE-2021-44228") -> dict:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mcp.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "cb_cve", "arguments": {"id": cid}},
                }
            )
        return json.loads(out.getvalue())["result"]

    def test_connection_is_reused(self):
        self.call()
        con = mcp.connection()
        self.call()
        self.assertIs(mcp.connection(), con)

    def sql(self, q) -> dict:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mcp.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "cb_sql", "arguments": {"query": q}},
                }
            )
        return json.loads(json.loads(out.getvalue())["result"]["content"][0]["text"])

    def test_pragma_does_not_stick(self):
        like = "select 'Log4J' like 'log4j' AS x"
        self.assertEqual(self.sql(like), [{"x": 1}])
        self.sql("pragma case_sensitive_like=1")
        self.assertEqual(self.sql(like), [{"x": 1}])  # a fresh connection, default LIKE again

    def test_database_error_drops_connection(self):
        key = mcp.connection() and mcp._con[1]
        broken = sqlite3.connect(":memory:")  # no tables: every tool raises OperationalError
        broken.row_factory = sqlite3.Row
        mcp._con[0] = broken
        res = self.call()
        self.assertTrue(res["isError"])  # no tables: schema check or OperationalError
        self.assertIsNone(mcp._con[0])
        res = self.call()
        self.assertFalse(res.get("isError"), res)
        self.assertEqual(mcp._con[1], key)


# ------------------------------------------------------------ FTS top-N search
WORDS = (
    "remote code execution buffer overflow heap stack nginx apache log4j openssh kernel "
    "privilege escalation cross site scripting sql injection deserialization race "
    "condition type confusion use after free windows linux ios php java wordpress"
).split()
QUERIES = [
    "kernel",
    "remote code execution",
    "nginx overflow",
    "sql injection wordpress",
    "log4j",
    "heap",
    "ios kernel",
    "kernel zzzznotaword",
    "deserialization java",
]


def synth_db(path: pathlib.Path, n: int) -> pathlib.Path:
    """`n` random CVEs with many bm25 ties, so candidate order at the pool edge is exercised."""
    rnd = random.Random(7)
    con = indexer.create(path)
    cves, fts, meta, expl = [], [], [], []
    for i in range(n):
        y, cid = 2002 + i % 24, f"CVE-{2002 + i % 24}-{10000 + i}"
        desc = " ".join(rnd.choice(WORDS) for _ in range(rnd.randint(6, 20)))
        kev, epss, ex = int(rnd.random() < 0.01), round(rnd.random() ** 4, 4), int(rnd.random() < 0.05)
        cves.append(
            (
                cid,
                f"{y}-01-01",
                f"{y}-02-01",
                "Analyzed",
                desc,
                7.0,
                "3.1",
                "",
                "HIGH",
                kev,
                epss,
                epss * 100,
                ex,
                0,
                0,
                y,
            )
        )
        fts.append((cid, desc, "p"))
        meta.append((cid, y, y, rnd.randint(0, 4) if rnd.random() < 0.1 else 0))
        if ex:
            expl.append((cid, str(i)))
    con.executemany("INSERT INTO cve VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", cves)
    con.executemany("INSERT INTO cve_fts(id,description,products) VALUES (?,?,?)", fts)
    con.executemany("INSERT INTO cve_meta(cve_id,published_year,cve_year,poc_count) VALUES (?,?,?,?)", meta)
    con.executemany("INSERT INTO cve_exploit VALUES (?,?)", expl)
    con.commit()
    indexer.finish(con)
    con.commit()
    con.close()
    return path


def reference_search(con, q: str, limit: int = 20, offset: int = 0) -> list[str]:
    """The pre-r1 relevance path: bm25 + per-row subqueries over every FTS match."""
    fq, toks = query.fts_query(q)
    sql = (
        "SELECT c.*, (SELECT count(*) FROM cve_exploit x WHERE x.cve_id=c.id) AS exploits,"
        " (SELECT count(*) FROM cve_nuclei n WHERE n.cve_id=c.id) AS nuclei_count,"
        " (SELECT coalesce(poc_count,0) FROM cve_meta m WHERE m.cve_id=c.id) AS poc_count,"
        " bm25(cve_fts) AS rank FROM cve_fts JOIN cve c ON c.id = cve_fts.id"
        " WHERE cve_fts MATCH ? ORDER BY rank LIMIT ?"
    )
    pool = min(max(300, (offset + limit) * 8), 2000)
    rows = con.execute(sql, [fq, pool]).fetchall()
    if not rows and len(toks) > 1:
        rows = con.execute(sql, [f'"{max(toks, key=len)}"*', pool]).fetchall()
    top = max([abs(r["rank"]) for r in rows] or [1.0]) or 1.0
    scored = [
        (
            10.0 * abs(r["rank"]) / top
            + 4.0 * r["kev"]
            + 5.0 * (r["epss"] or 0)
            + 1.5 * min(r["exploits"], 3)
            + 1.0 * min(r["poc_count"] or 0, 3),
            r,
        )
        for r in rows
    ]
    scored.sort(key=lambda pair: -pair[0])
    return [r["id"] for _, r in scored][offset : offset + limit]


class TestSearchTopN(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.synth = synth_db(pathlib.Path(tempfile.mkdtemp(prefix="hv-synth-")) / "crowbar.db", 30_000)

    def check(self, dbf: pathlib.Path):
        con = sqlite3.connect(db.ro_uri(dbf), uri=True)
        con.row_factory = sqlite3.Row
        for q in QUERIES:
            for limit, offset in ((20, 0), (5, 0), (50, 40), (100, 250)):
                with self.subTest(db=dbf.parent.name, q=q, limit=limit, offset=offset):
                    got = [r["id"] for r in query.search(con, q, limit=limit, offset=offset)]
                    self.assertEqual(got, reference_search(con, q, limit, offset))
        con.close()

    def test_equivalent_on_fixture(self):
        self.check(DB)

    def test_equivalent_on_synthetic(self):
        self.check(self.synth)

    def test_top_n_plan_joins_cve_on_the_pool(self):
        con = sqlite3.connect(db.ro_uri(self.synth), uri=True)
        con.row_factory = sqlite3.Row
        seen = []
        con.set_trace_callback(seen.append)
        self.assertTrue(query.search(con, "kernel"))
        con.set_trace_callback(None)
        sql = next(s for s in seen if "MATCH" in s)
        plan = [r[3] for r in con.execute("EXPLAIN QUERY PLAN " + sql)]
        self.assertIn("CO-ROUTINE f", plan)  # FTS top-N feeds the join
        self.assertTrue(any("SEARCH c USING INDEX" in p for p in plan), plan)
        # any filter leaves the single-query path; results must still come back
        self.assertTrue(query.search(con, "kernel", kev=True))
        self.assertTrue(query.search(con, "kernel", sort="newest"))
        con.close()

    def test_filtered_results_unchanged(self):
        con = sqlite3.connect(db.ro_uri(DB), uri=True)
        con.row_factory = sqlite3.Row
        self.assertEqual(
            [r["id"] for r in query.search(con, "remote", kev=True)], ["CVE-2021-44228", "CVE-2017-0144"]
        )
        con.close()


if __name__ == "__main__":
    unittest.main()
