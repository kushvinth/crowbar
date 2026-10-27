"""Round r1, agent 1: index write path (cve_fts rowids, optimize-on-build, in-place update).

Fixture only - no corpus, no network.  Run: python3 -m tests.test_r1_write
"""

from __future__ import annotations

import pathlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from crowbar import indexer, paths  # noqa: E402
from tests import support  # noqa: E402

HOME: pathlib.Path
DB: pathlib.Path


def setUpModule():
    global HOME, DB
    HOME, DB = support.make_fixture_home()


def fresh_copy() -> sqlite3.Connection:
    db = pathlib.Path(tempfile.mkdtemp(prefix="r1w-")) / "c.db"
    shutil.copy(DB, db)
    return sqlite3.connect(db)


def fts_rows(con) -> dict[int, str]:
    return {r[0]: r[1] for r in con.execute("SELECT rowid, id FROM cve_fts")}


class TestRowid(unittest.TestCase):
    def test_helper_and_sql_agree(self):
        self.assertEqual(indexer.fts_rowid("CVE-2021-44228"), 2021_00044228)
        self.assertEqual(indexer.fts_rowid("CVE-1999-0001"), 1999_00000001)
        con = sqlite3.connect(":memory:")
        for cid in ("CVE-2021-44228", "CVE-2024-1234567", "CVE-1999-0001"):
            got = con.execute(
                f"SELECT {indexer.FTS_ROWID_SQL} FROM (SELECT ? AS id)", (cid,)
            ).fetchone()[0]
            self.assertEqual(got, indexer.fts_rowid(cid), cid)

    def test_duplicate_insert_replaces_instead_of_raising(self):
        con = indexer.create(pathlib.Path(tempfile.mkdtemp(prefix="r1w-")) / "t.db")
        fts = [("CVE-2030-1", "first text", "acme widget")]
        indexer._flush(con, [], [], [], [], [], fts)
        indexer._flush(
            con, [], [], [], [], [], [("CVE-2030-1", "second text", "acme widget")]
        )
        self.assertEqual(fts_rows(con), {indexer.fts_rowid("CVE-2030-1"): "CVE-2030-1"})
        self.assertEqual(
            con.execute("SELECT description FROM cve_fts").fetchone()[0], "second text"
        )
        self.assertEqual(
            con.execute(
                "SELECT count(*) FROM cve_fts WHERE cve_fts MATCH 'first'"
            ).fetchone()[0],
            0,
        )
        con.close()


class TestMigration(unittest.TestCase):
    def test_fixture_copy_migrates_once(self):
        con = fresh_copy()
        con.execute("DELETE FROM meta WHERE key='fts_rowid'")   # an index built before the flag
        n_cve = con.execute("SELECT count(*) FROM cve").fetchone()[0]
        con.execute(
            "INSERT INTO cve_fts(id,description,products) "
            "VALUES ('CVE-2021-44228','log4j newest text','x')"
        )
        self.assertEqual(
            con.execute("SELECT count(*) FROM cve_fts").fetchone()[0], n_cve + 1
        )
        self.assertTrue(indexer.migrate_fts_rowids(con))
        self.assertFalse(indexer.migrate_fts_rowids(con))
        self.assertEqual(
            con.execute("SELECT value FROM meta WHERE key='fts_rowid'").fetchone()[0],
            "1",
        )
        got = fts_rows(con)
        self.assertEqual(len(got), n_cve)
        self.assertEqual(got, {indexer.fts_rowid(c): c for c in got.values()})
        for term in (
            "log4j",
            "newest",
        ):  # the newest duplicate survived and is searchable
            self.assertEqual(
                [
                    r[0]
                    for r in con.execute(
                        "SELECT id FROM cve_fts WHERE cve_fts MATCH ?", (term,)
                    )
                ],
                ["CVE-2021-44228"],
            )
        con.close()

    def test_delete_cves_removes_only_those_fts_rows(self):
        for migrated in (False, True):
            con = fresh_copy()
            if migrated:
                indexer.migrate_fts_rowids(con)
            before = {r[0] for r in con.execute("SELECT id FROM cve_fts")}
            indexer.delete_cves(con, ["CVE-2021-44228", "CVE-2017-0144"])
            after = {r[0] for r in con.execute("SELECT id FROM cve_fts")}
            self.assertEqual(
                before - after, {"CVE-2021-44228", "CVE-2017-0144"}, migrated
            )
            self.assertEqual(after, {r[0] for r in con.execute("SELECT id FROM cve")})
            self.assertEqual(
                con.execute(
                    "SELECT count(*) FROM cve_nuclei WHERE cve_id='CVE-2021-44228'"
                ).fetchone()[0],
                1,
            )
            con.close()

    def test_delete_by_rowid_is_a_lookup_not_a_scan(self):
        con = fresh_copy()
        indexer.migrate_fts_rowids(con)

        def plan(sql):
            return " ".join(
                r[-1] for r in con.execute("EXPLAIN QUERY PLAN " + sql, (1, 2))
            )

        by_id, by_rowid = (
            plan("DELETE FROM cve_fts WHERE id IN (?,?)"),
            plan("DELETE FROM cve_fts WHERE rowid IN (?,?)"),
        )
        self.assertNotEqual(by_id, by_rowid)
        self.assertTrue(
            by_rowid.endswith("="), by_rowid
        )  # FTS5 idxStr '=': rowid equality lookup
        con.close()


class TestEpss(unittest.TestCase):
    def test_apply_epss_skips_equal_rows(self):
        con = fresh_copy()
        cur = {
            r[0]: (r[1], r[2])
            for r in con.execute("SELECT id, epss, epss_pct FROM cve")
        }
        t = con.total_changes
        indexer.apply_epss(con, cur)
        self.assertEqual(con.total_changes - t, len(cur))  # the temp-table inserts only
        cur["CVE-2017-0144"] = (0.5, 77.0)
        t = con.total_changes
        indexer.apply_epss(con, cur)
        self.assertEqual(con.total_changes - t, len(cur) + 1)
        self.assertEqual(
            con.execute("SELECT epss FROM cve WHERE id='CVE-2017-0144'").fetchone()[0],
            0.5,
        )
        con.close()


class TestFinish(unittest.TestCase):
    def test_optimize_only_when_asked(self):
        for optimize in (False, True):
            con = fresh_copy()
            seen = []
            con.set_trace_callback(seen.append)
            indexer.finish(con, optimize=optimize)
            self.assertEqual(any("optimize" in s for s in seen), optimize)
            self.assertTrue(any(s.startswith("ANALYZE") for s in seen))
            con.close()


class TestOneTxn(unittest.TestCase):
    def test_executescript_keeps_the_transaction(self):
        con = sqlite3.connect(":memory:")
        con.isolation_level = None
        con.execute("BEGIN")
        proxy = indexer._OneTxn(con)
        proxy.executescript(
            "CREATE TABLE t(a); INSERT INTO t VALUES ('a;b'); -- c\n"
            "INSERT INTO t VALUES (2);\nINSERT INTO t VALUES (3)"
        )
        proxy.commit()
        self.assertTrue(con.in_transaction)
        self.assertEqual(
            [r[0] for r in proxy.execute("SELECT a FROM t")], ["a;b", 2, 3]
        )
        con.execute("ROLLBACK")
        self.assertEqual(
            con.execute("SELECT count(*) FROM sqlite_master").fetchone()[0], 0
        )


class TestUpdate(unittest.TestCase):
    """indexer.update() end to end on a fixture home, cloned and in place."""

    def setUp(self):
        self.home = pathlib.Path(tempfile.mkdtemp(prefix="r1w-home-"))
        (self.home / "data").mkdir()
        (self.home / "index").mkdir()
        self.db = self.home / "index" / "crowbar.db"
        shutil.copy(DB, self.db)
        self.epss = {"CVE-2017-0144": (0.91, 99.5)}
        self.patches = [
            mock.patch.object(paths, "DATA", self.home / "data"),
            mock.patch.object(paths, "INDEX", self.home / "index"),
            mock.patch.object(paths, "DB", self.db),
            mock.patch.object(indexer, "read_epss", return_value=self.epss),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def dump(self) -> str:
        con = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        try:
            return "\n".join(con.iterdump())
        finally:
            con.close()

    def check_updated(self, stats):
        con = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        self.assertEqual(
            con.execute("SELECT epss FROM cve WHERE id='CVE-2017-0144'").fetchone()[0],
            0.91,
        )
        self.assertEqual(
            con.execute("SELECT value FROM meta WHERE key='fts_rowid'").fetchone()[0],
            "1",
        )
        self.assertEqual(
            con.execute("SELECT value FROM meta WHERE key='updated_at'").fetchone()[0],
            stats["updated_at"],
        )
        self.assertEqual(
            con.execute("SELECT count(*) FROM cve_fts").fetchone()[0],
            con.execute("SELECT count(*) FROM cve").fetchone()[0],
        )
        self.assertEqual(
            fts_rows(con), {indexer.fts_rowid(c): c for c in fts_rows(con).values()}
        )
        con.close()
        self.assertFalse(self.db.with_suffix(".db.tmp").exists())
        self.assertFalse(self.db.with_name("crowbar.db-journal").exists())

    @unittest.skipIf(sys.platform == "win32", "no cp/clonefile")
    def test_cloned_path_swaps_and_skips_optimize(self):
        with (
            mock.patch.object(indexer, "finish", wraps=indexer.finish) as fin,
            mock.patch.object(indexer, "_clone", wraps=indexer._clone) as clone,
        ):
            stats = indexer.update()
        self.assertTrue(clone.return_value, "fixture home is not on a CoW filesystem")
        self.assertFalse(fin.call_args.kwargs.get("optimize"))
        self.check_updated(stats)

    def test_in_place_path_commits_once(self):
        with (
            mock.patch.object(indexer, "_clone", return_value=False),
            mock.patch.object(indexer, "finish", wraps=indexer.finish) as fin,
        ):
            stats = indexer.update()
        self.assertFalse(fin.call_args.kwargs.get("optimize"))
        self.check_updated(stats)

    def test_in_place_failure_leaves_the_db_untouched(self):
        before = self.dump()
        with (
            mock.patch.object(indexer, "_clone", return_value=False),
            mock.patch.object(indexer, "load_models", side_effect=RuntimeError("boom")),
            self.assertRaisesRegex(RuntimeError, "boom"),
        ):
            indexer.update()
        self.assertEqual(
            self.dump(), before
        )  # EPSS + fts renumber ran before the failure: rolled back
        self.assertFalse(self.db.with_name("crowbar.db-journal").exists())
        self.assertFalse(self.db.with_suffix(".db.tmp").exists())
        with mock.patch.object(indexer, "_clone", return_value=False):
            self.check_updated(
                indexer.update()
            )  # the next run succeeds on the same file


if __name__ == "__main__":
    unittest.main()
