"""Schema-v3 adapter tests: CVE List parsing, PoC join/dedupe, provenance.

Pure-fixture tests - no corpus, no network.  They cover the merge logic that
the audit flagged as untested: adapter parsing, idempotency, provenance rows,
orphan policy and deprecated-CWE stubs.
"""

from __future__ import annotations

import io
import json
import pathlib
import sqlite3
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from crowbar import indexer, intel  # noqa: E402

CVE_DOC = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.2",
    "cveMetadata": {
        "cveId": "CVE-2026-0001",
        "state": "PUBLISHED",
        "assignerShortName": "Example Vendor",
        "datePublished": "2026-09-08T14:18:57.227Z",
        "dateUpdated": "2026-09-08T14:36:37.191Z",
    },
    "containers": {
        "cna": {
            "title": "Widget overflow in the widget parser",
            "descriptions": [{"lang": "en", "value": "A heap overflow in the widget parser."}],
            "problemTypes": [{"descriptions": [{"lang": "en", "cweId": "CWE-787", "type": "CWE"}]}],
            "affected": [
                {
                    "vendor": "Example Vendor",
                    "product": "Widget",
                    "versions": [
                        {
                            "status": "affected",
                            "version": "1.0",
                            "lessThanOrEqual": "1.4.2",
                            "versionType": "semver",
                        }
                    ],
                },
            ],
            "references": [{"url": "https://example.invalid/advisory/1", "tags": ["Vendor Advisory"]}],
            "metrics": [
                {
                    "cvssV3_1": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ],
        }
    },
}

POC_REPOS = [
    {
        "id": 1,
        "full_name": "someone/CVE-2026-0001-poc",
        "html_url": "https://github.com/someone/CVE-2026-0001-poc",
        "stargazers_count": 12,
        "language": "Python",
        "created_at": "2026-09-09T00:00:00Z",
        "pushed_at": "2026-09-10T00:00:00Z",
        "description": "proof of concept",
    },
    {
        "id": 2,
        "full_name": "other/CVE-2026-0001",
        "html_url": "https://github.com/other/CVE-2026-0001",
        "stargazers_count": 3,
        "language": "C",
        "created_at": "2026-09-11T00:00:00Z",
        "pushed_at": "2026-09-12T00:00:00Z",
        "description": None,
    },
]


def _tarball(files: dict[str, object]) -> pathlib.Path:
    path = pathlib.Path(tempfile.mkdtemp(prefix="hv-v3-")) / "src.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for name, payload in files.items():
            data = json.dumps(payload).encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


class V3Case(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="hv-v3db-"))
        self.con = indexer.create(self.tmp / "t.db")
        self.con.row_factory = sqlite3.Row
        self.con.executescript(intel.V3_SCHEMA)

    def tearDown(self):
        self.con.close()


class TestParseCveorg(V3Case):
    def test_fields(self):
        p = intel.parse_cveorg(CVE_DOC)
        self.assertEqual(p["id"], "CVE-2026-0001")
        self.assertEqual(p["assigner"], "Example Vendor")
        self.assertEqual(p["state"], "PUBLISHED")
        self.assertEqual(p["cvss"], 9.8)
        self.assertEqual(p["severity"], "CRITICAL")
        self.assertEqual(p["cwes"], ["CWE-787"])
        self.assertEqual(p["products"], [("example vendor", "widget")])
        self.assertEqual(p["refs"], [("https://example.invalid/advisory/1", "Vendor Advisory")])

    def test_rejects_bad_id(self):
        doc = json.loads(json.dumps(CVE_DOC))
        doc["cveMetadata"]["cveId"] = "NOT-A-CVE"
        self.assertIsNone(intel.parse_cveorg(doc))

    def test_array_document(self):
        self.assertEqual(intel.parse_cveorg([CVE_DOC])["id"], "CVE-2026-0001")
        self.assertEqual(len(intel.iter_cveorg([CVE_DOC, CVE_DOC])), 2)

    def test_missing_description_falls_back_to_title(self):
        doc = json.loads(json.dumps(CVE_DOC))
        doc["containers"]["cna"].pop("descriptions")
        p = intel.parse_cveorg(doc)
        self.assertEqual(p["description"], "Widget overflow in the widget parser")


class TestLoadCveorg(V3Case):
    def setUp(self):
        super().setUp()
        self.tar = _tarball(
            {
                "cvelistV5-main/cves/2026/0xxx/CVE-2026-0001.json": CVE_DOC,
                "cvelistV5-main/cves/2026/0xxx/CVE-2026-0002.json": json.loads(
                    json.dumps(CVE_DOC).replace("CVE-2026-0001", "CVE-2026-0002")
                ),
            }
        )

    def test_inserts_missing_cve_only(self):
        n = intel.load_cveorg(self.tar, self.con)
        self.assertEqual(n, 2)
        self.assertEqual(self.con.execute("SELECT count(*) FROM cve").fetchone()[0], 2)
        self.assertEqual(self.con.execute("SELECT count(*) FROM cve_cna").fetchone()[0], 2)
        row = self.con.execute("SELECT * FROM cve WHERE id='CVE-2026-0001'").fetchone()
        self.assertEqual(row["status"], "Published")
        self.assertEqual(row["description"], "A heap overflow in the widget parser.")
        self.assertEqual(row["cvss"], 9.8)
        self.assertEqual(self.con.execute("SELECT count(*) FROM cve_fts").fetchone()[0], 2)

    def test_existing_nvd_row_is_not_overwritten(self):
        self.con.execute(
            "INSERT INTO cve(id,published,modified,status,description,cvss,cvss_version,"
            "cvss_vector,severity,kev,epss,epss_pct,year) "
            "VALUES ('CVE-2026-0001','2026-01-01','2026-01-02','Analyzed',"
            "'NVD description',5.0,'3.1','V','MEDIUM',0,0.1,10.0,2026)"
        )
        n = intel.load_cveorg(self.tar, self.con)
        self.assertEqual(n, 1)  # only CVE-2026-0002 is new
        row = self.con.execute("SELECT * FROM cve WHERE id='CVE-2026-0001'").fetchone()
        self.assertEqual(row["description"], "NVD description")
        self.assertEqual(row["cvss"], 5.0)
        self.assertEqual(row["severity"], "MEDIUM")
        cna = self.con.execute("SELECT * FROM cve_cna WHERE cve_id='CVE-2026-0001'").fetchone()
        self.assertEqual(cna["description"], "A heap overflow in the widget parser.")

    def test_idempotent(self):
        intel.load_cveorg(self.tar, self.con)
        first = {
            t: self.con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
            for t in ("cve", "cve_cna", "cve_cna_ref", "cve_cna_product", "cve_fts")
        }
        intel.load_cveorg(self.tar, self.con)
        second = {
            t: self.con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
            for t in ("cve", "cve_cna", "cve_cna_ref", "cve_cna_product", "cve_fts")
        }
        self.assertEqual(first, second)

    def test_cve_meta_years(self):
        intel.load_cveorg(self.tar, self.con)
        row = self.con.execute("SELECT * FROM cve_meta WHERE cve_id='CVE-2026-0001'").fetchone()
        self.assertEqual(row["cve_year"], 2026)
        self.assertEqual(row["published_year"], 2026)

    def test_rejected_records_do_not_become_cves(self):
        doc = json.loads(json.dumps(CVE_DOC))
        doc["cveMetadata"]["state"] = "REJECTED"
        tar = _tarball({"cvelistV5-main/cves/2026/0xxx/CVE-2026-0003.json": doc})
        n = intel.load_cveorg(tar, self.con)
        self.assertEqual(n, 0)
        self.assertEqual(self.con.execute("SELECT count(*) FROM cve").fetchone()[0], 0)
        self.assertEqual(self.con.execute("SELECT count(*) FROM cve_cna").fetchone()[0], 1)


class TestLoadPoc(V3Case):
    def setUp(self):
        super().setUp()
        self.tar = _tarball(
            {
                "PoC-in-GitHub-master/2026/CVE-2026-0001.json": POC_REPOS,
                "PoC-in-GitHub-master/2026/CVE-2099-9999.json": [POC_REPOS[0]],
            }
        )

    def test_repos_and_orphan(self):
        self.con.execute(
            "INSERT INTO cve(id,published,modified,status,description,cvss,cvss_version,"
            "cvss_vector,severity,kev,epss,epss_pct,year) "
            "VALUES ('CVE-2026-0001','2026-01-01','2026-01-02','Published','x',1.0,'3.1',"
            "'V','LOW',0,0.0,0.0,2026)"
        )
        self.con.execute(
            "INSERT INTO cve_meta(cve_id,published_year,cve_year) VALUES ('CVE-2026-0001',2026,2026)"
        )
        n = intel.load_poc_github(self.tar, self.con)
        self.assertEqual(n, 3)
        rows = self.con.execute("SELECT * FROM poc ORDER BY url").fetchall()
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["cve_id"], "CVE-2026-0001")
        self.assertEqual(self.con.execute("SELECT count(*) FROM poc_orphan").fetchone()[0], 1)
        orphan = self.con.execute("SELECT * FROM poc_orphan").fetchone()
        self.assertEqual(orphan["cve_id"], "CVE-2099-9999")
        meta = self.con.execute("SELECT * FROM cve_meta WHERE cve_id='CVE-2026-0001'").fetchone()
        self.assertEqual(meta["has_poc"], 1)
        self.assertEqual(meta["poc_count"], 2)

    def test_dedupe_by_url(self):
        self.con.execute(
            "INSERT INTO cve(id,published,modified,status,description,cvss,cvss_version,"
            "cvss_vector,severity,kev,epss,epss_pct,year) "
            "VALUES ('CVE-2026-0001','2026-01-01','2026-01-02','Published','x',1.0,'3.1',"
            "'V','LOW',0,0.0,0.0,2026)"
        )
        intel.load_poc_github(self.tar, self.con)
        intel.load_poc_github(self.tar, self.con)
        self.assertEqual(self.con.execute("SELECT count(*) FROM poc").fetchone()[0], 3)

    def test_no_code_is_executed(self):
        # The tarball payload is inert data; loading must not import or eval it.
        evil = _tarball(
            {
                "PoC-in-GitHub-master/2026/CVE-2026-0001.json": [
                    {
                        "html_url": "https://github.com/x/y",
                        "full_name": "x/y",
                        "description": "__import__('os').system('touch /tmp/hv-pwned')",
                    }
                ]
            }
        )
        intel.load_poc_github(evil, self.con)
        self.assertFalse(pathlib.Path("/tmp/hv-pwned").exists())


class TestProvenance(V3Case):
    def test_source_state_records_hash_and_license(self):
        path = _tarball({"cvelistV5-main/cves/2026/0xxx/CVE-2026-0001.json": CVE_DOC})
        intel.load_cveorg(path, self.con)
        row = self.con.execute("SELECT * FROM source_state WHERE source='cveorg-cvelist'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "loaded")
        self.assertEqual(row["license"], "MIT")
        self.assertTrue(row["sha256"])
        self.assertEqual(row["record_count"], 1)
        self.assertTrue(row["loaded_at"].endswith("Z"))

    def test_cna_row_carries_provenance(self):
        path = _tarball({"cvelistV5-main/cves/2026/0xxx/CVE-2026-0001.json": CVE_DOC})
        intel.load_cveorg(path, self.con)
        row = self.con.execute("SELECT * FROM cve_cna").fetchone()
        self.assertEqual(row["source"], "cveorg")
        self.assertTrue(row["source_url"].startswith("http"))
        self.assertTrue(row["source_sha256"])
        self.assertTrue(row["record_path"].endswith("CVE-2026-0001.json"))


class TestCweStubs(V3Case):
    def test_stub_created_for_missing_cwe(self):
        self.con.execute("INSERT INTO cve_cwe VALUES ('CVE-2026-0001','CWE-264')")
        self.con.execute(
            "INSERT INTO cwe(id,name,abstraction,status,description) "
            "VALUES ('CWE-502','Deserialization','Base','Stable','x')"
        )
        n = intel.stub_missing_cwes(self.con)
        self.assertEqual(n, 1)
        row = self.con.execute("SELECT * FROM cwe WHERE id='CWE-264'").fetchone()
        self.assertEqual(row["status"], "Deprecated")
        self.assertIn("CWE-264", row["name"])

    def test_stub_is_idempotent(self):
        self.con.execute("INSERT INTO cve_cwe VALUES ('CVE-2026-0001','CWE-264')")
        intel.stub_missing_cwes(self.con)
        self.assertEqual(intel.stub_missing_cwes(self.con), 0)
        self.assertEqual(self.con.execute("SELECT count(*) FROM cwe WHERE id='CWE-264'").fetchone()[0], 1)


class TestAliasPolicy(V3Case):
    def test_aliases_from_osv_only(self):
        self.con.execute(
            "INSERT INTO advisory(source,id,ecosystem,package,cve,summary,severity,published,"
            "modified,url,aliases,affected_count) VALUES "
            "('osv','GHSA-xxxx-yyyy-zzzz','npm','pkg','CVE-2026-0001','s','high','2026-01-01',"
            "'2026-01-02','https://osv.dev/x','GHSA-xxxx-yyyy-zzzz,CVE-2026-0001',1)"
        )
        n = intel.rebuild_aliases(self.con)
        self.assertEqual(n, 1)
        row = self.con.execute("SELECT * FROM cve_alias").fetchone()
        self.assertEqual(row["alias"], "GHSA-XXXX-YYYY-ZZZZ")
        self.assertEqual(row["source"], "osv")


if __name__ == "__main__":
    unittest.main()
