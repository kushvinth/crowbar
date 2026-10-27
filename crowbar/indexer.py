"""Build and update the crowbar SQLite index."""

from __future__ import annotations

import csv
import gzip
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile

from . import chatter, db, intel, loaders, paths
from .loaders import CVE_RE


SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE cve(
  id TEXT PRIMARY KEY,
  published TEXT, modified TEXT, status TEXT,
  description TEXT,
  cvss REAL, cvss_version TEXT, cvss_vector TEXT, severity TEXT,
  kev INTEGER DEFAULT 0, epss REAL, epss_pct REAL,
  has_exploit INTEGER DEFAULT 0, has_nuclei INTEGER DEFAULT 0, has_msf INTEGER DEFAULT 0,
  year INTEGER
);
-- Link tables are WITHOUT ROWID: the primary key is the table, not a second copy.
CREATE TABLE cve_cwe(cve_id TEXT, cwe TEXT, PRIMARY KEY(cve_id, cwe)) WITHOUT ROWID;
CREATE TABLE cve_product(
  cve_id TEXT, vendor TEXT, product TEXT, PRIMARY KEY(cve_id, vendor, product)
) WITHOUT ROWID;
-- WITHOUT ROWID key columns are NOT NULL, so an absent version bound is ''.
CREATE TABLE cpe_match(
  cve_id TEXT, part TEXT, vendor TEXT, product TEXT, version TEXT,
  v_start_incl TEXT, v_start_excl TEXT, v_end_incl TEXT, v_end_excl TEXT,
  PRIMARY KEY(cve_id, part, vendor, product, version,
              v_start_incl, v_start_excl, v_end_incl, v_end_excl)
) WITHOUT ROWID;
CREATE TABLE cve_ref(cve_id TEXT, url TEXT, tags TEXT, PRIMARY KEY(cve_id, url)) WITHOUT ROWID;
CREATE TABLE cve_exploit(cve_id TEXT, exploit_id TEXT, PRIMARY KEY(cve_id, exploit_id)) WITHOUT ROWID;
CREATE TABLE cve_nuclei(cve_id TEXT, template_id TEXT, PRIMARY KEY(cve_id, template_id)) WITHOUT ROWID;
CREATE TABLE cve_msf(cve_id TEXT, module_path TEXT, PRIMARY KEY(cve_id, module_path)) WITHOUT ROWID;

CREATE TABLE kev(
  cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT,
  date_added TEXT, ransomware TEXT, action TEXT, due TEXT, notes TEXT,
  epss REAL, epss_pct REAL
);
CREATE TABLE exploit(
  id TEXT PRIMARY KEY, file TEXT, description TEXT, date TEXT, author TEXT,
  type TEXT, platform TEXT, verified INTEGER, codes TEXT, tags TEXT, url TEXT, raw TEXT
);
CREATE TABLE shellcode(id TEXT PRIMARY KEY, file TEXT, description TEXT, date TEXT, platform TEXT, url TEXT);
CREATE TABLE nuclei(
  id TEXT PRIMARY KEY, name TEXT, severity TEXT, tags TEXT, cve TEXT,
  path TEXT, description TEXT, domain TEXT
);
CREATE TABLE msf(
  path TEXT PRIMARY KEY, type TEXT, name TEXT, platform TEXT,
  privileged INTEGER, disclosure_date TEXT, description TEXT, cves TEXT
);
CREATE TABLE attack(
  id TEXT, domain TEXT, name TEXT, tactics TEXT, platforms TEXT,
  description TEXT, url TEXT, PRIMARY KEY(id, domain)
);
CREATE TABLE cwe(id TEXT PRIMARY KEY, name TEXT, abstraction TEXT, status TEXT, description TEXT);
CREATE TABLE capec(id TEXT PRIMARY KEY, name TEXT, severity TEXT, likelihood TEXT, cwe TEXT, description TEXT);
CREATE TABLE model(
  provider TEXT, provider_name TEXT, id TEXT, name TEXT, context INTEGER,
  output_limit INTEGER, input_cost REAL, output_cost REAL, released TEXT,
  reasoning INTEGER, tool_call INTEGER, vision INTEGER,
  PRIMARY KEY(provider, id)
);
CREATE TABLE advisory(
  source TEXT, id TEXT, ecosystem TEXT, package TEXT, cve TEXT,
  summary TEXT, severity TEXT, published TEXT, modified TEXT, url TEXT,
  aliases TEXT, affected_count INTEGER,
  PRIMARY KEY(source, id)
);
CREATE TABLE package_range(
  advisory_id TEXT, ecosystem TEXT, package TEXT, introduced TEXT,
  fixed TEXT, last_affected TEXT, versions TEXT
);
CREATE TABLE debian(
  package TEXT, release TEXT, cve TEXT, status TEXT, fixed TEXT,
  urgency TEXT, description TEXT
);
CREATE TABLE os_advisory(
  source TEXT, cve TEXT, platform TEXT, product TEXT, version TEXT, title TEXT,
  severity TEXT, impact TEXT, exploited TEXT, released TEXT, url TEXT,
  PRIMARY KEY(source, cve, product, version)
);
CREATE VIRTUAL TABLE exploit_code_fts USING fts5(
  exploit_id UNINDEXED, path UNINDEXED, content, tokenize='porter unicode61'
);
CREATE TABLE toolkit(
  source TEXT, name TEXT, path TEXT, description TEXT, tags TEXT
);
CREATE VIRTUAL TABLE toolkit_fts USING fts5(
  source UNINDEXED, name, description, tags, tokenize='porter unicode61'
);
CREATE TABLE ssvc(
  cve_id TEXT PRIMARY KEY, exploitation TEXT, automatable TEXT,
  technical_impact TEXT, timestamp TEXT, source TEXT
);

-- Schema v3: CNA source of truth, PoC discovery, provenance.
CREATE TABLE cve_cna(
  cve_id TEXT PRIMARY KEY,
  assigner TEXT, state TEXT, published TEXT, updated TEXT,
  title TEXT, description TEXT,
  cvss REAL, cvss_version TEXT, cvss_vector TEXT, severity TEXT,
  record_path TEXT, source TEXT, source_url TEXT, source_sha256 TEXT, fetched_at TEXT
);
CREATE TABLE cve_cna_ref(
  cve_id TEXT, url TEXT, tags TEXT,
  PRIMARY KEY(cve_id, url)
) WITHOUT ROWID;
CREATE TABLE cve_cna_product(
  cve_id TEXT, vendor TEXT, product TEXT,
  PRIMARY KEY(cve_id, vendor, product)
) WITHOUT ROWID;
CREATE TABLE cve_meta(
  cve_id TEXT PRIMARY KEY,
  published_year INTEGER, cve_year INTEGER,
  has_poc INTEGER DEFAULT 0, poc_count INTEGER DEFAULT 0
);
CREATE TABLE poc(
  source TEXT, cve_id TEXT, repo TEXT, url TEXT, repo_id INTEGER,
  stars INTEGER, language TEXT, created_at TEXT, pushed_at TEXT,
  description TEXT, fetched_at TEXT,
  PRIMARY KEY(source, cve_id, url)
);
CREATE TABLE poc_orphan(cve_id TEXT PRIMARY KEY, count INTEGER);
CREATE TABLE cve_alias(
  cve_id TEXT, alias TEXT, source TEXT,
  PRIMARY KEY(cve_id, alias, source)
) WITHOUT ROWID;
CREATE TABLE source_state(
  source TEXT PRIMARY KEY, url TEXT, path TEXT, license TEXT, sha256 TEXT,
  fetched_at TEXT, loaded_at TEXT, record_count INTEGER, status TEXT, note TEXT
);

-- cve_fts.rowid = fts_rowid(id): deletes are rowid lookups (filtering the UNINDEXED id scans).
-- detail stays full: fts_query emits phrases ("1.18.0"*, "ms17_010"*) that detail=none/column reject.
CREATE VIRTUAL TABLE cve_fts USING fts5(
  id UNINDEXED, description, products, tokenize='porter unicode61', prefix='4 5 6'
);
CREATE VIRTUAL TABLE exploit_fts USING fts5(
  id UNINDEXED, description, tags, codes, tokenize='porter unicode61'
);
CREATE VIRTUAL TABLE nuclei_fts USING fts5(
  id, name, tags, cve, tokenize='porter unicode61'
);
CREATE VIRTUAL TABLE model_fts USING fts5(
  provider UNINDEXED, id UNINDEXED, name, tokenize='porter unicode61'
);
"""

# Loaders look these up while they insert, so they exist from create() on.
LOOKUP_INDEXES = """
CREATE INDEX IF NOT EXISTS pkg_adv ON package_range(advisory_id);
CREATE INDEX IF NOT EXISTS poc_cve ON poc(cve_id);
"""

# Query indexes, built after the bulk load. IF NOT EXISTS + RETIRED so update()
# brings indexes built by older versions up to date without a rebuild.
INDEXES = """
CREATE INDEX IF NOT EXISTS cve_published ON cve(published);
CREATE INDEX IF NOT EXISTS cve_modified ON cve(modified);
CREATE INDEX IF NOT EXISTS poc_created ON poc(created_at);
CREATE INDEX IF NOT EXISTS cve_kev_epss ON cve(kev, epss);
CREATE INDEX IF NOT EXISTS adv_pkg_eco ON advisory(package, ecosystem);
CREATE INDEX IF NOT EXISTS os_plat_rel ON os_advisory(platform, released);
CREATE INDEX IF NOT EXISTS os_released ON os_advisory(released);
CREATE INDEX IF NOT EXISTS cve_year ON cve(year);
CREATE INDEX IF NOT EXISTS cve_sev ON cve(severity);
CREATE INDEX IF NOT EXISTS cve_cvss ON cve(cvss);
CREATE INDEX IF NOT EXISTS cve_epss ON cve(epss);
CREATE INDEX IF NOT EXISTS cve_exploit_flag ON cve(has_exploit);
CREATE INDEX IF NOT EXISTS cve_nuclei_flag ON cve(has_nuclei);
CREATE INDEX IF NOT EXISTS cve_msf_flag ON cve(has_msf);
CREATE INDEX IF NOT EXISTS cve_cwe_cwe ON cve_cwe(cwe);
CREATE INDEX IF NOT EXISTS prod_product ON cve_product(product);
CREATE INDEX IF NOT EXISTS prod_vendor ON cve_product(vendor);
CREATE INDEX IF NOT EXISTS cpe_product ON cpe_match(product);
CREATE INDEX IF NOT EXISTS cpe_vendor ON cpe_match(vendor);
CREATE INDEX IF NOT EXISTS exp_date ON exploit(date);
CREATE INDEX IF NOT EXISTS exp_platform ON exploit(platform);
CREATE INDEX IF NOT EXISTS nuc_cve ON nuclei(cve);
CREATE INDEX IF NOT EXISTS nuc_sev ON nuclei(severity);
CREATE INDEX IF NOT EXISTS nuc_domain ON nuclei(domain);
CREATE INDEX IF NOT EXISTS kev_date ON kev(date_added);
CREATE INDEX IF NOT EXISTS ssvc_expl ON ssvc(exploitation);
CREATE INDEX IF NOT EXISTS adv_cve ON advisory(cve);
CREATE INDEX IF NOT EXISTS adv_eco ON advisory(ecosystem);
CREATE INDEX IF NOT EXISTS pkg_pkg ON package_range(package);
CREATE INDEX IF NOT EXISTS debian_pkg ON debian(package);
CREATE INDEX IF NOT EXISTS debian_cve ON debian(cve);
CREATE INDEX IF NOT EXISTS os_cve ON os_advisory(cve);
CREATE INDEX IF NOT EXISTS cve_cna_assigner ON cve_cna(assigner);
CREATE INDEX IF NOT EXISTS cve_meta_pubyear ON cve_meta(published_year);
CREATE INDEX IF NOT EXISTS cve_meta_cveyear ON cve_meta(cve_year);
CREATE INDEX IF NOT EXISTS cve_meta_poc ON cve_meta(has_poc);
CREATE INDEX IF NOT EXISTS poc_stars ON poc(stars);
CREATE INDEX IF NOT EXISTS cve_alias_alias ON cve_alias(alias);
DROP INDEX IF EXISTS adv_pkg;
DROP INDEX IF EXISTS cpe_id;
DROP INDEX IF EXISTS cve_cwe_id;
DROP INDEX IF EXISTS cve_kev;
DROP INDEX IF EXISTS cve_msf_id;
DROP INDEX IF EXISTS cve_nuclei_id;
DROP INDEX IF EXISTS kev_date_added;
DROP INDEX IF EXISTS os_plat;
DROP INDEX IF EXISTS poc_orphan_id;
DROP INDEX IF EXISTS prod_id;
DROP INDEX IF EXISTS ref_id;
DROP INDEX IF EXISTS source_state_status;
"""

BATCH = 800
# cve_fts.id is UNINDEXED: rows are addressed by a rowid derived from the CVE id instead
FTS_ROWID_SQL = "CAST(substr(id,5,4) AS INTEGER)*100000000 + CAST(substr(id,10) AS INTEGER)"


def fts_rowid(cid: str) -> int:
    """CVE-YYYY-N -> YYYY*1e8+N, the cve_fts rowid (same formula as FTS_ROWID_SQL)."""
    # shortcut: assumes a sequence below 1e8 (CVE ids have 4-7 digits today); widen the multiplier if that changes
    return int(cid[4:8]) * 100_000_000 + int(cid[9:])


def log(msg: str) -> None:
    print(f"[index] {msg}", flush=True)


def _norm(s: str | None, limit: int = 6000) -> str:
    return loaders.norm(s, limit)


# ---------------------------------------------------------------- NVD
def cpe_rows(cve: dict, cap: int = 400) -> list[tuple]:
    seen: set[tuple] = set()
    out: list[tuple] = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") is False:
                    continue
                parts = (m.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product = parts[3].lower(), parts[4].lower()
                if vendor in ("*", "-") or product in ("*", "-"):
                    continue
                row = (
                    parts[2],
                    vendor,
                    product,
                    parts[5],
                    m.get("versionStartIncluding") or "",
                    m.get("versionStartExcluding") or "",
                    m.get("versionEndIncluding") or "",
                    m.get("versionEndExcluding") or "",
                )
                if row in seen:
                    continue
                seen.add(row)
                out.append(row)
                if len(out) >= cap:
                    return out
    return out


def cvss_of(metrics: dict) -> tuple[float | None, str, str, str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for e in metrics.get(key) or []:
            data = e.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            try:
                score = float(score)
            except (TypeError, ValueError):
                continue  # one malformed metric must not abort the whole feed
            sev = data.get("baseSeverity") or e.get("baseSeverity") or ""
            return (score, data.get("version") or key[-3:], data.get("vectorString") or "", sev.upper())
    return (None, "", "", "")


def parse_cve(item: dict, epss: dict, kev_ids: set[str]) -> dict:
    c = item.get("cve") or {}
    cid = c.get("id")
    if not cid:
        return {}
    desc = ""
    for d in c.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break
    score, ver, vec, sev = cvss_of(c.get("metrics") or {})
    e, pct = epss.get(cid, (None, None))
    cwes, seen = [], set()
    for w in c.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = (d.get("value") or "").upper()
            if v.startswith("CWE-") and v not in seen:
                seen.add(v)
                cwes.append(v)
    cpes = cpe_rows(c)
    prods = []
    seen_p = set()
    for _, vendor, product, *_ in cpes:
        if (vendor, product) not in seen_p and len(prods) < 120:
            seen_p.add((vendor, product))
            prods.append((vendor, product))
    refs = []
    seen_r = set()
    for r in (c.get("references") or [])[:60]:
        u = r.get("url")
        if u and u not in seen_r:
            seen_r.add(u)
            refs.append((u, ",".join(r.get("tags") or [])))
    pub = c.get("published") or ""
    return {
        "row": (
            cid,
            pub,
            c.get("lastModified"),
            c.get("vulnStatus"),
            _norm(desc),
            score,
            ver,
            vec,
            sev,
            1 if cid in kev_ids else 0,
            e,
            pct,
            int(pub[:4]) if pub[:4].isdigit() else None,
        ),
        "cwes": [(cid, w) for w in cwes],
        "prods": [(cid, v, p) for v, p in prods],
        "cpes": [(cid, *r) for r in cpes],
        "refs": [(cid, u, t) for u, t in refs],
        "fts": (cid, _norm(desc, 4000), " ".join(f"{v} {p}" for v, p in prods)[:4000]),
    }


def delete_cves(con: sqlite3.Connection, ids: list[str]) -> None:
    # an index built before fts_rowid (see migrate_fts_rowids) still addresses cve_fts by id
    by_rowid = con.execute("SELECT 1 FROM meta WHERE key='fts_rowid'").fetchone() is not None
    for i in range(0, len(ids), BATCH):
        chunk = ids[i : i + BATCH]
        q = ",".join("?" * len(chunk))
        # cve_exploit/cve_nuclei/cve_msf come from other sources; an NVD re-load keeps them
        for table in ("cve_cwe", "cve_product", "cpe_match", "cve_ref"):
            con.execute(f"DELETE FROM {table} WHERE cve_id IN ({q})", chunk)
        con.execute(f"DELETE FROM cve WHERE id IN ({q})", chunk)
        if by_rowid:
            con.execute(f"DELETE FROM cve_fts WHERE rowid IN ({q})", [fts_rowid(c) for c in chunk])
        else:
            con.execute(f"DELETE FROM cve_fts WHERE id IN ({q})", chunk)


def migrate_fts_rowids(con: sqlite3.Connection) -> bool:
    """One-off renumber of cve_fts so delete_cves can address rows by rowid."""
    if con.execute("SELECT 1 FROM meta WHERE key='fts_rowid'").fetchone() is not None:
        return False
    # bare columns follow max(rowid): a duplicated id keeps its newest row
    con.execute(
        "CREATE TEMP TABLE _fts_tmp AS SELECT id, description, products, max(rowid) FROM cve_fts GROUP BY id"
    )
    # FTS5 has no fast truncate for a content-bearing table: drop and recreate it
    ddl = con.execute("SELECT sql FROM sqlite_master WHERE name='cve_fts'").fetchone()[0]
    con.execute("DROP TABLE cve_fts")
    con.execute(ddl)
    con.execute(
        "INSERT OR REPLACE INTO cve_fts(rowid, id, description, products) "
        f"SELECT {FTS_ROWID_SQL}, id, description, products FROM _fts_tmp"
    )
    con.execute("DROP TABLE _fts_tmp")
    con.execute("INSERT OR REPLACE INTO meta VALUES ('fts_rowid', '1')")
    con.commit()
    return True


def load_nvd(
    path: pathlib.Path,
    con: sqlite3.Connection,
    epss: dict,
    kev_ids: set[str],
    replace: bool = False,
    progress=None,
) -> int:
    if not path.exists():
        return 0
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        doc = json.load(fh)
    items = doc.get("vulnerabilities", [])
    if replace:
        ids = [(i.get("cve") or {}).get("id") for i in items]
        delete_cves(con, [i for i in ids if i])

    rows, cwes, prods, cpes, refs, fts = [], [], [], [], [], []
    for item in items:
        p = parse_cve(item, epss, kev_ids)
        if not p:
            continue
        rows.append(p["row"])
        cwes += p["cwes"]
        prods += p["prods"]
        cpes += p["cpes"]
        refs += p["refs"]
        fts.append(p["fts"])
        if len(rows) >= BATCH:
            done = len(fts)
            _flush(con, rows, cwes, prods, cpes, refs, fts)
            rows, cwes, prods, cpes, refs, fts = [], [], [], [], [], []
            if progress:
                progress(f"{done} rows")
    _flush(con, rows, cwes, prods, cpes, refs, fts)
    con.commit()
    return len(items)


def _flush(con, rows, cwes, prods, cpes, refs, fts) -> None:
    if rows:
        con.executemany(
            "INSERT OR REPLACE INTO cve(id,published,modified,status,description,cvss,"
            "cvss_version,cvss_vector,severity,kev,epss,epss_pct,year) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    if cwes:
        con.executemany("INSERT OR IGNORE INTO cve_cwe VALUES (?,?)", cwes)
    if prods:
        con.executemany("INSERT OR IGNORE INTO cve_product VALUES (?,?,?)", prods)
    if cpes:
        con.executemany("INSERT OR IGNORE INTO cpe_match VALUES (?,?,?,?,?,?,?,?,?)", cpes)
    if refs:
        con.executemany("INSERT OR IGNORE INTO cve_ref VALUES (?,?,?)", refs)
    if fts:
        con.executemany(
            "INSERT OR REPLACE INTO cve_fts(rowid, id, description, products) VALUES (?,?,?,?)",
            [(fts_rowid(r[0]), *r) for r in fts],
        )


# ---------------------------------------------------------------- intel
def load_kev(path: pathlib.Path, con: sqlite3.Connection, epss: dict | None = None) -> int:
    if not path.exists():
        return 0
    doc = json.loads(path.read_text())
    # indexes built before KEV carried EPSS: add the columns in place, no rebuild
    have = {r[1] for r in con.execute("PRAGMA table_info(kev)")}
    for col in ("epss", "epss_pct"):
        if col not in have:
            con.execute(f"ALTER TABLE kev ADD COLUMN {col} REAL")
    epss = epss or {}
    con.execute("DELETE FROM kev")
    rows = [
        (
            v.get("cveID"),
            v.get("vendorProject"),
            v.get("product"),
            v.get("vulnerabilityName"),
            v.get("dateAdded"),
            v.get("knownRansomwareCampaignUse"),
            v.get("requiredAction"),
            v.get("dueDate"),
            _norm(v.get("notes"), 1000),
            *epss.get(v.get("cveID"), (None, None)),
        )
        for v in doc.get("vulnerabilities", [])
    ]
    con.executemany(
        "INSERT OR REPLACE INTO kev(cve,vendor,product,name,date_added,ransomware,"
        "action,due,notes,epss,epss_pct) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    con.execute("UPDATE cve SET kev=0 WHERE kev=1 AND id NOT IN (SELECT cve FROM kev)")
    con.execute("UPDATE cve SET kev=1 WHERE id IN (SELECT cve FROM kev)")
    con.commit()
    return len(rows)


def read_epss(path: pathlib.Path) -> dict[str, tuple[float, float]]:
    out: dict[str, tuple[float, float]] = {}
    if not path.exists():
        return out
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", errors="replace") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or row[0].lower() == "cve":
                continue
            if len(row) >= 3:
                try:
                    out[row[0].upper()] = (float(row[1]), float(row[2]))
                except ValueError:
                    continue
    return out


def apply_epss(con: sqlite3.Connection, epss: dict) -> int:
    """Today's EPSS onto every CVE, not only the ones NVD re-sent."""
    if not epss:
        return 0
    con.execute("CREATE TEMP TABLE IF NOT EXISTS _epss_tmp(cve TEXT PRIMARY KEY, epss REAL, pct REAL)")
    con.execute("DELETE FROM _epss_tmp")
    con.executemany(
        "INSERT OR REPLACE INTO _epss_tmp VALUES (?,?,?)", [(k, v[0], v[1]) for k, v in epss.items()]
    )
    # only rows whose score moved, so a daily update does not rewrite every cve page
    con.execute(
        "UPDATE cve SET epss=t.epss, epss_pct=t.pct FROM _epss_tmp t WHERE t.cve=cve.id "
        "AND (cve.epss IS NOT t.epss OR cve.epss_pct IS NOT t.pct)"
    )
    con.execute("DROP TABLE _epss_tmp")
    return len(epss)


def load_exploitdb(path: pathlib.Path, con: sqlite3.Connection) -> int:
    if not path.exists():
        return 0
    con.execute("DELETE FROM exploit")
    con.execute("DELETE FROM exploit_fts")
    rows, fts = [], []
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            rid = (r.get("id") or "").strip()
            if not rid:
                continue
            desc = _norm(r.get("description"), 500)
            tags = (r.get("tags") or "").strip()
            codes = (r.get("codes") or "").strip()
            file = (r.get("file") or "").strip()
            rows.append(
                (
                    rid,
                    file,
                    desc,
                    r.get("date_published"),
                    r.get("author"),
                    r.get("type"),
                    r.get("platform"),
                    1 if (r.get("verified") or "0").strip() in ("1", "true", "True") else 0,
                    codes,
                    tags,
                    f"https://www.exploit-db.com/exploits/{rid}",
                    f"https://gitlab.com/exploit-database/exploitdb/-/raw/main/{file}",
                )
            )
            fts.append((rid, desc, tags, codes))
    # Exploit-DB occasionally lists the same id twice; keep one row and one FTS row.
    seen, urows, ufts = set(), [], []
    for row, frow in zip(rows, fts):
        if row[0] in seen:
            continue
        seen.add(row[0])
        urows.append(row)
        ufts.append(frow)
    con.executemany("INSERT OR REPLACE INTO exploit VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", urows)
    con.executemany("INSERT INTO exploit_fts(id, description, tags, codes) VALUES (?,?,?,?)", ufts)
    con.commit()
    return len(rows)


def load_shellcodes(path: pathlib.Path, con: sqlite3.Connection) -> int:
    if not path.exists():
        return 0
    con.execute("DELETE FROM shellcode")
    rows = []
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            rid = (r.get("id") or "").strip()
            if rid:
                rows.append(
                    (
                        rid,
                        r.get("file"),
                        _norm(r.get("description"), 300),
                        r.get("date_published"),
                        r.get("platform"),
                        f"https://www.exploit-db.com/shellcodes/{rid}",
                    )
                )
    con.executemany("INSERT OR REPLACE INTO shellcode VALUES (?,?,?,?,?,?)", rows)
    con.commit()
    return len(rows)


def link_exploits(con: sqlite3.Connection) -> int:
    pairs = []
    for rid, codes in con.execute("SELECT id, codes FROM exploit WHERE codes <> ''"):
        for cid in set(x.upper() for x in CVE_RE.findall(codes)):
            pairs.append((cid, rid))
    con.execute("DELETE FROM cve_exploit")
    con.executemany("INSERT OR IGNORE INTO cve_exploit VALUES (?,?)", pairs)
    con.execute("UPDATE cve SET has_exploit=0 WHERE has_exploit=1")
    con.execute("UPDATE cve SET has_exploit=1 WHERE id IN (SELECT cve_id FROM cve_exploit)")
    con.commit()
    return len(pairs)


NUCLEI_SKIP = {"workflows", "helpers", "profiles", "templates", ".github", "docs"}


def _block_value(lines: list[str], start: int, indent: int) -> str:
    out = []
    for ln in lines[start + 1 :]:
        if not ln.strip():
            continue
        if len(ln) - len(ln.lstrip()) <= indent:
            break
        out.append(ln.strip())
    return " ".join(out)


def parse_nuclei(text: str) -> dict:
    info = {"id": "", "name": "", "severity": "", "tags": "", "cve": "", "description": ""}
    in_info, in_class = False, False
    for i, ln in enumerate(text.splitlines()[:400]):
        s = ln.strip()
        ind = len(ln) - len(ln.lstrip())
        if ind == 0 and s.startswith("id:"):
            info["id"] = s.split(":", 1)[1].strip().strip("'\"")
        elif ind == 0 and s.startswith("info:"):
            in_info = True
            continue
        elif ind == 0 and s and not s.startswith("#"):
            in_info = False
        if not in_info:
            continue
        if s.startswith("name:") and not info["name"]:
            info["name"] = s.split(":", 1)[1].strip().strip("'\"")
        elif s.startswith("severity:") and not info["severity"]:
            info["severity"] = s.split(":", 1)[1].strip().strip("'\"")
        elif s.startswith("tags:") and not info["tags"]:
            info["tags"] = s.split(":", 1)[1].strip().strip("'\"")
        elif s.startswith("description:") and not info["description"]:
            rest = s.split(":", 1)[1].strip()
            info["description"] = _norm(
                rest if rest not in ("|", ">", "|-", ">-") else _block_value(text.splitlines(), i, ind), 800
            )
        elif s.startswith("classification:"):
            in_class = True
        elif in_class and s.startswith("cve-id:"):
            rest = s.split(":", 1)[1].strip()
            if rest.startswith("["):
                info["cve"] = ",".join(CVE_RE.findall(rest.upper()))
            elif rest:
                info["cve"] = rest.strip("'\"").upper()
            else:
                got = []
                for nxt in text.splitlines()[i + 1 : i + 12]:
                    m = re.match(r"\s*-\s*(CVE-\d{4}-\d+)", nxt, re.I)
                    if m:
                        got.append(m.group(1).upper())
                    elif nxt.strip() and not nxt.strip().startswith("-"):
                        break
                info["cve"] = ",".join(got)
    return info


def load_nuclei(root: pathlib.Path, con: sqlite3.Connection) -> int:
    if not root.exists():
        return 0
    con.execute("DELETE FROM nuclei")
    con.execute("DELETE FROM nuclei_fts")
    rows, fts = [], []
    for p in root.rglob("*.y*ml"):
        rel = p.relative_to(root)
        if not rel.parts or rel.parts[0] in NUCLEI_SKIP:
            continue
        if p.stat().st_size > 400_000:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "id:" not in text[:2000]:
            continue
        info = parse_nuclei(text)
        if not info["id"] or not info["name"]:
            continue
        domain = rel.parts[1 if len(rel.parts) > 2 else 0]
        rows.append(
            (
                info["id"],
                info["name"],
                info["severity"].lower(),
                info["tags"],
                info["cve"],
                str(rel),
                info["description"],
                domain,
            )
        )
        fts.append((info["id"], info["name"], info["tags"], info["cve"]))
    con.executemany("INSERT OR REPLACE INTO nuclei VALUES (?,?,?,?,?,?,?,?)", rows)
    con.executemany("INSERT INTO nuclei_fts(id, name, tags, cve) VALUES (?,?,?,?)", fts)
    pair = []
    for tid, cves in con.execute("SELECT id, cve FROM nuclei WHERE cve <> ''"):
        for cid in set(cves.upper().split(",")):
            if CVE_RE.fullmatch(cid):
                pair.append((cid, tid))
    con.execute("DELETE FROM cve_nuclei")
    con.executemany("INSERT OR IGNORE INTO cve_nuclei VALUES (?,?)", pair)
    con.execute("UPDATE cve SET has_nuclei=0 WHERE has_nuclei=1")
    con.execute("UPDATE cve SET has_nuclei=1 WHERE id IN (SELECT cve_id FROM cve_nuclei)")
    con.commit()
    return len(rows)


def load_msf(tree: pathlib.Path, con: sqlite3.Connection) -> int:
    if not tree.exists():
        return 0
    con.execute("DELETE FROM msf")
    rows = []
    for ent in json.loads(tree.read_text()).get("tree", []):
        p = ent.get("path") or ""
        if not p.startswith("modules/") or not p.endswith(".rb"):
            continue
        parts = p.split("/")
        if len(parts) < 3:
            continue
        cves = ",".join(sorted({c.upper() for c in CVE_RE.findall(p)}))
        rows.append((p, parts[1], "/".join(parts[2:]).removesuffix(".rb"), "", 0, "", "", cves))
    con.executemany(
        "INSERT OR REPLACE INTO msf(path,type,name,platform,privileged,"
        "disclosure_date,description,cves) VALUES (?,?,?,?,?,?,?,?)",
        rows,
    )
    pairs = []
    for p, name in con.execute("SELECT path, name FROM msf"):
        for cid in set(x.upper() for x in CVE_RE.findall(f"{p} {name}")):
            pairs.append((cid, p))
    con.execute("DELETE FROM cve_msf")
    con.executemany("INSERT OR IGNORE INTO cve_msf VALUES (?,?)", pairs)
    con.execute("UPDATE cve SET has_msf=0 WHERE has_msf=1")
    con.execute("UPDATE cve SET has_msf=1 WHERE id IN (SELECT cve_id FROM cve_msf)")
    con.commit()
    return len(rows)


def load_attack(path: pathlib.Path, domain: str, con: sqlite3.Connection) -> int:
    if not path.exists():
        return 0
    rows = []
    for obj in json.loads(path.read_text()).get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = ""
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                ext = ref.get("external_id") or ""
        if not ext:
            continue
        tactics = ",".join(p.get("phase_name", "") for p in obj.get("kill_chain_phases") or [])
        rows.append(
            (
                ext,
                domain,
                obj.get("name"),
                tactics,
                ",".join(obj.get("x_mitre_platforms") or []),
                _norm(obj.get("description"), 3000),
                f"https://attack.mitre.org/techniques/{ext.replace('.', '/')}/",
            )
        )
    con.execute("DELETE FROM attack WHERE domain=?", (domain,))
    con.executemany("INSERT OR REPLACE INTO attack VALUES (?,?,?,?,?,?,?)", rows)
    con.commit()
    return len(rows)


def _text(el) -> str:
    return _norm(" ".join("".join(el.itertext()).split()), 4000)


def load_cwe(path: pathlib.Path, con: sqlite3.Connection) -> int:
    if not path.exists():
        return 0
    zf = zipfile.ZipFile(path)
    xml = zf.read(next(n for n in zf.namelist() if n.endswith(".xml")))
    root = ET.fromstring(xml)
    rows = []
    for el in root.iter():
        if not el.tag.endswith("Weakness") or not el.get("ID"):
            continue
        desc = next((_text(c) for c in el if c.tag.endswith("Description")), "")
        rows.append(("CWE-" + el.attrib["ID"], el.get("Name"), el.get("Abstraction"), el.get("Status"), desc))
    con.execute("DELETE FROM cwe")
    con.executemany("INSERT OR REPLACE INTO cwe VALUES (?,?,?,?,?)", rows)
    con.commit()
    return len(rows)


def load_capec(path: pathlib.Path, con: sqlite3.Connection) -> int:
    if not path.exists():
        return 0
    root = ET.parse(path).getroot()
    rows = []
    for el in root.iter():
        if not el.tag.endswith("Attack_Pattern") or not el.get("ID"):
            continue
        desc, cwes = "", []
        for child in el:
            tag = child.tag.split("}")[-1]
            if tag == "Description":
                desc = _text(child)
            elif tag == "Related_Weaknesses":
                cwes += ["CWE-" + w.attrib["CWE_ID"] for w in child if w.get("CWE_ID")]
        rows.append(
            (
                "CAPEC-" + el.attrib["ID"],
                el.get("Name"),
                el.get("Severity"),
                el.get("Likelihood_Of_Attack"),
                ",".join(sorted(set(cwes))),
                desc,
            )
        )
    con.execute("DELETE FROM capec")
    con.executemany("INSERT OR REPLACE INTO capec VALUES (?,?,?,?,?,?)", rows)
    con.commit()
    return len(rows)


def load_models(path: pathlib.Path, con: sqlite3.Connection) -> int:
    if not path.exists():
        return 0
    doc = json.loads(path.read_text())
    rows, fts = [], []
    for pid, prov in doc.items():
        pname = prov.get("name") or pid
        for mid, m in (prov.get("models") or {}).items():
            cost, limit = m.get("cost") or {}, m.get("limit") or {}
            modality = m.get("modalities") or {}
            rows.append(
                (
                    pid,
                    pname,
                    mid,
                    m.get("name") or mid,
                    limit.get("context"),
                    limit.get("output"),
                    cost.get("input"),
                    cost.get("output"),
                    str(m.get("release_date") or ""),
                    1 if m.get("reasoning") else 0,
                    1 if m.get("tool_call") else 0,
                    1 if "image" in (modality.get("input") or []) else 0,
                )
            )
            fts.append((pid, mid, f"{m.get('name') or mid} {pid} {pname}"))
    con.execute("DELETE FROM model")
    con.execute("DELETE FROM model_fts")
    con.executemany("INSERT OR REPLACE INTO model VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    con.executemany("INSERT INTO model_fts(provider, id, name) VALUES (?,?,?)", fts)
    con.commit()
    return len(rows)


def load_ssvc(root: pathlib.Path, con: sqlite3.Connection) -> int:
    """CISA Vulnrichment: SSVC decision points (Exploitation/Automatable/Technical Impact)."""
    if not root.exists():
        return 0
    rows = []
    for p in root.rglob("CVE-*.json"):
        try:
            doc = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        cid = (doc.get("cveMetadata") or {}).get("cveId")
        if not cid:
            continue
        for adp in (doc.get("containers") or {}).get("adp") or []:
            for metric in adp.get("metrics") or []:
                other = metric.get("other") or {}
                if other.get("type") != "ssvc":
                    continue
                content = other.get("content") or {}
                opts = {}
                for o in content.get("options") or []:
                    if isinstance(o, dict):
                        opts.update(o)
                rows.append(
                    (
                        cid,
                        opts.get("Exploitation"),
                        opts.get("Automatable"),
                        opts.get("Technical Impact"),
                        content.get("timestamp"),
                        "CISA-ADP",
                    )
                )
    if rows:
        con.execute("DELETE FROM ssvc")
        con.executemany("INSERT OR REPLACE INTO ssvc VALUES (?,?,?,?,?,?)", rows)
        con.commit()
    return len(rows)


# ---------------------------------------------------------------- build/update
def create(path: pathlib.Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.executescript(
        "PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF; PRAGMA temp_store=MEMORY;"
        "PRAGMA cache_size=-1048576; PRAGMA threads=4;"
    )
    con.executescript(SCHEMA + chatter.SCHEMA + LOOKUP_INDEXES)
    return con


def finish(con: sqlite3.Connection, optimize: bool = False) -> None:
    """Indexes and planner stats before every swap; FTS optimize (a full rewrite) only on build."""
    con.executescript(INDEXES)
    for fts in ("cve_fts", "exploit_fts", "exploit_code_fts", "nuclei_fts") if optimize else ():
        con.execute(f"INSERT INTO {fts}({fts}) VALUES('optimize')")
    con.execute("PRAGMA analysis_limit=1000")
    con.execute("ANALYZE")
    con.commit()


def _clone(src: pathlib.Path, dst: pathlib.Path) -> bool:
    """Copy-on-write clone (APFS, btrfs, XFS): instant and free. False where the filesystem
    cannot clone (exFAT USB, Windows); update() then works on the live DB instead."""
    try:
        if sys.platform == "darwin":  # cp -c silently falls back to a full copy: ask clonefile(2)
            import ctypes

            ok = ctypes.CDLL(None).clonefile(os.fsencode(src), os.fsencode(dst), 0) == 0
        else:
            ok = (
                subprocess.run(["cp", "--reflink=always", str(src), str(dst)], capture_output=True).returncode
                == 0
            )
    except (OSError, AttributeError):  # no cp (Windows), no clonefile
        ok = False
    if not ok:
        dst.unlink(missing_ok=True)
    return ok


class _OneTxn:
    """Routes a loader's calls into one open transaction: commit() waits for the end and
    executescript() (an implicit COMMIT in sqlite3) runs its statements one by one."""

    def __init__(self, con: sqlite3.Connection):
        self._con = con

    def __getattr__(self, name):
        return getattr(self._con, name)

    def commit(self) -> None:
        pass

    def executescript(self, script: str) -> None:
        buf = ""
        for part in script.split(";"):
            buf += part + ";"
            if sqlite3.complete_statement(buf):
                self._con.execute(buf)
                buf = ""
        if buf.strip(" \t\n;"):  # last statement without its semicolon
            self._con.execute(buf)


def _fsync(path: pathlib.Path) -> None:
    """synchronous=OFF skipped every flush; make the file durable before it goes live."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_bulk(con: sqlite3.Connection, progress=None, heavy: bool = True) -> dict:
    """Load every bulk corpus that is present on disk. Missing dirs are skipped."""
    counts: dict[str, int] = {}
    if heavy:
        for z in sorted((paths.DATA / "osv").glob("*.zip")):
            n = loaders.load_osv_zip(z, con)
            counts[f"osv-{z.stem}"] = n
            if progress:
                progress(f"OSV {z.stem}: {n}")

    if (paths.DATA / "debian/tracker.json").exists():
        counts["debian"] = loaders.load_debian(paths.DATA / "debian/tracker.json", con)
        if progress:
            progress(f"Debian {counts['debian']}")

    if (paths.DATA / "msrc/sug.json").exists():
        counts["msrc"] = loaders.load_msrc(paths.DATA / "msrc/sug.json", con)
        if progress:
            progress(f"MSRC {counts['msrc']}")

    if (paths.DATA / "apple").exists():
        counts["apple"] = loaders.load_apple(paths.DATA / "apple", con)
        if progress:
            progress(f"Apple {counts['apple']}")

    for src in ("gtfobins", "lolbas", "payloads"):
        root = paths.DATA / "toolkit" / src
        if root.exists():
            counts[src] = loaders.load_toolkit(root, src, con)
            if progress:
                progress(f"{src} {counts[src]}")

    src = paths.DATA / "metasploit/source"
    if (src / "modules").exists():
        counts["msf-source"] = loaders.load_msf_source(src, con)
        if progress:
            progress(f"Metasploit source {counts['msf-source']}")

    if (paths.DATA / "exploitdb/full/exploits").exists() and heavy:
        counts["exploit-code"] = loaders.load_exploit_code(paths.DATA / "exploitdb/full", con)
        if progress:
            progress(f"Exploit-DB code {counts['exploit-code']} files")
    return counts


def build(quick: bool = False, with_extra: bool = False, with_bulk: bool = False, progress=None) -> dict:
    t0 = time.time()
    paths.ensure_dirs()
    tmp = paths.DB.with_suffix(".db.tmp")
    if tmp.exists():
        tmp.unlink()
    con = create(tmp)

    epss = read_epss(paths.DATA / "epss/epss_scores-current.csv.gz")
    if progress:
        progress(f"EPSS {len(epss)}")
    kev_path = paths.DATA / "kev/known_exploited_vulnerabilities.json"
    n = load_kev(kev_path, con, epss)
    if progress:
        progress(f"KEV {n}")
    kev_ids = {r[0] for r in con.execute("SELECT cve FROM kev")}

    total = 0
    for y in paths.YEARS:
        p = paths.DATA / f"nvd/nvdcve-2.0-{y}.json.gz"
        if not p.exists():
            continue
        n = load_nvd(p, con, epss, kev_ids)
        total += n
        if progress:
            progress(f"NVD {y}: {n} ({total})")

    intel.load_all(con, epss=epss, kev_ids=kev_ids, progress=progress)

    n = load_exploitdb(paths.DATA / "exploitdb/files_exploits.csv", con)
    load_shellcodes(paths.DATA / "exploitdb/files_shellcodes.csv", con)
    if progress:
        progress(f"Exploit-DB {n}")
    if progress:
        progress(f"exploit links {link_exploits(con)}")

    if not quick:
        n = load_nuclei(paths.DATA / "nuclei/templates", con)
        if progress:
            progress(f"Nuclei {n}")
        if not (paths.DATA / "metasploit/source/modules").exists():
            n = load_msf(paths.DATA / "metasploit/tree.json", con)
            if progress:
                progress(f"Metasploit {n}")
        load_attack(paths.DATA / "attack/enterprise-attack.json", "enterprise", con)
        for extra in ("mobile", "ics"):
            load_attack(paths.DATA / f"attack/{extra}-attack.json", extra, con)
        if progress:
            progress(f"ATT&CK {con.execute('SELECT count(*) FROM attack').fetchone()[0]}")

    load_cwe(paths.DATA / "cwe/cwec_latest.xml.zip", con)
    load_capec(paths.DATA / "capec/capec_latest.xml", con)
    load_models(paths.DATA / "models/models.dev.json", con)
    if progress:
        progress(f"mentions {chatter.load(con)}")
    if with_extra or (paths.DATA / "vulnrichment").exists():
        n = load_ssvc(paths.DATA / "vulnrichment", con)
        if progress:
            progress(f"SSVC {n}")
    if not quick:
        load_bulk(con, progress)

    intel.rebuild_cve_meta(con)
    intel.stub_missing_cwes(con)
    intel.rebuild_aliases(con)
    con.commit()
    finish(con, optimize=True)
    for k, v in (
        ("schema", str(paths.SCHEMA_VERSION)),
        ("fts_rowid", "1"),
        ("built_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        ("updated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
    ):
        con.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))
    con.commit()
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA temp_store=FILE")  # VACUUM's temp copy is DB-sized: keep it off RAM
    con.execute("VACUUM")
    con.close()
    _fsync(tmp)
    tmp.replace(paths.DB)

    stats = summarize()
    stats["build_seconds"] = round(time.time() - t0, 1)
    _write_stats(stats)
    paths.save_state(schema=paths.SCHEMA_VERSION)
    return stats


def update(deep: bool = False, progress=None) -> dict:
    """Apply the NVD `modified` feed + refresh intel tables, then swap atomically.

    On a copy-on-write filesystem all work happens on a clone (``crowbar.db.tmp``) and only
    a complete run replaces the live index via ``os.replace``. Elsewhere (exFAT, USB) the
    live DB is updated inside one transaction: the rollback journal gives the same crash
    atomicity without a second copy, but once the changes outgrow the page cache SQLite takes
    an exclusive lock, so readers can wait for most of the run.
    """
    t0 = time.time()
    if not paths.DB.exists():
        raise FileNotFoundError(f"no index to update: {paths.DB} (run: crowbar build)")
    db.recover_journal(paths.DB)  # a leftover journal would make the read-only open fail
    live = sqlite3.connect(db.ro_uri(paths.DB), uri=True)
    try:
        schema = db.schema_version(live)
    finally:
        live.close()
    if schema != paths.SCHEMA_VERSION:
        # v4 recreated the link tables and realigned cve_fts rowids: nothing to migrate in place
        raise ValueError(f"index schema v{schema} needs a rebuild: run crowbar build")
    tmp = paths.DB.with_suffix(".db.tmp")
    tmp.unlink(missing_ok=True)
    cloned = _clone(paths.DB, tmp)
    con = sqlite3.connect(tmp if cloned else paths.DB, timeout=90)
    con.row_factory = sqlite3.Row
    if cloned:
        # the copy is thrown away on failure, so durability is only needed at the swap
        con.executescript(
            "PRAGMA synchronous=OFF; PRAGMA journal_mode=MEMORY; PRAGMA temp_store=MEMORY;"
            "PRAGMA cache_size=-262144;"
        )
    else:
        con.executescript("PRAGMA temp_store=MEMORY; PRAGMA cache_size=-262144;")
        con.isolation_level = None  # no implicit BEGIN/COMMIT: the transaction below is the only one
        con.execute("BEGIN IMMEDIATE")
        con = _OneTxn(con)
    try:
        if migrate_fts_rowids(con) and progress:
            progress("cve_fts renumbered")

        epss = read_epss(paths.DATA / "epss/epss_scores-current.csv.gz")
        if progress:
            progress(f"EPSS {len(epss)}")
        n = load_kev(paths.DATA / "kev/known_exploited_vulnerabilities.json", con, epss)
        if progress:
            progress(f"KEV {n}")
        kev_ids = {r[0] for r in con.execute("SELECT cve FROM kev")}

        changed = 0
        for feed in ("modified", "recent"):
            p = paths.DATA / f"nvd/nvdcve-2.0-{feed}.json.gz"
            if p.exists():
                changed += load_nvd(p, con, epss, kev_ids, replace=True)
        # INSERT OR REPLACE reset these flags on re-sent CVEs; the link tables still hold them
        con.execute(
            "UPDATE cve SET has_nuclei=1 WHERE has_nuclei=0 AND id IN (SELECT cve_id FROM cve_nuclei)"
        )
        con.execute("UPDATE cve SET has_msf=1 WHERE has_msf=0 AND id IN (SELECT cve_id FROM cve_msf)")
        apply_epss(con, epss)
        if progress:
            progress(f"CVE rows touched {changed}")

        intel.load_all(con, epss=epss, kev_ids=kev_ids, progress=progress)

        if paths.DATA.joinpath("exploitdb/files_exploits.csv").exists():
            load_exploitdb(paths.DATA / "exploitdb/files_exploits.csv", con)
            load_shellcodes(paths.DATA / "exploitdb/files_shellcodes.csv", con)
        link_exploits(con)
        if deep:
            load_nuclei(paths.DATA / "nuclei/templates", con)
            if not (paths.DATA / "metasploit/source/modules").exists():
                load_msf(paths.DATA / "metasploit/tree.json", con)
            for dom, f in (("enterprise", "enterprise"), ("mobile", "mobile"), ("ics", "ics")):
                load_attack(paths.DATA / f"attack/{f}-attack.json", dom, con)
            load_bulk(con, progress, heavy=False)
        load_models(paths.DATA / "models/models.dev.json", con)
        chatter.load(con)
        load_cwe(paths.DATA / "cwe/cwec_latest.xml.zip", con)
        load_capec(paths.DATA / "capec/capec_latest.xml", con)
        if (paths.DATA / "vulnrichment").exists():
            load_ssvc(paths.DATA / "vulnrichment", con)

        intel.rebuild_cve_meta(con)
        intel.stub_missing_cwes(con)
        intel.rebuild_aliases(con)
        con.executescript(LOOKUP_INDEXES)
        finish(con)

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        con.execute("INSERT OR REPLACE INTO meta VALUES ('updated_at', ?)", (now,))
        con.commit()
        stats = {
            "updated_at": now,
            "rows_touched": changed,
            "seconds": round(time.time() - t0, 1),
            "cve": con.execute("SELECT count(*) FROM cve").fetchone()[0],
        }
        if not cloned:
            con.execute("COMMIT")
        con.close()
    except BaseException:
        if not cloned and con.in_transaction:
            con.execute("ROLLBACK")
        con.close()
        tmp.unlink(missing_ok=True)
        raise
    if cloned:
        _fsync(tmp)
        tmp.replace(paths.DB)

    full = summarize()
    full.update(stats)
    _write_stats(full)
    return stats


def _write_stats(stats: dict) -> None:
    (paths.INDEX / "stats.json").write_text(json.dumps(stats, indent=2, default=str) + "\n")


def summarize() -> dict:
    con = sqlite3.connect(db.ro_uri(paths.DB), uri=True)
    out = db.counts(con)
    try:
        out.update(db.flag_counts(con))
    except sqlite3.DatabaseError:
        pass
    out["meta"] = db.meta(con)
    con.close()
    out["db_bytes"] = paths.DB.stat().st_size
    return out
