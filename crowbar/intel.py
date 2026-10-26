"""Schema-v3 intel adapters: CVE List v5, PoC-in-GitHub, provenance.

Everything here treats the downloaded archives as inert data.  No repository,
PoC, notebook, Makefile, or installer is executed.  Loaders are deterministic
and idempotent so an interrupted build/update can simply be run again.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
import tarfile
import time

from . import datasets, loaders, paths
from .loaders import CVE_RE

BATCH = 1500


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _norm(value: str | None, limit: int = 6000) -> str:
    return loaders.norm(value, limit)


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest() -> dict:
    p = paths.DATA / "intel" / "manifest.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text()).get("sources", {})
    except (OSError, json.JSONDecodeError):
        return {}


def source_meta(name: str, default_license: str = "", path: pathlib.Path | None = None) -> dict:
    # fetch_intel.py writes data/intel/manifest.json; `crowbar sync` writes index/manifest.json
    entry = _manifest().get(name) or datasets.load_manifest().get("datasets", {}).get(name, {})
    rel = entry.get("path", "")
    disk = path or ((paths.ROOT / rel) if rel else None)
    url = entry.get("url") or next((d.url for d in datasets.CORE_INTEL if d.name == name), "")
    return {
        "name": name,
        "url": url,
        "path": rel,
        "license": entry.get("license") or default_license,
        "sha256": entry.get("sha256") or (_sha256(disk) if disk and disk.exists() else ""),
        "fetched_at": entry.get("fetched_at", ""),
    }


def record_source(con: sqlite3.Connection, source: str, *, path: pathlib.Path | None = None,
                  url: str = "", license: str = "", sha256: str = "", fetched_at: str = "",
                  count: int = 0, status: str = "loaded", note: str = "") -> None:
    rel = ""
    if path:
        try:
            rel = str(path.relative_to(paths.ROOT))
        except ValueError:
            rel = str(path)
    con.execute(
        "INSERT OR REPLACE INTO source_state"
        "(source,url,path,license,sha256,fetched_at,loaded_at,record_count,status,note) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (source, url, rel, license, sha256, fetched_at, _now(), count, status, note[:1000]),
    )


# ---------------------------------------------------------------- schema
V3_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_cna(
  cve_id TEXT PRIMARY KEY,
  assigner TEXT, state TEXT, published TEXT, updated TEXT,
  title TEXT, description TEXT,
  cvss REAL, cvss_version TEXT, cvss_vector TEXT, severity TEXT,
  record_path TEXT, source TEXT, source_url TEXT, source_sha256 TEXT, fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS cve_cna_ref(
  cve_id TEXT, url TEXT, tags TEXT,
  PRIMARY KEY(cve_id, url)
);
CREATE TABLE IF NOT EXISTS cve_cna_product(
  cve_id TEXT, vendor TEXT, product TEXT,
  PRIMARY KEY(cve_id, vendor, product)
);
CREATE TABLE IF NOT EXISTS cve_cna_cwe(
  cve_id TEXT, cwe TEXT,
  PRIMARY KEY(cve_id, cwe)
);
CREATE TABLE IF NOT EXISTS cve_meta(
  cve_id TEXT PRIMARY KEY,
  published_year INTEGER, cve_year INTEGER,
  has_poc INTEGER DEFAULT 0, poc_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS poc(
  source TEXT, cve_id TEXT, repo TEXT, url TEXT, repo_id INTEGER,
  stars INTEGER, language TEXT, created_at TEXT, pushed_at TEXT,
  description TEXT, fetched_at TEXT,
  PRIMARY KEY(source, cve_id, url)
);
CREATE TABLE IF NOT EXISTS poc_orphan(cve_id TEXT PRIMARY KEY, count INTEGER);
CREATE TABLE IF NOT EXISTS cve_alias(
  cve_id TEXT, alias TEXT, source TEXT,
  PRIMARY KEY(cve_id, alias, source)
);
CREATE TABLE IF NOT EXISTS source_state(
  source TEXT PRIMARY KEY, url TEXT, path TEXT, license TEXT, sha256 TEXT,
  fetched_at TEXT, loaded_at TEXT, record_count INTEGER, status TEXT, note TEXT
);
CREATE INDEX IF NOT EXISTS cve_cna_assigner ON cve_cna(assigner);
CREATE INDEX IF NOT EXISTS cve_meta_pubyear ON cve_meta(published_year);
CREATE INDEX IF NOT EXISTS cve_meta_cveyear ON cve_meta(cve_year);
CREATE INDEX IF NOT EXISTS cve_meta_poc ON cve_meta(has_poc);
CREATE INDEX IF NOT EXISTS poc_cve ON poc(cve_id);
CREATE INDEX IF NOT EXISTS poc_stars ON poc(stars);
CREATE INDEX IF NOT EXISTS cve_alias_alias ON cve_alias(alias);
"""


def migrate(con: sqlite3.Connection, progress=None) -> None:
    """Upgrade a v2 index in place.  Safe to call repeatedly."""
    con.executescript(V3_SCHEMA)
    # Exact duplicate CPE rows were an audit finding.  Deduplicate before the
    # unique index is created so the migration cannot fail on existing data.
    dedupe = (
        ("cve_cwe", "cve_id,cwe"),
        ("cve_product", "cve_id,vendor,product"),
        ("cpe_match", "cve_id,part,vendor,product,version,"
                      "v_start_incl,v_start_excl,v_end_incl,v_end_excl"),
        ("cve_ref", "cve_id,url"),
    )
    for table, cols in dedupe:
        con.execute(
            f"DELETE FROM {table} WHERE rowid NOT IN "
            f"(SELECT min(rowid) FROM {table} GROUP BY {cols})"
        )
    con.executescript("""
CREATE UNIQUE INDEX IF NOT EXISTS cve_cwe_unique ON cve_cwe(cve_id,cwe);
CREATE UNIQUE INDEX IF NOT EXISTS cve_product_unique ON cve_product(cve_id,vendor,product);
CREATE UNIQUE INDEX IF NOT EXISTS cpe_match_unique ON cpe_match(
  cve_id,part,vendor,product,version,v_start_incl,v_start_excl,v_end_incl,v_end_excl);
CREATE UNIQUE INDEX IF NOT EXISTS cve_ref_unique ON cve_ref(cve_id,url);
""")
    rebuild_cve_meta(con)
    stub_missing_cwes(con)
    con.execute("INSERT OR REPLACE INTO meta VALUES ('schema',?)", (str(paths.SCHEMA_VERSION),))
    con.commit()
    if progress:
        progress("schema v3 migrated")


# ---------------------------------------------------------------- CVE List v5
def _cna_metrics(cna: dict) -> tuple[float | None, str, str, str]:
    """CNA CVSS: the schema allows one metric object per key inside a list."""
    buckets: list[dict] = []
    for entry in cna.get("metrics") or []:
        if isinstance(entry, dict):
            buckets.append(entry)
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        for bucket in buckets:
            data = bucket.get(key)
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            if score is None:
                continue
            return (float(score), str(data.get("version") or ""),
                    str(data.get("vectorString") or ""),
                    str(data.get("baseSeverity") or "").upper())
        data = cna.get(key)
        if isinstance(data, dict) and data.get("baseScore") is not None:
            return (float(data["baseScore"]), str(data.get("version") or ""),
                    str(data.get("vectorString") or ""),
                    str(data.get("baseSeverity") or "").upper())
    return (None, "", "", "")


def iter_cveorg(doc) -> list[dict]:
    """One CVE List file can hold a single record or an array of records."""
    out: list[dict] = []
    items = doc if isinstance(doc, list) else [doc]
    for item in items:
        if not isinstance(item, dict):
            continue
        parsed = parse_cveorg(item)
        if parsed:
            out.append(parsed)
    return out


def parse_cveorg(doc: dict | list) -> dict | None:
    if isinstance(doc, list):
        # A handful of CVE List files hold a JSON array of records.
        for item in doc:
            parsed = parse_cveorg(item) if isinstance(item, dict) else None
            if parsed:
                return parsed
        return None
    if not isinstance(doc, dict):
        return None
    meta = doc.get("cveMetadata") or {}
    cid = (meta.get("cveId") or "").upper()
    if not CVE_RE.fullmatch(cid):
        return None
    cna = (doc.get("containers") or {}).get("cna") or {}
    desc = ""
    for d in cna.get("descriptions") or []:
        if isinstance(d, dict) and str(d.get("lang", "")).lower().startswith("en"):
            desc = d.get("value") or ""
            break
    title = _norm(cna.get("title"), 1000)
    desc = _norm(desc) or title or "No CNA description provided."
    score, version, vector, severity = _cna_metrics(cna)

    cwes: list[str] = []
    for pt in cna.get("problemTypes") or []:
        for d in (pt or {}).get("descriptions") or []:
            w = str((d or {}).get("cweId") or "").upper()
            if w.startswith("CWE-") and w not in cwes:
                cwes.append(w)

    products: list[tuple[str, str]] = []
    for a in cna.get("affected") or []:
        if not isinstance(a, dict):
            continue
        vendor = _norm(a.get("vendor"), 200).lower()
        product = _norm(a.get("product"), 200).lower()
        if not vendor or not product or vendor in ("n/a", "unknown"):
            continue
        pair = (vendor, product)
        if pair not in products and len(products) < 120:
            products.append(pair)

    refs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for r in cna.get("references") or []:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        refs.append((url, ",".join(str(t) for t in (r.get("tags") or []))[:300]))

    return {
        "id": cid,
        "assigner": _norm(meta.get("assignerShortName")
                          or (cna.get("providerMetadata") or {}).get("shortName"), 200),
        "state": str(meta.get("state") or "").upper(),
        "published": meta.get("datePublished") or "",
        "updated": meta.get("dateUpdated") or "",
        "title": title,
        "description": desc,
        "cvss": score, "cvss_version": version, "cvss_vector": vector, "severity": severity,
        "cwes": cwes[:80], "products": products, "refs": refs[:60],
    }


def load_cveorg(path: pathlib.Path, con: sqlite3.Connection, *, epss: dict | None = None,
                kev_ids: set[str] | None = None, progress=None) -> int:
    if not path.exists():
        return 0
    src = source_meta("cveorg-cvelist", "MIT", path)
    fetched = src["fetched_at"] or _now()
    epss = epss or {}
    kev_ids = kev_ids or set()
    existing = {r[0] for r in con.execute("SELECT id FROM cve")}

    con.execute("DELETE FROM cve_cna")
    con.execute("DELETE FROM cve_cna_ref")
    con.execute("DELETE FROM cve_cna_product")
    cna_rows: list[tuple] = []
    cve_rows: list[tuple] = []
    cwe_rows: list[tuple] = []
    prod_rows: list[tuple] = []
    ref_rows: list[tuple] = []
    cna_ref_rows: list[tuple] = []
    cna_prod_rows: list[tuple] = []
    fts_rows: list[tuple] = []
    meta_rows: list[tuple] = []
    inserted = 0
    records = 0

    def flush() -> None:
        nonlocal cna_rows, cve_rows, cwe_rows, prod_rows, ref_rows, fts_rows, meta_rows
        nonlocal cna_ref_rows, cna_prod_rows
        if cna_rows:
            con.executemany(
                "INSERT OR REPLACE INTO cve_cna(cve_id,assigner,state,published,updated,"
                "title,description,cvss,cvss_version,cvss_vector,severity,record_path,source,"
                "source_url,source_sha256,fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                cna_rows)
        if cve_rows:
            con.executemany(
                "INSERT OR IGNORE INTO cve(id,published,modified,status,description,cvss,"
                "cvss_version,cvss_vector,severity,kev,epss,epss_pct,year) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", cve_rows)
        if cwe_rows:
            con.executemany("INSERT OR IGNORE INTO cve_cwe VALUES (?,?)", cwe_rows)
        if prod_rows:
            con.executemany("INSERT OR IGNORE INTO cve_product VALUES (?,?,?)", prod_rows)
        if ref_rows:
            con.executemany("INSERT OR IGNORE INTO cve_ref VALUES (?,?,?)", ref_rows)
        if cna_ref_rows:
            con.executemany("INSERT OR IGNORE INTO cve_cna_ref VALUES (?,?,?)", cna_ref_rows)
        if cna_prod_rows:
            con.executemany("INSERT OR IGNORE INTO cve_cna_product VALUES (?,?,?)",
                            cna_prod_rows)
        if fts_rows:
            con.executemany("INSERT INTO cve_fts(id,description,products) VALUES (?,?,?)",
                            fts_rows)
        if meta_rows:
            con.executemany(
                "INSERT INTO cve_meta(cve_id,published_year,cve_year) VALUES (?,?,?) "
                "ON CONFLICT(cve_id) DO UPDATE SET published_year=excluded.published_year,"
                " cve_year=excluded.cve_year", meta_rows)
        (cna_rows, cve_rows, cwe_rows, prod_rows, ref_rows, fts_rows, meta_rows,
         cna_ref_rows, cna_prod_rows) = ([], [], [], [], [], [], [], [], [])

    with tarfile.open(path, "r:gz") as tf:
        for member in tf:
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            if "/cves/" not in member.name:
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            try:
                doc = json.load(fh)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            parsed = iter_cveorg(doc)
            if not parsed:
                continue
            for p in parsed:
                records += 1
                cid = p["id"]
                year = int(cid.split("-")[1])
                pub_year = int(p["published"][:4]) if p["published"][:4].isdigit() else None
                e, pct = epss.get(cid, (None, None))
                cna_rows.append((cid, p["assigner"], p["state"], p["published"], p["updated"],
                                 p["title"], p["description"], p["cvss"], p["cvss_version"],
                                 p["cvss_vector"], p["severity"], member.name, "cveorg",
                                 src["url"], src["sha256"], fetched))
                meta_rows.append((cid, pub_year, year))
                for w in p["cwes"]:
                    cwe_rows.append((cid, w))
                for vendor, product in p["products"]:
                    cna_prod_rows.append((cid, vendor, product))
                for url, tags in p["refs"]:
                    cna_ref_rows.append((cid, url, tags))
                if cid not in existing and p["state"] == "PUBLISHED":
                    existing.add(cid)
                    inserted += 1
                    cve_rows.append((cid, p["published"], p["updated"] or p["published"],
                                     "Published", p["description"], p["cvss"], p["cvss_version"],
                                     p["cvss_vector"], p["severity"], 1 if cid in kev_ids else 0,
                                     e, pct, pub_year or year))
                    # A CVE that NVD never carried has no NVD refs/products, so its
                    # CNA data is the only copy -> promote it into the shared tables.
                    for vendor, product in p["products"]:
                        prod_rows.append((cid, vendor, product))
                    for url, tags in p["refs"]:
                        ref_rows.append((cid, url, tags))
                    fts_rows.append((cid, p["description"][:4000],
                                     " ".join(f"{v} {pr}" for v, pr in p["products"])[:4000]))
            if len(cna_rows) >= BATCH:
                flush()
                if progress and records % 20000 == 0:
                    progress(f"CVE List {records} records / {inserted} new")

    flush()
    rebuild_cve_meta(con)
    record_source(con, "cveorg-cvelist", path=path, url=src["url"],
                  license=src["license"], sha256=src["sha256"], fetched_at=fetched,
                  count=records,
                  note=f"{inserted} CVE rows inserted; {len(ref_rows)} CNA refs in last batch")
    con.commit()
    if progress:
        progress(f"CVE List {records} records, {inserted} new CVEs")
    return inserted


# ---------------------------------------------------------------- PoC-in-GitHub
def load_poc_github(path: pathlib.Path, con: sqlite3.Connection, progress=None) -> int:
    if not path.exists():
        return 0
    src = source_meta("poc-in-github", "MIT", path)
    fetched = src["fetched_at"] or _now()
    con.execute("DELETE FROM poc WHERE source='poc-in-github'")
    rows: list[tuple] = []
    files = 0
    added = 0

    def flush() -> None:
        nonlocal rows
        if rows:
            con.executemany(
                "INSERT OR IGNORE INTO poc(source,cve_id,repo,url,repo_id,stars,language,"
                "created_at,pushed_at,description,fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                rows)
            rows = []

    with tarfile.open(path, "r:gz") as tf:
        for member in tf:
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            name = member.name.rsplit("/", 1)[-1][:-5]
            if not CVE_RE.fullmatch(name):
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            try:
                repos = json.load(fh)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(repos, list):
                continue
            files += 1
            for repo in repos:
                if not isinstance(repo, dict):
                    continue
                url = str(repo.get("html_url") or "").strip()
                if not url:
                    continue
                rows.append((
                    "poc-in-github", name.upper(),
                    _norm(repo.get("full_name"), 300), url,
                    repo.get("id") if isinstance(repo.get("id"), int) else None,
                    repo.get("stargazers_count") if isinstance(repo.get("stargazers_count"), int) else 0,
                    _norm(repo.get("language"), 100),
                    repo.get("created_at") or "", repo.get("pushed_at") or "",
                    _norm(repo.get("description"), 500), fetched,
                ))
                added += 1
                if len(rows) >= BATCH * 2:
                    flush()
            if files % 2000 == 0 and progress:
                progress(f"PoC {files} files / {added} repos")
    flush()
    con.execute("DELETE FROM poc_orphan")
    con.execute(
        "INSERT INTO poc_orphan(cve_id,count) SELECT p.cve_id,count(*) FROM poc p "
        "WHERE NOT EXISTS(SELECT 1 FROM cve c WHERE c.id=p.cve_id) GROUP BY p.cve_id")
    con.execute("UPDATE cve_meta SET has_poc=0, poc_count=0")
    # one grouped pass; a correlated count per row is quadratic before poc_cve exists
    con.execute(
        "UPDATE cve_meta SET has_poc=1, poc_count=p.n FROM "
        "(SELECT cve_id, count(*) n FROM poc GROUP BY cve_id) p WHERE p.cve_id=cve_meta.cve_id")
    record_source(con, "poc-in-github", path=path, url=src["url"],
                  license=src["license"], sha256=src["sha256"], fetched_at=fetched,
                  count=added,
                  note=f"{files} CVE files parsed; repo metadata only, no code executed")
    con.commit()
    if progress:
        progress(f"PoC-in-GitHub {files} files, {added} repos")
    return added


# ---------------------------------------------------------------- derived tables
def rebuild_cve_meta(con: sqlite3.Connection) -> int:
    con.execute(
        "INSERT OR IGNORE INTO cve_meta(cve_id,published_year,cve_year) "
        "SELECT id, NULL, CAST(substr(id,5,4) AS INTEGER) FROM cve")
    con.execute(
        "UPDATE cve_meta SET published_year=CASE WHEN substr("
        "(SELECT published FROM cve WHERE cve.id=cve_meta.cve_id),1,4) GLOB '[0-9][0-9][0-9][0-9]' "
        "THEN CAST(substr((SELECT published FROM cve WHERE cve.id=cve_meta.cve_id),1,4) AS INTEGER) "
        "ELSE NULL END WHERE published_year IS NULL")
    con.execute(
        "UPDATE cve_meta SET cve_year=CAST(substr(cve_id,5,4) AS INTEGER) "
        "WHERE cve_year IS NULL")
    # Only CVEs that are actually in the index carry metadata rows; rejected or
    # reserved CVE List records stay in cve_cna alone.
    con.execute("DELETE FROM cve_meta WHERE cve_id NOT IN (SELECT id FROM cve)")
    return con.execute("SELECT count(*) FROM cve_meta").fetchone()[0]


def stub_missing_cwes(con: sqlite3.Connection) -> int:
    before = con.execute("SELECT count(*) FROM cwe").fetchone()[0]
    con.execute(
        "INSERT OR IGNORE INTO cwe(id,name,abstraction,status,description) "
        "SELECT DISTINCT cwe,'Deprecated or withdrawn CWE '||cwe,'Unknown','Deprecated',"
        "'Referenced by CVE records but absent from the current CWE catalog; usually a "
        "deprecated CWE retained for historical mapping.' FROM cve_cwe "
        "WHERE cwe NOT IN (SELECT id FROM cwe)")
    return con.execute("SELECT count(*) FROM cwe").fetchone()[0] - before


def rebuild_aliases(con: sqlite3.Connection) -> int:
    con.execute("DELETE FROM cve_alias WHERE source='osv'")
    rows: list[tuple[str, str, str]] = []
    for cve, aliases in con.execute(
            "SELECT cve,aliases FROM advisory WHERE cve<>'' AND aliases<>''"):
        for alias in str(aliases).split(","):
            alias = alias.strip().upper()
            if alias and alias != cve and len(alias) <= 100:
                rows.append((cve, alias, "osv"))
    if rows:
        con.executemany("INSERT OR IGNORE INTO cve_alias VALUES (?,?,?)", rows)
    con.commit()
    return len(rows)


def already_loaded(con: sqlite3.Connection, source: str, path: pathlib.Path) -> bool:
    """True when this exact archive was already loaded (idempotent skip)."""
    row = con.execute(
        "SELECT sha256, status FROM source_state WHERE source=?", (source,)).fetchone()
    if not row or row[1] != "loaded" or not row[0]:
        return False
    if not path.exists():
        return False
    return _sha256(path) == row[0]


def load_all(con: sqlite3.Connection, *, epss: dict | None = None,
             kev_ids: set[str] | None = None, progress=None,
             force: bool = False) -> dict:
    """Load every staged v3 source that exists.  Missing files are skipped.

    Archives whose SHA-256 already matches `source_state` are skipped, so a
    repeated run is cheap and produces identical rows.
    """
    counts: dict[str, int] = {}
    cve_tar = paths.DATA / "intel/cveorg/cvelistV5-main.tar.gz"
    poc_tar = paths.DATA / "intel/poc-in-github/PoC-in-GitHub-master.tar.gz"
    if force or not already_loaded(con, "cveorg-cvelist", cve_tar):
        counts["cveorg"] = load_cveorg(cve_tar, con, epss=epss, kev_ids=kev_ids,
                                        progress=progress)
    else:
        counts["cveorg"] = 0
        if progress:
            progress("CVE List unchanged (sha256 match) - skipped")
    if force or not already_loaded(con, "poc-in-github", poc_tar):
        counts["poc"] = load_poc_github(poc_tar, con, progress=progress)
    else:
        counts["poc"] = 0
        if progress:
            progress("PoC-in-GitHub unchanged (sha256 match) - skipped")
    counts["cwe_stubs"] = stub_missing_cwes(con)
    counts["aliases"] = rebuild_aliases(con)
    con.commit()
    return counts
