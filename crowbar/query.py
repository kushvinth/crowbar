"""Read-only query layer. Every function returns plain dicts (JSON-ready)."""
from __future__ import annotations

import json
import re
import sqlite3
import time

from . import datasets, db, paths



# ---------------------------------------------------------------- helpers
def fts_query(q: str) -> tuple[str, list[str]]:
    toks = [t for t in re.findall(r"[A-Za-z0-9_.]{2,}", q)]
    if not toks:
        raise ValueError("query too short")
    terms = [f'"{t}"*' if len(t) >= 4 else f'"{t}"' for t in toks]
    return " AND ".join(terms), toks


def vkey(v: str):
    """Orderable version key: 1.2.3p1 -> [(1,''),(2,''),(3,'p'),(1,'')]."""
    out = []
    for part in re.split(r"[.\-_+~]", v or ""):
        if not part:
            continue
        if part.isdigit():
            out.append((int(part), ""))
        else:
            m = re.match(r"^(\d+)(.*)$", part)
            out.append((int(m.group(1)), m.group(2).lower()) if m else (10 ** 9, part.lower()))
    return out


def version_affected(row: sqlite3.Row, version: str) -> bool:
    ver = (row["version"] or "").strip()
    if ver not in ("*", "-", ""):
        return ver.lower() == version.lower()
    try:
        v = vkey(version)
        if row["v_start_incl"] and v < vkey(row["v_start_incl"]):
            return False
        if row["v_start_excl"] and v <= vkey(row["v_start_excl"]):
            return False
        if row["v_end_incl"] and v > vkey(row["v_end_incl"]):
            return False
        if row["v_end_excl"] and v >= vkey(row["v_end_excl"]):
            return False
    except (TypeError, ValueError):
        return False
    return True


def range_label(row: sqlite3.Row) -> str:
    base = f"{row['vendor']}:{row['product']}"
    ver = (row["version"] or "").strip()
    if ver not in ("*", "-", ""):
        return f"{base} {ver}"
    bits = []
    if row["v_start_incl"]:
        bits.append(f">={row['v_start_incl']}")
    if row["v_start_excl"]:
        bits.append(f">{row['v_start_excl']}")
    if row["v_end_incl"]:
        bits.append(f"<={row['v_end_incl']}")
    if row["v_end_excl"]:
        bits.append(f"<{row['v_end_excl']}")
    return base + (" " + " ".join(bits) if bits else " (any)")


# ---------------------------------------------------------------- search
def _prefix(name: str) -> str:
    """GLOB pattern for names starting with `name` (an index range, unlike LIKE '%x%')."""
    return re.sub(r"([*?\[])", r"[\1]", name.lower()) + "*"


def search(con: sqlite3.Connection, query: str = "", *, limit: int = 20,
           offset: int = 0, sort: str = "relevance", severity: str | None = None,
           year: int | None = None, since: str | None = None, kev: bool = False,
           exploit: bool = False, epss: float | None = None, cvss: float | None = None,
           cwe: str | None = None, product: str | None = None,
           vendor: str | None = None, ssvc: str | None = None,
           poc: bool = False) -> list[dict]:
    where, params = [], []
    use_fts = bool(query)
    toks: list[str] = []
    if use_fts:
        fq, toks = fts_query(query)
        where.append("cve_fts MATCH ?")
        params.append(fq)
    if severity:
        sevs = [s.upper() for s in severity.split(",")]
        where.append(f"c.severity IN ({','.join('?' * len(sevs))})")
        params += sevs
    if year:
        where.append("c.year = ?")
        params.append(int(year))
    if since:
        where.append("c.published >= ?")
        params.append(since)
    if kev:
        where.append("c.kev = 1")
    if exploit:
        where.append("c.has_exploit = 1")
    if epss is not None:
        where.append("c.epss >= ?")
        params.append(epss)
    if cvss is not None:
        where.append("c.cvss >= ?")
        params.append(cvss)
    if cwe:
        where.append("EXISTS(SELECT 1 FROM cve_cwe w WHERE w.cve_id=c.id AND w.cwe=?)")
        params.append(cwe.upper())
    if product:
        where.append("c.id IN (SELECT cve_id FROM cve_product WHERE product GLOB ?)")
        params.append(_prefix(product))
    if vendor:
        where.append("c.id IN (SELECT cve_id FROM cve_product WHERE vendor GLOB ?)")
        params.append(_prefix(vendor))
    if ssvc:
        where.append("EXISTS(SELECT 1 FROM ssvc s WHERE s.cve_id=c.id AND s.exploitation=?)")
        params.append(ssvc)
    if poc:
        where.append("EXISTS(SELECT 1 FROM poc p WHERE p.cve_id=c.id)")

    sql_where = (" WHERE " + " AND ".join(where)) if where else ""
    base = "FROM cve_fts JOIN cve c ON c.id = cve_fts.id" if use_fts else "FROM cve c"
    sel = ("SELECT c.*, (SELECT count(*) FROM cve_exploit x WHERE x.cve_id=c.id) AS exploits,"
           " (SELECT count(*) FROM cve_nuclei n WHERE n.cve_id=c.id) AS nuclei_count,"
           " (SELECT coalesce(poc_count,0) FROM cve_meta m WHERE m.cve_id=c.id) AS poc_count"
           + (", bm25(cve_fts) AS rank" if use_fts else ""))
    sql = f"{sel} {base}{sql_where}"
    order = {
        "relevance": "ORDER BY c.kev DESC, c.epss DESC",
        "newest": "ORDER BY c.published DESC",
        "oldest": "ORDER BY c.published ASC",
        "cvss": "ORDER BY c.cvss DESC",
        "epss": "ORDER BY c.epss DESC",
    }[sort]

    if use_fts and sort == "relevance":
        pool = min(max(300, (offset + limit) * 8), 2000)
        rows = con.execute(sql + " ORDER BY rank LIMIT ?", [*params, pool]).fetchall()
        if not rows and len(toks) > 1:
            params[0] = f'"{max(toks, key=len)}"*'
            rows = con.execute(sql + " ORDER BY rank LIMIT ?", [*params, pool]).fetchall()
        if rows:
            top = max(abs(r["rank"]) for r in rows) or 1.0
            scored = [(10.0 * abs(r["rank"]) / top + 4.0 * r["kev"]
                       + 5.0 * (r["epss"] or 0) + 1.5 * min(r["exploits"], 3)
                       + 1.0 * min(r["poc_count"] or 0, 3), r)
                      for r in rows]
            scored.sort(key=lambda pair: -pair[0])
            rows = [r for _, r in scored][offset:offset + limit]
    else:
        rows = con.execute(sql + f" {order} LIMIT ? OFFSET ?",
                           [*params, limit, offset]).fetchall()
        if not rows and use_fts and len(toks) > 1 and offset == 0:
            params[0] = f'"{max(toks, key=len)}"*'
            rows = con.execute(sql + f" {order} LIMIT ? OFFSET ?",
                               [*params, limit, offset]).fetchall()
    return [{k: v for k, v in dict(r).items() if k != "rank"} for r in rows]


# Per-CVE array caps keep cb_cve responses small enough to call every turn.
# The *_total fields tell the caller how many rows exist beyond the cap;
# use `crowbar sql` / the CLI for the full list.
CVE_ARRAY_CAP = 50

# ---------------------------------------------------------------- one CVE
def get_cve(con: sqlite3.Connection, cid: str) -> dict:
    cid = cid.strip().upper()
    if not cid.startswith("CVE-"):
        cid = "CVE-" + cid
    r = con.execute("SELECT * FROM cve WHERE id=?", (cid,)).fetchone()
    if not r:
        r = con.execute(
            "SELECT c.* FROM cve_alias a JOIN cve c ON c.id=a.cve_id "
            "WHERE a.alias=?", (cid,)).fetchone()
    if not r:
        k = con.execute("SELECT date_added, epss FROM kev WHERE cve=?", (cid,)).fetchone()
        if k:
            raise KeyError(f"{cid} has no NVD record in this index, but it IS in CISA KEV "
                           f"(added {k['date_added']}, EPSS {k['epss']}). A lite index only "
                           f"carries recent NVD years; use cb_kev, or build a bigger tier.")
        raise KeyError(cid)
    out = dict(r)
    cid = out["id"]
    meta = con.execute("SELECT * FROM cve_meta WHERE cve_id=?", (cid,)).fetchone()
    out["published_year"] = meta["published_year"] if meta else None
    out["cve_year"] = meta["cve_year"] if meta else None
    out["poc_count"] = meta["poc_count"] if meta else 0
    out["pocs"] = [dict(x) for x in con.execute(
        "SELECT source, repo, url, stars, language, created_at FROM poc "
        "WHERE cve_id=? ORDER BY stars DESC, repo LIMIT 50", (cid,))]
    cna = con.execute("SELECT * FROM cve_cna WHERE cve_id=?", (cid,)).fetchone()
    out["cna"] = dict(cna) if cna else None
    out["aliases"] = [x[0] for x in con.execute(
        "SELECT alias FROM cve_alias WHERE cve_id=? ORDER BY alias", (cid,))]
    out["cwe"] = [x[0] for x in con.execute("SELECT cwe FROM cve_cwe WHERE cve_id=?", (cid,))]
    out["products_total"] = con.execute(
        "SELECT count(*) FROM cve_product WHERE cve_id=?", (cid,)).fetchone()[0]
    out["products"] = [dict(x) for x in con.execute(
        "SELECT vendor, product FROM cve_product WHERE cve_id=? ORDER BY product LIMIT ?",
        (cid, CVE_ARRAY_CAP))]
    out["affects_total"] = con.execute(
        "SELECT count(*) FROM cpe_match WHERE cve_id=?", (cid,)).fetchone()[0]
    out["affects"] = [{**dict(x), "label": range_label(x)} for x in con.execute(
        "SELECT * FROM cpe_match WHERE cve_id=? ORDER BY vendor, product, version LIMIT ?",
        (cid, CVE_ARRAY_CAP))]
    out["references_total"] = con.execute(
        "SELECT count(*) FROM cve_ref WHERE cve_id=?", (cid,)).fetchone()[0]
    out["references"] = [dict(x) for x in con.execute(
        "SELECT url, tags FROM cve_ref WHERE cve_id=? LIMIT ?", (cid, CVE_ARRAY_CAP))]
    kev = con.execute("SELECT * FROM kev WHERE cve=?", (cid,)).fetchone()
    out["kev_detail"] = dict(kev) if kev else None
    out["exploits_total"] = con.execute(
        "SELECT count(*) FROM cve_exploit WHERE cve_id=?", (cid,)).fetchone()[0]
    out["exploits"] = [dict(x) for x in con.execute(
        "SELECT e.id, e.description, e.type, e.platform, e.verified, e.url FROM exploit e "
        "JOIN cve_exploit x ON x.exploit_id=e.id WHERE x.cve_id=? ORDER BY e.id LIMIT ?", (cid, CVE_ARRAY_CAP))]
    out["nuclei"] = [dict(x) for x in con.execute(
        "SELECT n.id, n.name, n.severity, n.path, n.domain FROM nuclei n "
        "JOIN cve_nuclei x ON x.template_id=n.id WHERE x.cve_id=?", (cid,))]
    out["metasploit"] = [dict(x) for x in con.execute(
        "SELECT m.path, m.type, m.name FROM msf m JOIN cve_msf x ON x.module_path=m.path "
        "WHERE x.cve_id=?", (cid,))]
    s = con.execute("SELECT * FROM ssvc WHERE cve_id=?", (cid,)).fetchone()
    out["ssvc"] = dict(s) if s else None
    out["os"] = [dict(x) for x in con.execute(
        "SELECT source, platform, product, version, title, severity, impact, exploited, url "
        "FROM os_advisory WHERE cve=? ORDER BY platform, released DESC", (cid,))]
    out["advisories"] = [dict(x) for x in con.execute(
        "SELECT source, id, ecosystem, package, severity, summary, url "
        "FROM advisory WHERE cve=? LIMIT 20", (cid,))]
    out["debian"] = [dict(x) for x in con.execute(
        "SELECT package, release, status, fixed, urgency FROM debian WHERE cve=? LIMIT 20", (cid,))]
    out["mentions"] = _optional(con, "SELECT source, url, title, posted_at, score FROM mention "
                                     "WHERE cve_id=? ORDER BY posted_at DESC LIMIT 20", (cid,))
    return out


def _optional(con: sqlite3.Connection, sql: str, params=()) -> list[dict]:
    """Rows from a table an older index may not have yet (it appears on the next update)."""
    try:
        return [dict(x) for x in con.execute(sql, params)]
    except sqlite3.OperationalError:
        return []


def _days_ago(days: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))


# ---------------------------------------------------------------- what's moving
def trending(con: sqlite3.Connection, days: float = 7, limit: int = 25) -> list[dict]:
    """CVEs people are posting about: ranked by how many distinct places mention them."""
    return _optional(con, """
        SELECT m.cve_id AS id, count(DISTINCT m.source) AS sources, count(*) AS posts,
               group_concat(DISTINCT m.source) AS seen_on, max(m.posted_at) AS last_seen,
               c.severity, c.cvss, c.epss, c.kev, c.has_exploit,
               substr(c.description, 1, 160) AS description
        FROM mention m LEFT JOIN cve c ON c.id = m.cve_id
        WHERE m.posted_at >= ? GROUP BY m.cve_id
        ORDER BY sources DESC, posts DESC, c.kev DESC, c.epss DESC LIMIT ?""",
                     (_days_ago(days), limit))


def new_since(con: sqlite3.Connection, since: str | None = None, days: float = 7,
              limit: int = 25) -> dict:
    """What changed since a date: KEV/EUVD exploited additions, new CVEs, new public PoCs."""
    since = since or _days_ago(days)[:10]
    def part(sql: str, order: str) -> dict:
        total = _optional(con, f"SELECT count(*) n FROM ({sql})", (since,))
        rows = _optional(con, f"{sql} {order} LIMIT ?", (since, limit))
        return {"total": total[0]["n"] if total else 0, "rows": rows}
    return {
        "since": since,
        "kev": part("SELECT cve, vendor, product, name, date_added, ransomware FROM kev "
                    "WHERE date_added >= ?", "ORDER BY date_added DESC"),
        "eu_exploited": part("SELECT m.cve_id AS cve, m.posted_at AS exploited_since, c.cvss, "
                             "c.kev FROM mention m LEFT JOIN cve c ON c.id = m.cve_id "
                             "WHERE m.source = 'euvd-exploited' AND m.posted_at >= ?",
                             "ORDER BY m.posted_at DESC"),
        "published": part("SELECT id, published, severity, cvss, epss, kev, has_exploit, "
                          "substr(description, 1, 160) AS description FROM cve WHERE published >= ?",
                          "ORDER BY kev DESC, epss DESC, cvss DESC"),
        "pocs": part("SELECT cve_id AS cve, repo, url, stars, language, created_at FROM poc "
                     "WHERE created_at >= ?", "ORDER BY stars DESC"),
    }


def data_as_of(con: sqlite3.Connection) -> dict:
    """Newest row per source: how current the data is, not just when it was built."""
    out = {}
    for key, sql in (("cve_published", "SELECT max(published) FROM cve"),
                     ("cve_modified", "SELECT max(modified) FROM cve"),
                     ("kev_added", "SELECT max(date_added) FROM kev"),
                     ("poc_created", "SELECT max(created_at) FROM poc"),
                     ("mention_posted", "SELECT max(posted_at) FROM mention")):
        try:
            out[key] = con.execute(sql).fetchone()[0]
        except sqlite3.OperationalError:
            out[key] = None
    return out


# ---------------------------------------------------------------- product
def products(con: sqlite3.Connection, name: str, version: str | None = None,
             limit: int = 25) -> list[dict]:
    """CVEs whose CPE rows name the product (or vendor), ranked KEV > EPSS."""
    n = name.lower()   # CPE vendor/product strings are lowercase
    sel = "SELECT * FROM cpe_match WHERE "
    # exact, then prefix (both index lookups); substring scan of all rows only as a last resort
    rows = con.execute(sel + "product = ? OR vendor = ?", (n, n)).fetchall()
    if not rows:
        rows = con.execute(sel + "product GLOB ? OR vendor GLOB ?", (_prefix(n),) * 2).fetchall()
    if not rows:
        rows = con.execute(sel + "product LIKE ? OR vendor LIKE ? LIMIT 20000",
                           (f"%{n}%", f"%{n}%")).fetchall()
    hits: dict[str, list[sqlite3.Row]] = {}
    for r in rows:
        if not version or version_affected(r, version):
            hits.setdefault(r["cve_id"], []).append(r)
    out = []
    for c in con.execute(
            "SELECT c.*, (SELECT count(*) FROM cve_exploit x WHERE x.cve_id=c.id) AS exploits,"
            " (SELECT count(*) FROM cve_nuclei n WHERE n.cve_id=c.id) AS nuclei_count"
            " FROM cve c WHERE c.id IN (SELECT value FROM json_each(?))"
            " ORDER BY c.kev DESC, c.epss DESC, c.id DESC LIMIT ?", (json.dumps(list(hits)), limit)):
        d = dict(c)
        d["matched"] = sorted({range_label(h) for h in hits[d["id"]]})[:6]
        out.append(d)
    return out


# ---------------------------------------------------------------- intel
def kev_list(con: sqlite3.Connection, q: str | None = None, limit: int = 25) -> list[dict]:
    sql = "SELECT * FROM kev"
    params: list = []
    if q:
        sql += " WHERE cve LIKE ? OR name LIKE ? OR vendor LIKE ? OR product LIKE ? OR notes LIKE ?"
        params = [f"%{q}%"] * 5
    sql += " ORDER BY date_added DESC LIMIT ?"
    params.append(limit)
    return [dict(r) for r in con.execute(sql, params)]


def exploit_search(con: sqlite3.Connection, q: str, limit: int = 20) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT e.*, bm25(exploit_fts) AS rank FROM exploit_fts "
        "JOIN exploit e ON e.id=exploit_fts.id WHERE exploit_fts MATCH ? "
        "ORDER BY rank LIMIT ?", (fts_query(q)[0], limit))]


def exploit_lookup(con: sqlite3.Connection, eid: str) -> dict:
    """Offline: return the indexed Exploit-DB row for an id, with a hint to fetch
    the source via the CLI. Never touches the network (safe for the MCP server)."""
    r = con.execute("SELECT * FROM exploit WHERE id=?", (str(eid),)).fetchone()
    if not r:
        return {"id": eid, "error": "not_found"}
    out = dict(r)
    local = [p for p in (paths.DATA / "exploitdb/full" / (r["file"] or ""),
                         paths.DATA / "exploitdb/files" / (r["file"] or "")) if r["file"] and p.is_file()]
    out["local_path"] = str(local[0]) if local else None
    out["fetch"] = f"crowbar exploit {eid} --fetch   # downloads the source locally (CLI only)"
    return out


def exploit_fetch(con: sqlite3.Connection, eid: str) -> dict:
    e = con.execute("SELECT * FROM exploit WHERE id=?", (eid,)).fetchone()
    if not e:
        raise KeyError(eid)
    base = (paths.DATA / "exploitdb" / "files").resolve()
    dest = paths.DATA / "exploitdb" / "files" / (e["file"] or f"{e['id']}.txt")
    try:                                   # reject a poisoned ../ path in the index
        dest.resolve().relative_to(base)
    except ValueError:
        raise ValueError(f"unsafe exploit file path: {e['file']!r}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        import urllib.request
        req = urllib.request.Request(e["raw"], headers={"User-Agent": datasets.UA})
        with urllib.request.urlopen(req, timeout=60) as resp:
            dest.write_bytes(resp.read())
    return {**dict(e), "local_path": str(dest)}


def nuclei_search(con: sqlite3.Connection, q: str | None = None, limit: int = 20,
                  domain: str | None = None) -> list[dict]:
    if q:
        sql = ("SELECT n.*, bm25(nuclei_fts) AS rank FROM nuclei_fts "
               "JOIN nuclei n ON n.id=nuclei_fts.id WHERE nuclei_fts MATCH ?")
        params: list = [fts_query(q)[0]]
    else:   # browse by filter alone (e.g. --domain cloud)
        sql, params = "SELECT n.*, n.id AS rank FROM nuclei n WHERE 1", []
    if domain:
        sql += " AND n.domain = ?"
        params.append(domain)
    sql += " ORDER BY rank LIMIT ?"
    params.append(limit)
    return [{k: v for k, v in dict(r).items() if k != "rank"}
            for r in con.execute(sql, params)]


def msf_search(con: sqlite3.Connection, q: str | None = None, limit: int = 30) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT * FROM msf WHERE name LIKE ? ORDER BY type, name LIMIT ?",
        (f"%{q or ''}%", limit))]


def models_list(con: sqlite3.Connection, q: str | None = None, provider: str | None = None,
                limit: int = 40) -> list[dict]:
    sql = "SELECT * FROM model"
    params: list = []
    if q:
        sql += " WHERE (id LIKE ? OR name LIKE ? OR provider LIKE ? OR provider_name LIKE ?)"
        params = [f"%{q}%"] * 4
    if provider:
        sql += (" AND " if q else " WHERE ") + "provider = ?"
        params.append(provider)
    boost = "lower(id) = lower(?) DESC, " if q else ""
    sql += (f" ORDER BY {boost}"
            "CASE WHEN input_cost IS NULL OR input_cost = 0 THEN 1 ELSE 0 END,"
            " input_cost, context DESC LIMIT ?")
    if q:
        params.append(q)
    params.append(limit)
    return [dict(r) for r in con.execute(sql, params)]


def attack_lookup(con: sqlite3.Connection, q: str | None = None, limit: int = 10,
                  domain: str | None = None) -> list[dict]:
    sql = ("SELECT * FROM attack WHERE (id LIKE ? OR name LIKE ? OR tactics LIKE ?"
           " OR description LIKE ?)")
    params: list = [f"%{q or ''}%"] * 4
    if domain:
        sql += " AND domain = ?"
        params.append(domain)
    sql += " LIMIT ?"
    params.append(limit)
    return [dict(r) for r in con.execute(sql, params)]


def cwe_get(con: sqlite3.Connection, q: str | None, limit: int = 30) -> dict | list[dict]:
    if q and re.fullmatch(r"(\d+|CWE-\d+)", q, re.I):
        cid = "CWE-" + q.upper().removeprefix("CWE-")
        r = con.execute("SELECT * FROM cwe WHERE id=?", (cid,)).fetchone()
        if not r:
            raise KeyError(cid)
        return dict(r)
    sql = "SELECT * FROM cwe"
    params: list = []
    if q:
        sql += " WHERE name LIKE ? OR description LIKE ?"
        params = [f"%{q}%"] * 2
    sql += " ORDER BY CAST(substr(id,5) AS INTEGER) LIMIT ?"
    params.append(limit)
    return [dict(r) for r in con.execute(sql, params)]


def capec_search(con: sqlite3.Connection, q: str, limit: int = 15) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT * FROM capec WHERE id LIKE ? OR name LIKE ? OR cwe LIKE ?"
        " OR description LIKE ? LIMIT ?", [*([f"%{q}%"] * 4), limit])]


# ---------------------------------------------------------------- bulk intel
def os_search(con: sqlite3.Connection, q: str | None = None, platform: str | None = None,
              impact: str | None = None, exploited: bool = False,
              since: str | None = None, limit: int = 40) -> list[dict]:
    """Vendor OS advisories: MSRC (windows) and Apple (ios/macos)."""
    sql = "SELECT * FROM os_advisory WHERE 1=1"
    params: list = []
    if platform:
        sql += " AND platform = ?"
        params.append(platform.lower())
    if q:
        sql += (" AND (cve LIKE ? OR product LIKE ? OR title LIKE ? OR version LIKE ?)")
        params += [f"%{q}%"] * 4
    if impact:
        sql += " AND impact = ?"
        params.append(impact)
    if exploited:
        sql += " AND exploited != ''"
    if since:
        sql += " AND released >= ?"
        params.append(since)
    sql += " ORDER BY released DESC, cve DESC LIMIT ?"
    params.append(limit)
    return [dict(r) for r in con.execute(sql, params)]


def advisory_search(con: sqlite3.Connection, q: str | None = None,
                    ecosystem: str | None = None, package: str | None = None,
                    limit: int = 30) -> list[dict]:
    """OSV advisories (GHSA + per-ecosystem databases)."""
    sql = "SELECT * FROM advisory WHERE source='osv'"
    params: list = []
    if ecosystem:
        sql += " AND ecosystem = ?"
        params.append(ecosystem)
    if package:
        sql += " AND package = ?"
        params.append(package.lower())
    if q:
        sql += " AND (id LIKE ? OR package LIKE ? OR summary LIKE ? OR cve LIKE ? OR aliases LIKE ?)"
        params += [f"%{q}%"] * 5
    sql += " ORDER BY COALESCE(published, '') DESC LIMIT ?"
    params.append(limit)
    rows = [dict(r) for r in con.execute(sql, params)]
    if rows:
        ids = [r["id"] for r in rows]
        marks = ",".join("?" * len(ids))
        ranges: dict[str, list[dict]] = {}
        for r in con.execute(
                f"SELECT advisory_id, ecosystem, package, introduced, fixed, last_affected, versions "
                f"FROM package_range WHERE advisory_id IN ({marks})", ids):
            ranges.setdefault(r["advisory_id"], []).append({
                "ecosystem": r["ecosystem"], "package": r["package"],
                "introduced": r["introduced"], "fixed": r["fixed"],
                "last_affected": r["last_affected"], "versions": r["versions"],
            })
        for r in rows:
            r["ranges"] = ranges.get(r["id"], [])
    return rows


def code_search(con: sqlite3.Connection, q: str, limit: int = 20) -> list[dict]:
    """Full-text search inside Exploit-DB sources."""
    sql = ("SELECT exploit_id, path, snippet(exploit_code_fts, 2, '[', ']', ' … ', 20) AS snippet,"
           " bm25(exploit_code_fts) AS rank FROM exploit_code_fts "
           "WHERE exploit_code_fts MATCH ? ORDER BY rank LIMIT ?")
    return [{k: v for k, v in dict(r).items() if k != "rank"}
            for r in con.execute(sql, (fts_query(q)[0], limit))]


def toolkit_search(con: sqlite3.Connection, q: str | None = None, source: str | None = None,
                   limit: int = 25) -> list[dict]:
    """GTFOBins / LOLBAS / PayloadsAllTheThings."""
    if not q:   # list by source alone
        return [dict(r) for r in con.execute(
            "SELECT source, name, path, description, tags FROM toolkit WHERE source = coalesce(?, source) "
            "ORDER BY source, lower(name) LIMIT ?", (source, limit))]
    sql = ("SELECT t.source, t.name, t.path, t.description, t.tags "
           "FROM toolkit_fts f JOIN toolkit t ON t.source=f.source AND t.name=f.name "
           "WHERE toolkit_fts MATCH ?")
    params: list = [fts_query(q)[0]]
    if source:
        sql += " AND t.source = ?"
        params.append(source)
    sql += " ORDER BY lower(t.name) = lower(?) DESC, bm25(toolkit_fts) LIMIT ?"
    params.extend([q, limit])
    return [dict(r) for r in con.execute(sql, params)]


def debian_lookup(con: sqlite3.Connection, package: str, cve: str | None = None,
                  limit: int = 50) -> list[dict]:
    sql = "SELECT * FROM debian WHERE package = ?"
    params: list = [package.lower()]
    if cve:
        sql += " AND cve = ?"
        params.append(cve.upper())
    sql += " ORDER BY cve DESC, release LIMIT ?"   # newest CVEs first: `debian linux` has thousands
    return [dict(r) for r in con.execute(sql, [*params, limit])]


# ---------------------------------------------------------------- public PoCs
def poc_search(con: sqlite3.Connection, q: str = "", *, cve: str | None = None,
               language: str | None = None, min_stars: int = 0,
               limit: int = 25) -> list[dict]:
    """Public GitHub PoC repositories.  Metadata only - nothing is executed."""
    sql = ("SELECT p.cve_id, p.repo, p.url, p.stars, p.language, p.created_at, "
           "p.pushed_at, p.description, p.source FROM poc p WHERE 1=1")
    params: list = []
    if cve:
        sql += " AND p.cve_id = ?"
        params.append(cve.upper())
    if q:
        sql += " AND (p.repo LIKE ? OR p.description LIKE ? OR p.cve_id LIKE ?)"
        params += [f"%{q}%"] * 3
    if language:
        sql += " AND p.language = ?"
        params.append(language)
    if min_stars:
        sql += " AND p.stars >= ?"
        params.append(int(min_stars))
    sql += " ORDER BY p.stars DESC, p.cve_id LIMIT ?"
    params.append(limit)
    return [dict(r) for r in con.execute(sql, params)]


def poc_cves(con: sqlite3.Connection, limit: int = 25) -> list[dict]:
    """CVEs with the most public PoC repositories."""
    return [dict(r) for r in con.execute(
        "SELECT m.cve_id, m.poc_count, c.severity, c.cvss, c.epss, c.kev, "
        "substr(c.description,1,120) AS description FROM cve_meta m "
        "JOIN cve c ON c.id = m.cve_id WHERE m.has_poc = 1 "
        "ORDER BY m.poc_count DESC LIMIT ?", (limit,))]


# ---------------------------------------------------------------- meta
def stats(con: sqlite3.Connection) -> dict:
    meta = db.meta(con)
    try:   # build/update already counted every table; reuse it while it describes this DB
        cached = json.loads((paths.INDEX / "stats.json").read_text())
    except (OSError, ValueError):
        cached = {}
    if meta.get("updated_at") and cached.get("meta", {}).get("updated_at") == meta["updated_at"]:
        counts = {k: v for k, v in cached.items() if isinstance(v, int) and k not in ("db_bytes", "rows_touched")}
    else:
        counts = db.counts(con)
    try:
        counts["cve_with_epss"] = con.execute(
            "SELECT count(*) FROM cve WHERE epss IS NOT NULL").fetchone()[0]
        counts["cve_kev"] = con.execute("SELECT count(*) FROM cve WHERE kev=1").fetchone()[0]
        counts["cve_with_exploit"] = con.execute(
            "SELECT count(*) FROM cve WHERE has_exploit=1").fetchone()[0]
        counts["cve_with_nuclei"] = con.execute(
            "SELECT count(*) FROM cve WHERE has_nuclei=1").fetchone()[0]
        counts["cve_with_msf"] = con.execute(
            "SELECT count(*) FROM cve WHERE has_msf=1").fetchone()[0]
    except sqlite3.DatabaseError:
        pass
    counts["db_bytes"] = paths.DB.stat().st_size if paths.DB.exists() else 0
    counts["meta"] = meta
    counts["freshness"] = datasets.freshness()
    counts["data_as_of"] = data_as_of(con)
    return counts


def sql_readonly(con: sqlite3.Connection, q: str, limit: int = 200) -> list[dict]:
    q = q.strip().rstrip(";")
    if not re.match(r"^(select|with|pragma|explain)\b", q, re.I):
        raise ValueError("read-only: only SELECT / WITH / PRAGMA / EXPLAIN")
    cur = con.execute(q)
    cols = [d[0] for d in cur.description] if cur.description else []
    return [{c: r[i] for i, c in enumerate(cols)} for r in cur.fetchmany(limit)]
