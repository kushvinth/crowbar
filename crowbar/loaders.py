"""Loaders for the bulk OSV / vendor / toolkit corpora."""
from __future__ import annotations

import json
import pathlib
import re
import sqlite3
import zipfile

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

MSRC_IMPACT = {
    "Elevation of Privilege": "EoP",
    "Remote Code Execution": "RCE",
    "Information Disclosure": "InfoDisclosure",
    "Denial of Service": "DoS",
    "Spoofing": "Spoofing",
    "Security Feature Bypass": "Bypass",
    "Tampering": "Tampering",
    "Defense in Depth": "DefenseInDepth",
    "Not a Vulnerability": "",
}

MSRC_SEVERITY = {100000000: "Critical", 100000001: "Important",
                 100000002: "Moderate", 100000003: "Low"}


def norm(s, limit: int = 4000) -> str:
    """Collapse whitespace and cap length (shared by every loader)."""
    if not s:
        return ""
    return re.sub(r"\s+", " ", str(s)).strip()[:limit]



# ---------------------------------------------------------------- OSV
def load_osv_zip(path: pathlib.Path, con: sqlite3.Connection) -> int:
    """One OSV ecosystem zip -> advisory + package_range rows."""
    if not path.exists():
        return 0
    eco_default = path.stem
    adv: dict[tuple[str, str], dict] = {}
    ranges: list[tuple] = []
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                doc = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                continue
            aid = doc.get("id")
            if not aid:
                continue
            aliases = [str(a) for a in doc.get("aliases") or []]
            cve = next((a.upper() for a in aliases if CVE_RE.fullmatch(a.upper())), "")
            if not cve:
                m = CVE_RE.search(doc.get("summary") or "")
                cve = m.group(0).upper() if m else ""
            sev = ""
            for s in doc.get("severity") or []:
                if s.get("score"):
                    sev = s["score"]
            sev = sev or (doc.get("database_specific") or {}).get("severity") or ""
            affected = doc.get("affected") or []
            first_eco, first_pkg = "", ""
            for a in affected:
                pkg = a.get("package") or {}
                eco = pkg.get("ecosystem") or eco_default
                pname = (pkg.get("name") or "").lower()
                if not pname:
                    continue
                first_eco = first_eco or eco
                first_pkg = first_pkg or pname
                for rng in a.get("ranges") or []:
                    intro = fixed = last = ""
                    for ev in rng.get("events") or []:
                        if "introduced" in ev and not intro:
                            intro = str(ev["introduced"])
                        if "fixed" in ev and not fixed:
                            fixed = str(ev["fixed"])
                        if "last_affected" in ev and not last:
                            last = str(ev["last_affected"])
                    ranges.append((aid, eco, pname, intro, fixed, last,
                                   ",".join(a.get("versions") or [])[:1000]))
                if not a.get("ranges") and a.get("versions"):
                    ranges.append((aid, eco, pname, "", "", "",
                                   ",".join(a["versions"])[:1000]))
            adv[(aid, eco_default)] = {
                "id": aid, "ecosystem": first_eco, "package": first_pkg, "cve": cve,
                "summary": norm(doc.get("summary") or doc.get("details"), 800),
                "severity": sev, "published": doc.get("published"),
                "modified": doc.get("modified"),
                "url": f"https://osv.dev/vulnerability/{aid}",
                "aliases": ",".join(aliases)[:500],
                "affected": len(affected),
            }
    rows = [(r["id"], "osv", r["ecosystem"], r["package"], r["cve"], r["summary"],
             r["severity"], r["published"], r["modified"], r["url"], r["aliases"],
             r["affected"]) for r in adv.values()]
    con.executemany(
        "INSERT OR REPLACE INTO advisory(source,id,ecosystem,package,cve,summary,"
        "severity,published,modified,url,aliases,affected_count) VALUES ('osv',?,?,?,?,?,?,?,?,?,?,?)",
        [(r[0], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11]) for r in rows])
    # Reloading a zip re-REPLACEs advisory rows; clear their old ranges too so
    # package_range stays in sync instead of accumulating duplicate rows.
    # Index before the per-advisory DELETE below; without it each one scans all of package_range.
    con.execute("CREATE INDEX IF NOT EXISTS pkg_adv ON package_range(advisory_id)")
    con.executemany("DELETE FROM package_range WHERE advisory_id=?",
                    [(r[0],) for r in rows])
    con.executemany(
        "INSERT INTO package_range(advisory_id,ecosystem,package,introduced,fixed,"
        "last_affected,versions) VALUES (?,?,?,?,?,?,?)", ranges)
    con.commit()
    return len(rows)


# ---------------------------------------------------------------- Debian
def load_debian(path: pathlib.Path, con: sqlite3.Connection) -> int:
    """Debian tracker: package -> CVE -> per-release status/fixed version."""
    if not path.exists():
        return 0
    doc = json.loads(path.read_text())
    rows = []
    for pkg, cves in doc.items():
        if not isinstance(cves, dict):
            continue
        for cve, info in cves.items():
            if not CVE_RE.fullmatch(cve):
                continue
            desc = norm((info or {}).get("description"), 500)
            for rel, rinfo in ((info or {}).get("releases") or {}).items():
                rows.append((pkg.lower(), rel, cve, (rinfo or {}).get("status", ""),
                             (rinfo or {}).get("fixed_version", ""),
                             (rinfo or {}).get("urgency", ""), desc))
    con.execute("DELETE FROM debian")
    con.executemany("INSERT INTO debian(package,release,cve,status,fixed,urgency,"
                    "description) VALUES (?,?,?,?,?,?,?)", rows)
    con.commit()
    return len(rows)


# ---------------------------------------------------------------- Microsoft
def _sev_from_cvss(score: float) -> str:
    """Microsoft severity label derived from a CVSS base score (used only when
    MSRC omits the label but ships a score)."""
    return ("Critical" if score >= 9 else "Important" if score >= 7
            else "Moderate" if score >= 4 else "Low")


def load_msrc(path: pathlib.Path, con: sqlite3.Connection) -> int:
    """MSRC Security Update Guide: CVE, title, severity, impact, product tag."""
    if not path.exists():
        return 0
    rows = []
    for v in json.loads(path.read_text()):
        cid = v.get("cveNumber")
        if not cid:
            continue
        title = v.get("cveTitle") or ""
        impact = MSRC_IMPACT.get(v.get("impact") or "", "")
        if not impact:
            low = title.lower()
            for kw, val in (("remote code execution", "RCE"),
                            ("elevation of privilege", "EoP"),
                            ("information disclosure", "InfoDisclosure"),
                            ("denial of service", "DoS"),
                            ("security feature bypass", "Bypass"),
                            ("spoofing", "Spoofing"),
                            ("tampering", "Tampering")):
                if kw in low:
                    impact = val
                    break
        severity = MSRC_SEVERITY.get(v.get("severityId"), "")
        raw_sev = (v.get("severity") or "").strip()
        if raw_sev and raw_sev.lower() != "none":
            severity = raw_sev
        if not severity:                       # recover from a CVSS score if present
            score = v.get("baseScore")
            if not score:
                for sset in (v.get("cvssScoreSets") or []):
                    if sset.get("baseScore"):
                        score = sset["baseScore"]
                        break
            if score:
                try:
                    severity = _sev_from_cvss(float(score))
                except (TypeError, ValueError):
                    pass
        # MSRC sends "Yes"/"No"; the old truthiness test marked 13.4k "No" rows.
        exploited = "exploited" if str(v.get("exploited") or "").lower() == "yes" else ""
        rows.append((
            cid, "windows", (v.get("tag") or "Microsoft").lower(),
            f"{(v.get('releaseNumber') or '')}",
            title, severity, impact, exploited,
            v.get("releaseDate") or "",
            v.get("mitreUrl") or f"https://msrc.microsoft.com/update-guide/vulnerability/{cid}",
        ))
    con.execute("DELETE FROM os_advisory WHERE source='msrc'")
    con.executemany(
        "INSERT OR REPLACE INTO os_advisory(source,cve,platform,product,version,title,"
        "severity,impact,exploited,released,url) VALUES ('msrc',?,?,?,?,?,?,?,?,?,?)", rows)
    con.commit()
    return len(rows)


# ---------------------------------------------------------------- Apple
APPLE_ROWS = re.compile(
    r'<a href="(https://support\.apple\.com/en-us/\d+)"[^>]*>([^<]+)</a>.*?'
    r'<td[^>]*><p[^>]*>(.*?)</p></td>\s*<td[^>]*><p[^>]*>([^<]*)</p></td>',
    re.S)


def load_apple(root: pathlib.Path, con: sqlite3.Connection) -> int:
    """Apple security releases: product/version -> CVE list scraped from advisories."""
    index = root / "index.html"
    if not index.exists():
        return 0
    html = index.read_text(encoding="utf-8", errors="replace")
    rows = []
    for url, title, _devices, date in APPLE_ROWS.findall(html):
        title = re.sub(r"\s+", " ", title).strip()
        page = root / "pages" / (url.rsplit("/", 1)[-1] + ".html")
        cves: list[str] = []
        exploited_map: dict[str, str] = {}
        if page.exists():
            txt = page.read_text(encoding="utf-8", errors="replace")
            cves = sorted({c.upper() for c in CVE_RE.findall(txt)})
            # Apple notes exploitation in each CVE's block, just before its id:
            # attribute "exploited" to a CVE if the phrase is in its preceding segment.
            last = 0
            for m in CVE_RE.finditer(txt):
                seg = txt[last:m.start()]
                if re.search(r"(actively )?(been )?exploited", seg, re.I) and \
                   re.search(r"aware|report|exploited in", seg, re.I):
                    exploited_map[m.group(0).upper()] = "exploited"
                last = m.start()
        platform = "macos" if title.lower().startswith("macos") else \
            "ios" if any(k in title.lower() for k in ("ios", "ipados")) else "apple"
        version = ""
        m = re.search(r"(\d+(?:\.\d+)*)", title)
        if m:
            version = m.group(1)
        if not cves:
            rows.append(("APPLE:" + url.rsplit("/", 1)[-1], "", platform, title.lower(),
                         version, title, "", "", "", date.strip(), url))
            continue
        for c in cves:
            rows.append(("APPLE:" + url.rsplit("/", 1)[-1], c, platform, title.lower(),
                         version, title, "", "", exploited_map.get(c, ""), date.strip(), url))
    con.execute("DELETE FROM os_advisory WHERE source='apple'")
    con.executemany(
        "INSERT OR REPLACE INTO os_advisory(source,cve,platform,product,version,title,"
        "severity,impact,exploited,released,url) VALUES ('apple',?,?,?,?,?,?,?,?,?,?)",
        [(r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10]) for r in rows])
    con.commit()
    return len(rows)


# ---------------------------------------------------------------- Metasploit
NAME_RE = re.compile(r"'Name'\s*=>\s*['\"](.+?)['\"]")
PLAT_RE = re.compile(r"'Platform'\s*=>\s*(.+)$", re.M)
PRIV_RE = re.compile(r"'Privileged'\s*=>\s*(true|false)")
DATE_RE = re.compile(r"'DisclosureDate'\s*=>\s*['\"](.+?)['\"]")
DESC_RE = re.compile(r"'Description'\s*=>\s*%q\{(.*?)\}\s*,?\s*$", re.S | re.M)


def load_msf_source(root: pathlib.Path, con: sqlite3.Connection) -> int:
    """Parse module sources for metadata + CVE references (fixes cve_msf)."""
    mods = root / "modules"
    if not mods.exists():
        return 0
    rows, pairs = [], []
    for p in mods.rglob("*.rb"):
        rel = p.relative_to(root).as_posix()
        parts = rel.split("/")
        if len(parts) < 3:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        name_m = NAME_RE.search(text)
        platform = ""
        pm = PLAT_RE.search(text)
        if pm:
            platform = re.sub(r"[\s%w\[\]'\"]", "", pm.group(1))[:60]
        dm = DESC_RE.search(text)
        date_m = DATE_RE.search(text)
        priv = PRIV_RE.search(text)
        cves = sorted({c.upper() for c in CVE_RE.findall(text)})
        rows.append((rel, parts[1],
                     name_m.group(1) if name_m else "/".join(parts[2:]).removesuffix(".rb"),
                     platform, 1 if (priv and priv.group(1) == "true") else 0,
                     date_m.group(1) if date_m else "",
                     norm(dm.group(1) if dm else "", 1200), ",".join(cves)))
        for c in cves:
            pairs.append((c, rel))
    con.execute("DELETE FROM msf")
    con.executemany("INSERT OR REPLACE INTO msf(path,type,name,platform,privileged,"
                    "disclosure_date,description,cves) VALUES (?,?,?,?,?,?,?,?)", rows)
    con.execute("DELETE FROM cve_msf")
    con.executemany("INSERT OR IGNORE INTO cve_msf VALUES (?,?)", pairs)
    con.execute("UPDATE cve SET has_msf=0 WHERE has_msf=1")
    con.execute("UPDATE cve SET has_msf=1 WHERE id IN (SELECT cve_id FROM cve_msf)")
    con.commit()
    return len(rows)


# ---------------------------------------------------------------- Exploit-DB code
CODE_EXT = {".c", ".cc", ".cpp", ".py", ".rb", ".pl", ".sh", ".php", ".js", ".java",
            ".go", ".rs", ".txt", ".md", ".html", ".xml", ".ps1", ".asm", ".s"}
CODE_CAP = 60_000


def load_exploit_code(root: pathlib.Path, con: sqlite3.Connection) -> int:
    """Full Exploit-DB sources -> FTS over the code itself."""
    if not root.exists():
        return 0
    con.execute("DELETE FROM exploit_code_fts")
    n = 0
    batch = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in CODE_EXT:
            continue
        try:
            if p.stat().st_size > 400_000:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        eid = p.stem if p.stem.isdigit() else ""
        batch.append((eid, rel, text[:CODE_CAP]))
        n += 1
        if len(batch) >= 500:
            con.executemany("INSERT INTO exploit_code_fts(exploit_id,path,content) VALUES (?,?,?)", batch)
            batch = []
    if batch:
        con.executemany("INSERT INTO exploit_code_fts(exploit_id,path,content) VALUES (?,?,?)", batch)
    con.commit()
    return n


# ---------------------------------------------------------------- toolkits
def load_toolkit(root: pathlib.Path, source: str, con: sqlite3.Connection) -> int:
    if not root.exists():
        return 0
    if source == "gtfobins":
        # Jekyll collection: files have no extension (e.g. _gtfobins/awk)
        files = [p for p in (root / "_gtfobins").rglob("*") if p.is_file()]
    else:
        files = (list(root.rglob("*.md")) + list(root.rglob("*.yml"))
                 + list(root.rglob("*.yaml")))
    rows = []
    for p in sorted(files)[:8000]:
        if ".git" in p.parts:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name = p.stem
        rel = p.relative_to(root).as_posix()
        # frontmatter: functions/tags block, else the first heading or description
        tags = ""
        m = re.search(r"^functions:\s*\n((?:[ \t]+\w+:.*\n?)+)", text, re.M)
        if m:
            tags = ",".join(sorted(set(re.findall(r"^[ \t]{2}(\w+):", m.group(1), re.M))))
        if not tags:
            m = re.search(r"^(?:functions|tags):\s*(.+)$", text, re.M)
            if m:
                tags = norm(m.group(1), 200)
        desc = ""
        dm = re.search(r"^description:\s*(.+)$", text, re.M)
        if dm:
            desc = norm(dm.group(1), 400)
        body = re.sub(r"^---.*?---", "", text, flags=re.S)
        if not desc:
            heading = re.search(r"^#\s+(.+)$", body, re.M)
            desc = norm(heading.group(1) if heading else body, 400)
        rows.append((source, name, rel, desc, tags))
    con.execute("DELETE FROM toolkit WHERE source=?", (source,))
    con.executemany("INSERT INTO toolkit(source,name,path,description,tags) VALUES (?,?,?,?,?)", rows)
    con.execute("DELETE FROM toolkit_fts WHERE source=?", (source,))
    con.executemany("INSERT INTO toolkit_fts(source,name,description,tags) VALUES (?,?,?,?)",
                    [(r[0], r[1], r[3], r[4]) for r in rows])
    con.commit()
    return len(rows)
