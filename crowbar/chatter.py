"""Where people post about CVEs: HN, oss-security, Full Disclosure, ZDI, Mastodon,
and ENISA's exploited list. Each source is fetched into an append-only JSONL archive
(feeds only show their latest items, so history lives on disk) and loaded into
`mention(source, cve_id, url, title, posted_at, score)`."""
from __future__ import annotations

import json
import pathlib
import re
import sqlite3
import time
from datetime import datetime, timezone

from . import paths

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TAG_RE = re.compile(r"<[^>]+>")
SCHEMA = """
CREATE TABLE IF NOT EXISTS mention(source TEXT, cve_id TEXT, url TEXT, title TEXT,
  posted_at TEXT, score INTEGER, PRIMARY KEY(source, cve_id, url)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS mention_cve ON mention(cve_id, posted_at);
CREATE INDEX IF NOT EXISTS mention_posted ON mention(posted_at);
"""
SOURCES = {   # name -> (url shown in the registry, note)
    "hn": ("https://hn.algolia.com/api/v1/search_by_date", "Hacker News stories naming a CVE"),
    "oss-security": ("https://seclists.org/rss/oss-sec.rss", "oss-security mailing list"),
    "fulldisclosure": ("https://seclists.org/rss/fulldisclosure.rss", "Full Disclosure mailing list"),
    "zdi": ("https://www.zerodayinitiative.com/rss/published/", "Zero Day Initiative advisories"),
    "mastodon": ("https://mastodon.social/api/v1/timelines/tag/cve", "Mastodon #cve posts (bots skipped)"),
    "euvd-exploited": ("https://euvdservices.enisa.europa.eu/api/search?exploited=true",
                       "ENISA EUVD exploited vulnerabilities (EU counterpart to CISA KEV)"),
}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cves(*texts: str | None) -> list[str]:
    return sorted({c.upper() for t in texts if t for c in CVE_RE.findall(t)})


def _get(url: str) -> str:
    from .datasets import http_text   # datasets imports this module
    return http_text(url, timeout=60)


def _rss(url: str) -> list[dict]:
    import xml.etree.ElementTree as ET
    from email.utils import parsedate_to_datetime
    out = []
    for item in ET.fromstring(_get(url)).iter("item"):
        title, desc = item.findtext("title") or "", item.findtext("description") or ""
        pub = item.findtext("pubDate")
        out.append({"url": item.findtext("link"), "title": title.strip(),
                    "posted_at": _iso(parsedate_to_datetime(pub)) if pub else None,
                    "score": None, "cves": _cves(title, desc)})
    return out


def _hn(since: int) -> list[dict]:
    import urllib.parse
    out, year = [], time.gmtime().tm_year
    for y in (year, year - 1):
        for page in range(20):
            q = urllib.parse.urlencode({"query": f'"CVE-{y}"', "tags": "story", "hitsPerPage": 1000,
                                        "page": page, "numericFilters": f"created_at_i>{since}"})
            hits = json.loads(_get(f"{SOURCES['hn'][0]}?{q}")).get("hits", [])
            for h in hits:
                out.append({"url": f"https://news.ycombinator.com/item?id={h['objectID']}",
                            "title": h.get("title") or "", "score": h.get("points"),
                            "posted_at": _iso(datetime.fromtimestamp(h["created_at_i"], timezone.utc)),
                            "cves": _cves(h.get("title"), h.get("url"), h.get("story_text"))})
            if len(hits) < 1000:
                break
    return out


def _mastodon() -> list[dict]:
    out, max_id = [], None
    for _ in range(10):   # 400 newest posts; older ones are already archived
        q = "?limit=40" + (f"&max_id={max_id}" if max_id else "")
        posts = json.loads(_get(SOURCES["mastodon"][0] + q))
        for p in posts:
            if p.get("account", {}).get("bot"):
                continue
            text = TAG_RE.sub(" ", p.get("content") or "")
            out.append({"url": p["url"], "title": " ".join(text.split())[:200],
                        "posted_at": _iso(datetime.fromisoformat(p["created_at"].replace("Z", "+00:00"))),
                        "score": (p.get("favourites_count") or 0) + (p.get("reblogs_count") or 0),
                        "cves": _cves(text)})
        if len(posts) < 40:
            break
        max_id = posts[-1]["id"]
    return out


def _euvd() -> list[dict]:
    out = []
    for page in range(100):
        doc = json.loads(_get(f"{SOURCES['euvd-exploited'][0]}&size=100&page={page}"))
        for v in doc.get("items", []):
            since = v.get("exploitedSince") or v.get("datePublished")
            out.append({"url": f"https://euvd.enisa.europa.eu/vulnerability/{v['id']}",
                        "title": f"{v['id']} exploited",
                        "posted_at": _iso(datetime.strptime(since, "%b %d, %Y, %I:%M:%S %p")
                                          .replace(tzinfo=timezone.utc)) if since else None,
                        "score": None, "cves": _cves(v.get("aliases"))})
        if (page + 1) * 100 >= doc.get("total", 0):
            break
    return out


def fetch(name: str, dest: pathlib.Path) -> int:
    """Merge the source's current items into its JSONL archive; returns the file size."""
    old = {}
    if dest.exists():
        for line in dest.read_text().splitlines():
            r = json.loads(line)
            old[r["url"]] = r
    if name == "hn":
        newest = max((r["posted_at"] for r in old.values() if r["posted_at"]), default=None)
        since = (int(datetime.fromisoformat(newest.replace("Z", "+00:00")).timestamp()) - 86400
                 if newest else int(time.time()) - 90 * 86400)
        items = _hn(since)
    elif name == "mastodon":
        items = _mastodon()
    elif name == "euvd-exploited":
        items = _euvd()
    else:
        items = _rss(SOURCES[name][0])
    for r in items:
        if r["cves"] and r["url"]:
            old[r["url"]] = r   # newer copy wins: scores grow
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    tmp.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in old.values()))
    tmp.replace(dest)
    return dest.stat().st_size


def load(con: sqlite3.Connection) -> int:
    """Replace `mention` with every archived post (a few thousand rows: cheap)."""
    con.executescript(SCHEMA)
    con.execute("DELETE FROM mention")
    rows = []
    for name in SOURCES:
        f = paths.DATA / f"chatter/{name}.jsonl"
        if not f.exists():
            continue
        for line in f.read_text().splitlines():
            r = json.loads(line)
            rows += [(name, c, r["url"], r["title"], r["posted_at"], r["score"]) for c in r["cves"]]
    con.executemany("INSERT OR IGNORE INTO mention VALUES (?,?,?,?,?,?)", rows)
    return len(rows)
