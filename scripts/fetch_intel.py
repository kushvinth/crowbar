#!/usr/bin/env python3
"""Fetch free vulnerability-intelligence sources into ``data/intel/``.

This is a raw-intel fetcher, not a loader: archives and feeds land on disk with a
SHA-256 manifest so a later loader can parse them without re-downloading.  It is
stdlib-only and resumable; run it again after an interruption.

    uv run python scripts/fetch_intel.py --list
    uv run python scripts/fetch_intel.py              # all sources
    uv run python scripts/fetch_intel.py --only cveorg-cvelist,project-zero
    uv run python scripts/fetch_intel.py --force      # re-download everything

Sources that need an API key, account, or scraping behind a terms-of-service
wall are listed in ``data/intel/README.md`` instead of being fetched blindly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "intel"
MANIFEST = OUT / "manifest.json"
UA = "crowbar-intel-fetcher/1.0 (+local research; contact: none)"


def _src(name, url, path, kind, note="", headers=None):
    return {
        "name": name,
        "url": url,
        "path": path,
        "kind": kind,
        "note": note,
        "headers": headers or {},
    }


SOURCES = [
    _src(
        "cveorg-cvelist",
        "https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main",
        "cveorg/cvelistV5-main.tar.gz",
        "tar",
        "MITRE CVE List v5: CNA metadata, affected products, references.",
    ),
    _src(
        "ghsa-advisories",
        "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main",
        "ghsa/advisory-database-main.tar.gz",
        "tar",
        "GitHub Advisory Database, OSV-format JSON for every GHSA ecosystem.",
    ),
    _src(
        "poc-in-github",
        "https://codeload.github.com/nomi-sec/PoC-in-GitHub/tar.gz/refs/heads/master",
        "poc-in-github/PoC-in-GitHub-master.tar.gz",
        "tar",
        "CVE -> public GitHub PoC references (one JSON per CVE).",
    ),
    _src(
        "project-zero",
        "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
        "project-zero/blog.rss",
        "rss",
        "Project Zero blog: 0-day writeups and root-cause analysis.",
    ),
    _src(
        "zdi-published-rss",
        "https://www.zerodayinitiative.com/rss/published/",
        "zdi/published.rss",
        "rss",
        "ZDI published advisories feed.",
    ),
    _src(
        "zdi-published-html",
        "https://www.zerodayinitiative.com/advisories/published/",
        "zdi/published.html",
        "html",
        "Full published-advisory listing (RSS is recent-only).",
    ),
    _src(
        "zdi-upcoming-html",
        "https://www.zerodayinitiative.com/advisories/upcoming/",
        "zdi/upcoming.html",
        "html",
        "Upcoming / not-yet-published ZDI advisories (0-day pipeline).",
    ),
    _src(
        "cisa-all-advisories",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "cisa/all-advisories.xml",
        "rss",
        "CISA alerts and ICS advisories (single RSS feed).",
    ),
    _src(
        "certcc-vuls",
        "https://www.kb.cert.org/vuls/",
        "certcc/vuls.html",
        "html",
        "CERT/CC vulnerability notes listing.",
    ),
    _src(
        "fulldisclosure",
        "https://seclists.org/rss/fulldisclosure.rss",
        "seclists/fulldisclosure.rss",
        "rss",
        "Full Disclosure mailing list: public 0-day and exploit disclosures.",
    ),
    _src(
        "cisco-advisories",
        "https://sec.cloudapps.cisco.com/security/center/rss.x?i=44",
        "cisco/advisories.html",
        "html",
        "Cisco PSIRT feed index (the XML feeds below are the real payload).",
    ),
    _src(
        "cisco-advisory-rss",
        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "cisco/advisories.xml",
        "rss",
        "Cisco security advisories, RSS 2.0.",
    ),
    _src(
        "cisco-csaf",
        "https://sec.cloudapps.cisco.com/security/center/csaf_20.xml",
        "cisco/csaf.xml",
        "xml",
        "Cisco CSAF 2.0 advisory index.",
    ),
    _src(
        "fortinet-psirt",
        "https://www.fortiguard.com/psirt",
        "fortinet/psirt.html",
        "html",
        "Fortinet PSIRT advisory listing.",
    ),
    _src(
        "paloalto-advisories",
        "https://security.paloaltonetworks.com/",
        "paloalto/advisories.html",
        "html",
        "Palo Alto Networks security advisory listing.",
    ),
    _src(
        "citrix-bulletins",
        "https://support.citrix.com/securitybulletins",
        "citrix/bulletins.html",
        "html",
        "Citrix security bulletin index.",
    ),
    _src(
        "vmware-advisories",
        "https://www.vmware.com/security/advisories.html",
        "vmware/advisories.html",
        "html",
        "VMware/Broadcom VMSA index.",
    ),
    _src(
        "zimbra-security",
        "https://wiki.zimbra.com/wiki/Security_Center",
        "zimbra/security.html",
        "html",
        "Zimbra Security Center.",
    ),
    _src(
        "sap-security-notes",
        "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html",
        "sap/security-notes.html",
        "html",
        "SAP Security Notes / Patch Day index.",
    ),
    _src(
        "f5-advisories",
        "https://my.f5.com/manage/s/article/K4602",
        "f5/advisories.html",
        "html",
        "F5 security advisory index (K4602).",
    ),
    _src(
        "sonicwall-psirt",
        "https://psirt.global.sonicwall.com/v3/guidance/",
        "sonicwall/psirt.html",
        "html",
        "SonicWall PSIRT guidance index (JS app shell).",
    ),
    _src(
        "oracle-cpu",
        "https://www.oracle.com/security-alerts/",
        "oracle/cpu.html",
        "html",
        "Oracle Critical Patch Update index.",
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126 Safari/537.36"
        },
    ),
]

BY_NAME = {s["name"]: s for s in SOURCES}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def load_manifest() -> dict:
    if MANIFEST.exists():
        try:
            return json.loads(MANIFEST.read_text())
        except json.JSONDecodeError:
            pass
    return {"generated_at": now(), "sources": {}}


def save_manifest(data: dict) -> None:
    # Merge with whatever is on disk: two fetchers may run at once (e.g. bulk
    # archives in one shell, vendor snapshots in another).  Union by source name
    # instead of letting the last writer drop the other run's entries.
    disk = load_manifest()
    disk["sources"].update(data.get("sources", {}))
    data = disk
    data["generated_at"] = now()
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    tmp = MANIFEST.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, MANIFEST)


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(src: dict, force: bool = False) -> dict:
    dest = OUT / src["path"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")

    if dest.exists() and not force:
        size = dest.stat().st_size
        print(f"  cached  {src['name']:<22} {human(size):>9}  {dest.relative_to(ROOT)}")
        return {
            "url": src["url"],
            "path": str(dest.relative_to(ROOT)),
            "kind": src["kind"],
            "bytes": size,
            "sha256": sha256(dest),
            "fetched_at": datetime.fromtimestamp(dest.stat().st_mtime, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "note": src["note"],
        }

    if tmp.exists() and not force:
        start = tmp.stat().st_size
        print(f"  resume  {src['name']:<22} at {human(start)}")
    else:
        start = 0
        tmp.unlink(missing_ok=True)

    req = urllib.request.Request(src["url"], headers={"User-Agent": UA, **src.get("headers", {})})
    if start:
        req.add_header("Range", f"bytes={start}-")
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            status = getattr(resp, "status", 200)
            if status == 206 and start:
                mode = "ab"
            else:
                start = 0
                mode = "wb"
            total = resp.headers.get("Content-Length")
            total = int(total) + start if total else 0
            t0 = time.time()
            last = 0.0
            with tmp.open(mode) as f:
                while True:
                    chunk = resp.read(1024 * 256)
                    if not chunk:
                        break
                    f.write(chunk)
                    done = f.tell()
                    if time.time() - last > 2:
                        rate = done / max(time.time() - t0, 0.1)
                        pct = f"{done * 100 / total:5.1f}%" if total else "     "
                        print(
                            f"\r  get     {src['name']:<22} {pct} {human(done):>9} {human(int(rate))}/s",
                            end="",
                            flush=True,
                        )
                        last = time.time()
            print()
    except urllib.error.HTTPError as e:
        print(f"\n  FAIL    {src['name']}: HTTP {e.code} {e.reason}", file=sys.stderr)
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"\n  FAIL    {src['name']}: {e}", file=sys.stderr)
        raise

    os.replace(tmp, dest)
    size = dest.stat().st_size
    print(f"  done    {src['name']:<22} {human(size):>9}  {dest.relative_to(ROOT)}")
    return {
        "url": src["url"],
        "path": str(dest.relative_to(ROOT)),
        "kind": src["kind"],
        "bytes": size,
        "sha256": sha256(dest),
        "fetched_at": now(),
        "note": src["note"],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", help="comma-separated source names (see --list)")
    ap.add_argument("--force", action="store_true", help="re-download even if cached")
    ap.add_argument("--list", action="store_true", help="list sources and exit")
    args = ap.parse_args()

    if args.list:
        for s in SOURCES:
            print(f"{s['name']:<22} {s['kind']:<5} {s['url']}")
        return 0

    if args.only:
        names = [n.strip() for n in args.only.split(",") if n.strip()]
        unknown = [n for n in names if n not in BY_NAME]
        if unknown:
            print(f"unknown source(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        selected = [BY_NAME[n] for n in names]
    else:
        selected = SOURCES

    manifest = load_manifest()
    print(f"fetching {len(selected)} source(s) into {OUT.relative_to(ROOT)}")
    failed = []
    for src in selected:
        try:
            manifest["sources"][src["name"]] = download(src, force=args.force)
            save_manifest(manifest)
        except Exception:
            failed.append(src["name"])

    total = sum(v.get("bytes", 0) for v in manifest["sources"].values())
    print(f"\nmanifest: {MANIFEST.relative_to(ROOT)} · {len(manifest['sources'])} sources · {human(total)}")
    if failed:
        print(f"failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
