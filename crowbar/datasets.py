"""Dataset registry, downloader, and freshness tracking."""
from __future__ import annotations

import calendar
import concurrent.futures as cf
import hashlib
import json
import os
import pathlib
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from . import db, paths

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None

from crowbar import __version__ as _V
UA = f"crowbar/{_V} (+https://github.com/kushvinth/crowbar)"

# A mirror is a flat directory made by `crowbar pack`, hosted wherever the
# maintainer chooses. Set it here to make it the default for every user;
# CROWBAR_MIRROR overrides it, and CROWBAR_MIRROR= (empty) forces upstream.
DEFAULT_MIRROR = ""


def mirror_url() -> str:
    return os.environ.get("CROWBAR_MIRROR", DEFAULT_MIRROR).rstrip("/")

# NVD's CDN resets connections when one client opens several at once
_HOST_SLOTS: dict[str, threading.BoundedSemaphore] = {}
_HOST_LOCK = threading.Lock()


def _host_slot(url: str) -> threading.BoundedSemaphore:
    host = urllib.parse.urlsplit(url).hostname or ""
    with _HOST_LOCK:
        return _HOST_SLOTS.setdefault(host, threading.BoundedSemaphore(2))


@dataclass
class Dataset:
    name: str
    group: str
    kind: str            # http | git
    url: str
    dest: str
    note: str
    tier: str = "core"   # core | extra | bulk
    sparse: str | None = None
    optional: bool = False

    @property
    def path(self) -> pathlib.Path:
        return paths.DATA / self.dest


def _nvd(year: int, kind: str = "year") -> Dataset:
    if kind == "year":
        return Dataset(f"nvd-{year}", "nvd", "http",
                       f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz",
                       f"nvd/nvdcve-2.0-{year}.json.gz", f"NVD CVE feed, year {year}")
    return Dataset(f"nvd-{kind}", "nvd", "http",
                   f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{kind}.json.gz",
                   f"nvd/nvdcve-2.0-{kind}.json.gz",
                   f"NVD CVE {kind} feed (last 8 days of changes)")


CORE_INTEL = [
    Dataset("cveorg-cvelist", "cveorg", "http",
            "https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main",
            "intel/cveorg/cvelistV5-main.tar.gz",
            "MITRE CVE List v5 (CNA records, affected products, references)"),
    Dataset("poc-in-github", "poc", "http",
            "https://codeload.github.com/nomi-sec/PoC-in-GitHub/tar.gz/refs/heads/master",
            "intel/poc-in-github/PoC-in-GitHub-master.tar.gz",
            "PoC-in-GitHub (public PoC repo metadata; never executed)"),
    Dataset("epss", "epss", "http",
            "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
            "epss/epss_scores-current.csv.gz", "FIRST EPSS exploit-prediction scores"),
    Dataset("kev", "kev", "http",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "kev/known_exploited_vulnerabilities.json", "CISA Known Exploited Vulnerabilities"),
    Dataset("cwe", "cwe", "http", "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
            "cwe/cwec_latest.xml.zip", "MITRE CWE taxonomy"),
    Dataset("capec", "capec", "http", "https://capec.mitre.org/data/xml/capec_latest.xml",
            "capec/capec_latest.xml", "MITRE CAPEC attack patterns"),
    Dataset("exploitdb", "exploitdb", "http",
            "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
            "exploitdb/files_exploits.csv", "Exploit-DB index (46k entries)"),
    Dataset("exploitdb-shellcodes", "exploitdb", "http",
            "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_shellcodes.csv",
            "exploitdb/files_shellcodes.csv", "Exploit-DB shellcode index"),
    Dataset("nuclei", "nuclei", "git", "https://github.com/projectdiscovery/nuclei-templates.git",
            "nuclei/templates", "Nuclei template library (YAML)"),
    Dataset("metasploit", "metasploit", "http",
            "https://api.github.com/repos/rapid7/metasploit-framework/git/trees/master?recursive=1",
            "metasploit/tree.json", "Metasploit module tree"),
    Dataset("models", "models", "http", "https://models.dev/api.json",
            "models/models.dev.json", "LLM catalog: providers, context, price"),
]

OSV_ECOSYSTEMS = [
    ("npm", 209), ("PyPI", 35), ("Go", 12), ("Maven", 10), ("NuGet", 3),
    ("RubyGems", 5), ("crates.io", 3), ("Packagist", 10), ("Debian", 73), ("Alpine", 4),
]

BULK_INTEL = [
    *[Dataset(f"osv-{eco.lower()}", "osv", "http",
              f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip",
              f"osv/{eco}.zip", f"OSV advisories for {eco} (GHSA + ecosystem DBs)",
              tier="bulk")
      for eco, _ in OSV_ECOSYSTEMS],
    Dataset("exploitdb-full", "exploitdb", "git",
            "https://gitlab.com/exploit-database/exploitdb.git",
            "exploitdb/full", "Exploit-DB full sources (code search, 47k files)",
            tier="bulk", sparse="exploits"),
    Dataset("msrc", "vendor", "msrc",
            "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability",
            "msrc/sug.json", "MSRC Security Update Guide (Windows/Edge CVEs, severity, impact)"),
    Dataset("apple", "vendor", "apple", "https://support.apple.com/en-us/100100",
            "apple", "Apple security releases (iOS/iPadOS/macOS/watchOS advisories)"),
    Dataset("debian-tracker", "debian", "http",
            "https://security-tracker.debian.org/tracker/data/json",
            "debian/tracker.json", "Debian security tracker (per-package fixed versions)"),
]

EXTRA_INTEL = [
    Dataset("attack-mobile", "attack", "http",
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
            "attack/mobile-attack.json", "ATT&CK Mobile STIX", tier="extra"),
    Dataset("attack-ics", "attack", "http",
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
            "attack/ics-attack.json", "ATT&CK ICS STIX", tier="extra"),
    Dataset("vulnrichment", "vulnrichment", "git", "https://github.com/cisagov/vulnrichment.git",
            "vulnrichment", "CISA Vulnrichment (SSVC decision points, ADP data)", tier="extra"),
]

TOOLKIT = [
    Dataset("gtfobins", "toolkit", "git", "https://github.com/GTFOBins/GTFOBins.github.io.git",
            "toolkit/gtfobins", "GTFOBins (unix binary abuse)"),
    Dataset("lolbas", "toolkit", "git", "https://github.com/LOLBAS-Project/LOLBAS.git",
            "toolkit/lolbas", "LOLBAS (windows binary abuse)"),
    Dataset("payloads", "toolkit", "git", "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
            "toolkit/payloads", "PayloadsAllTheThings (payload cheat sheets)"),
    Dataset("msf-source", "metasploit", "git", "https://github.com/rapid7/metasploit-framework.git",
            "metasploit/source", "Metasploit module sources (metadata + CVE refs)",
            sparse="modules"),
]


def attack_enterprise() -> Dataset:
    return Dataset("attack-enterprise", "attack", "http",
                   "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
                   "enterprise-attack/enterprise-attack.json",
                   "attack/enterprise-attack.json", "ATT&CK Enterprise STIX")


def registry(with_extra: bool = False, with_bulk: bool = False) -> list[Dataset]:
    items = [_nvd(y) for y in paths.YEARS]
    items += [_nvd(0, "recent"), _nvd(0, "modified")]
    items += CORE_INTEL + TOOLKIT
    items.append(attack_enterprise())
    if with_extra or with_bulk:
        items += EXTRA_INTEL
    if with_bulk:
        items += BULK_INTEL
    return items


def plan(only: list[str] | None = None, years: list[int] | None = None,
         with_extra: bool = False, with_bulk: bool = False) -> list[Dataset]:
    items = registry(with_extra=True, with_bulk=True)
    if years:
        keep = set(years)
        items = [d for d in items if not d.name.startswith("nvd-2") or int(d.name.split("-")[1]) in keep]
    if only:
        want = {s.strip().lower() for s in only if s.strip()}
        # explicitly named extra datasets are always honoured
        items = [d for d in items if d.name in want
                 or (d.group in want and (d.tier == "core" or with_extra or with_bulk))]
    else:
        items = [d for d in items
                 if d.tier == "core" or (with_extra and d.tier == "extra")
                 or (with_bulk and d.tier in ("extra", "bulk"))]
    return items


# ---------------------------------------------------------------- risk tiers
# User-facing size tiers, each a superset of the one above. Expressed as the set
# of dataset groups to include (reusing plan()); build() then loads whatever was
# synced, so a lite sync + build yields a lite index with no extra wiring.
TIER_NAMES = ["lite", "medium", "heavy", "extreme"]
TIER_SIZES = {"lite": "~150MB", "medium": "~500MB", "heavy": "~2GB", "extreme": "full"}
_TIER_ADD = {
    "lite":   {"nvd", "kev", "epss", "cwe"},
    "medium": {"cveorg", "capec", "attack", "vulnrichment"},
    "heavy":  {"exploitdb", "nuclei", "metasploit", "osv", "poc", "toolkit"},
    # extreme == every source (handled in tier_plan)
}


def tier_groups(tier: str) -> set[str]:
    out: set[str] = set()
    for t in TIER_NAMES:
        out |= _TIER_ADD.get(t, set())
        if t == tier:
            break
    return out



def tier_missing(tier: str | None) -> list[str]:
    """Datasets the recorded tier promised but the manifest does not have,
    i.e. downloads that failed or were never run. Empty when no tier is set."""
    if not tier or tier not in TIER_NAMES:
        return []
    expected = {ds.name for ds in tier_plan(tier)}
    present = set(load_manifest().get("datasets", {}).keys())
    return sorted(expected - present)


def tier_plan(tier: str) -> list[Dataset]:
    """Datasets for a risk tier. lite keeps only the last 2 NVD years plus the
    recent/modified feeds; medium and up take the full NVD history."""
    tier = (tier or "").lower()
    if tier not in TIER_NAMES:
        raise ValueError(f"unknown tier {tier!r}; choose: {', '.join(TIER_NAMES)}")
    if tier == "extreme":
        return plan(with_extra=True, with_bulk=True)
    years = list(paths.YEARS[-2:]) if tier == "lite" else None
    return plan(only=sorted(tier_groups(tier)), years=years,
                with_extra=True, with_bulk=True)


# ---------------------------------------------------------------- manifest
def load_manifest() -> dict:
    if paths.MANIFEST.exists():
        try:
            return json.loads(paths.MANIFEST.read_text())
        except json.JSONDecodeError:
            pass
    return {"datasets": {}}


def save_manifest(m: dict) -> None:
    paths.ensure_dirs()
    m["generated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    paths.MANIFEST.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------- helpers
def sha256(path: pathlib.Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def http_get(url: str, dest: pathlib.Path, retries: int = 7, timeout: int = 180,
             since: str | None = None) -> tuple[int, str] | None:
    """Download atomically. Returns (bytes, last_modified) or None on HTTP 304."""
    import email.utils  # noqa: F401
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    if tmp.exists():
        tmp.unlink()                       # start clean; resume only within this call
    last: Exception | None = None
    lm = ""
    failures = 0
    while failures < retries:
        have = start = tmp.stat().st_size if tmp.exists() else 0
        try:
            headers = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity"}
            if since:
                headers["If-Modified-Since"] = since
            if have:
                headers["Range"] = f"bytes={have}-"   # resume a truncated download
            req = urllib.request.Request(url, headers=headers)
            with _host_slot(url), urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 304:
                    return None
                partial = resp.status == 206
                if not partial:
                    have = 0                 # server ignored Range: restart from scratch
                with tmp.open("ab" if partial else "wb") as out:
                    shutil.copyfileobj(resp, out, length=1 << 20)
                lm = resp.headers.get("Last-Modified") or lm
                total = None
                cr = resp.headers.get("Content-Range")       # "bytes X-Y/TOTAL"
                if cr and "/" in cr and cr.rsplit("/", 1)[-1].isdigit():
                    total = int(cr.rsplit("/", 1)[-1])
                elif resp.headers.get("Content-Length") is not None:
                    total = have + int(resp.headers["Content-Length"])
            got = tmp.stat().st_size
            if got == 0:
                raise IOError("empty response")
            if total is not None and got != total:
                # keep .part and resume the remaining bytes on the next attempt
                raise IOError(f"truncated: {got}/{total} bytes (resuming)")
            tmp.replace(dest)
            return dest.stat().st_size, lm
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return None
            if exc.code == 416 and tmp.exists():
                tmp.unlink()                 # range unsatisfiable: our .part is stale
            last = exc
            failures += 1
        except Exception as exc:  # noqa: BLE001
            last = exc                       # keep .part: a truncation only grows toward total
            # a reset mid-stream that still moved bytes is progress, not a failure
            # (NVD drops long transfers); the file size bounds how often this repeats
            grew = tmp.exists() and tmp.stat().st_size > start
            failures = 0 if grew else failures + 1
        if failures < retries:
            time.sleep(min(2 ** max(failures, 1), 30) + random.uniform(0, 2))
    if tmp.exists():
        tmp.unlink()                         # give up cleanly; never leave a partial behind
    raise RuntimeError(f"download failed: {url}: {last}")


def http_date(iso: str | None) -> str | None:
    if not iso:
        return None
    import datetime as _dt
    import email.utils
    try:
        dt = _dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return None
    return email.utils.format_datetime(dt, usegmt=True)


APPLE_ROWS = re.compile(
    r'<a href="(https://support\.apple\.com/en-us/\d+)"[^>]*>([^<]+)</a>.*?'
    r'<td[^>]*><p[^>]*>(.*?)</p></td>\s*<td[^>]*><p[^>]*>([^<]*)</p></td>', re.S)


def http_text(url: str, timeout: int = 60) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def msrc_fetch(dest: pathlib.Path) -> int:
    url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"
    rows: list[dict] = []
    while url:
        doc = json.loads(http_text(url, timeout=90))
        rows += doc.get("value", [])
        url = doc.get("@odata.nextLink")
        time.sleep(0.2)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(rows))
    return dest.stat().st_size


def apple_fetch(dest: pathlib.Path) -> int:
    html = http_text("https://support.apple.com/en-us/100100")
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "index.html").write_text(html)
    pages = dest / "pages"
    pages.mkdir(exist_ok=True)
    todo = []
    for url in {u for u, *_ in APPLE_ROWS.findall(html)}:
        page = pages / (url.rsplit("/", 1)[-1] + ".html")
        if not page.exists():
            todo.append((url, page))
    with cf.ThreadPoolExecutor(max_workers=6) as pool:
        def grab(pair):
            url, page = pair
            try:
                page.write_text(http_text(url))
            except Exception:  # noqa: BLE001
                pass
        list(pool.map(grab, todo))
    return sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())


def git_clone(url: str, dest: pathlib.Path, pull: bool = False,
              sparse: str | None = None) -> str:
    if (dest / ".git").exists():
        if not pull:
            return "exists"
        res = subprocess.run(["git", "-C", str(dest), "pull", "--ff-only", "--depth", "1"],
                             capture_output=True, text=True)
        return "pulled" if res.returncode == 0 else "exists"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and not any(dest.iterdir()):
        dest.rmdir()
    target = dest
    if dest.exists():
        # a mirror extract (no .git): clone beside it and swap, so a failed clone keeps it
        target = dest.with_name(dest.name + ".clone")
        shutil.rmtree(target, ignore_errors=True)
    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if sparse:
        cmd += ["--filter=blob:none", "--sparse"]
    cmd += [url, str(target)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0 and sparse:
        subprocess.run(["git", "-C", str(target), "sparse-checkout", "set", sparse],
                       capture_output=True, text=True)
    if res.returncode != 0:
        tail = (res.stderr or res.stdout).strip().splitlines()[-1:] or ["git clone failed"]
        raise RuntimeError(f"{url}: {tail[0]}")
    if target != dest:
        shutil.rmtree(dest)
        target.replace(dest)
    return "cloned"


def git_head(dest: pathlib.Path) -> str:
    """Resolved commit of a cloned repo - the git analogue of a file sha256,
    recorded for provenance. (We fetch a mutable branch tip rather than a
    pinned commit: full pinning needs curated per-repo SHAs + verification
    infra, so this records what was fetched, it does not attest it.)"""
    res = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                         capture_output=True, text=True)
    return res.stdout.strip() if res.returncode == 0 else ""


def mirror_one(d: Dataset, entry: dict, base: str, manifest: dict, force: bool = False) -> dict:
    """Fetch one dataset from a `crowbar pack` mirror, verified against its sha256."""
    rec = manifest["datasets"].get(d.name, {})
    if d.path.exists() and not force and rec.get("mirror_sha256") == entry["sha256"]:
        return {"name": d.name, "status": "same", "bytes": rec.get("bytes", 0)}
    started = time.time()
    url = f"{base}/{urllib.parse.quote(entry['file'])}"
    dl = d.path.with_name(d.path.name + ".mirror")
    new = d.path.with_name(d.path.name + ".new")
    try:
        http_get(url, dl, retries=2)        # a cache: give up fast, upstream retries fully
        if sha256(dl) != entry["sha256"]:
            raise RuntimeError(f"{url}: sha256 does not match the mirror manifest")
        if entry.get("dir"):
            shutil.rmtree(new, ignore_errors=True)
            with tarfile.open(dl) as tf:
                # filter= needs Python >= 3.11.4; rejects absolute paths, .. and devices
                tf.extractall(new, filter="data")
            if d.path.exists():
                shutil.rmtree(d.path)
            new.replace(d.path)
            digest = ""                      # verify hashes files; a dir has no single hash
        else:
            dl.replace(d.path)
            digest = entry["sha256"]
    finally:
        dl.unlink(missing_ok=True)
        shutil.rmtree(new, ignore_errors=True)
    size = entry.get("bytes") or d.path.stat().st_size
    manifest["datasets"][d.name] = {
        "group": d.group, "url": url, "path": d.dest, "bytes": size,
        "sha256": digest, "mirror_sha256": entry["sha256"], "tier": d.tier,
        # when the mirror fetched it upstream: keeps If-Modified-Since honest later
        "fetched_at": entry.get("fetched_at")
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "http_last_modified": "", "note": d.note,
    }
    return {"name": d.name, "status": "ok", "bytes": size, "via": "mirror",
            "secs": round(time.time() - started, 1)}


def sync_one(d: Dataset, manifest: dict, force: bool = False, pull: bool = False,
             mirror: tuple[str, dict] | None = None) -> dict:
    rec = manifest["datasets"].get(d.name, {})
    if mirror and d.name in mirror[1]:
        try:
            return mirror_one(d, mirror[1][d.name], mirror[0], manifest, force)
        except Exception as exc:  # noqa: BLE001
            # upstream is the source of truth, so this is safe for a tampered file too
            print(f"mirror: {d.name}: {str(exc)[:200]}; using upstream", file=sys.stderr)
    started = time.time()
    lm = ""
    drift = False
    try:
        if d.kind == "msrc":
            size, digest = msrc_fetch(d.path), ""
        elif d.kind == "apple":
            size, digest = apple_fetch(d.path), ""
        elif d.kind == "git":
            state = git_clone(d.url, d.path, pull=pull, sparse=d.sparse)
            head = git_head(d.path)
            if state in ("exists", "pulled") and not force:
                if head and d.name in manifest["datasets"]:
                    manifest["datasets"][d.name]["sha256"] = head  # record commit
                return {"name": d.name, "status": state, "bytes": rec.get("bytes", 0),
                        "commit": head[:12]}
            size = sum(f.stat().st_size for f in d.path.rglob("*") if f.is_file())
            digest = head
        else:
            # shortcut: the recorded sha256 is self-referential (file vs its own
            # last hash) - no upstream signature exists for these feeds, so we
            # can't attest authenticity, only make version drift visible.
            if d.path.exists() and not force and rec.get("sha256") and sha256(d.path) == rec["sha256"]:
                return {"name": d.name, "status": "same", "bytes": d.path.stat().st_size}
            got = http_get(d.url, d.path,
                           since=None if force else http_date(rec.get("fetched_at")))
            if got is None:
                return {"name": d.name, "status": "same", "bytes": d.path.stat().st_size}
            size, lm = got
            digest = sha256(d.path)
            drift = bool(rec.get("sha256")) and rec["sha256"] != digest
        manifest["datasets"][d.name] = {
            "group": d.group, "url": d.url, "path": d.dest, "bytes": size,
            "sha256": digest, "tier": d.tier,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "http_last_modified": lm,
            "note": d.note,
        }
        return {"name": d.name, "status": "ok", "bytes": size, "changed": drift,
                "secs": round(time.time() - started, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"name": d.name, "status": "FAIL", "error": str(exc)[:300]}


def sync(items: list[Dataset], force: bool = False, jobs: int = 4,
         pull: bool = False, progress=None) -> list[dict]:
    manifest = load_manifest()
    results: list[dict] = []
    mirror = None
    if base := mirror_url():
        try:
            mirror = (base, json.loads(http_text(f"{base}/manifest.json"))["datasets"])
        except Exception as exc:  # noqa: BLE001
            print(f"mirror {base} unavailable ({exc}); using upstream sources", file=sys.stderr)
    with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futs = {pool.submit(sync_one, d, manifest, force, pull, mirror): d for d in items}
        for fut in cf.as_completed(futs):
            r = fut.result()
            results.append(r)
            if progress:
                progress(r)
    save_manifest(manifest)
    return results


def pack(out: pathlib.Path) -> dict:
    """Write every synced dataset into `out` as a flat mirror for `CROWBAR_MIRROR`:
    files as-is, directories as <name>.tar.gz (no .git), plus manifest.json."""
    out.mkdir(parents=True, exist_ok=True)
    entries: dict[str, dict] = {}
    for name, rec in sorted(load_manifest().get("datasets", {}).items()):
        src = paths.DATA / rec["path"]
        if not src.exists():
            continue
        if src.is_dir():
            dst = out / f"{name}.tar.gz"
            with tarfile.open(dst, "w:gz") as tf:
                for child in sorted(src.iterdir()):
                    if child.name != ".git":
                        tf.add(child, arcname=child.name)
        else:
            dst = out / name
            shutil.copyfile(src, dst)
        entries[name] = {"file": dst.name, "sha256": sha256(dst), "bytes": dst.stat().st_size,
                         "dir": src.is_dir(), "fetched_at": rec.get("fetched_at")}
    doc = {"crowbar": _V, "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "datasets": entries}
    (out / "manifest.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return doc


def freshness(manifest: dict | None = None) -> dict[str, dict]:
    m = manifest or load_manifest()
    return {k: {"fetched_at": v.get("fetched_at"), "bytes": v.get("bytes"),
                "path": v.get("path"), "tier": v.get("tier", "core")}
            for k, v in sorted(m.get("datasets", {}).items())}


# ---------------------------------------------------------------- index age
REFRESH_AFTER_DAYS = 1   # background refresh once the index is a day old
STALE_AFTER_DAYS = 7     # NVD's modified feed covers 8 days; older means a gap


def index_status() -> dict:
    """How old the index is, from the meta rows each build/update writes with the data."""
    try:
        con = db.connect()
    except (db.NotIndexed, sqlite3.Error):
        meta = {}
    else:
        meta = db.meta(con)
        con.close()
    last = max(filter(None, (meta.get("updated_at"), meta.get("built_at"))), default=None)
    age = None
    if last:
        age = round((time.time() - calendar.timegm(time.strptime(last, "%Y-%m-%dT%H:%M:%SZ")))
                    / 86400, 1)
    return {"last_update": last, "age_days": age,
            "stale": age is not None and age > STALE_AFTER_DAYS,
            "tier": load_manifest().get("tier"),
            "auto_update": not os.environ.get("CROWBAR_NO_AUTO_UPDATE")}


_held: list = []   # this process's open lock file; closing it releases the lock


def _flock(f) -> bool:
    if fcntl is None:
        return True
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def acquire_update_lock() -> bool:
    """Hold the writer lock until this process exits; False if another
    sync/build/update already holds it (they share crowbar.db.tmp)."""
    # shortcut: no cross-process lock without fcntl (Windows); add msvcrt.locking if Windows gets CI
    if _held or fcntl is None:
        return True
    try:
        paths.INDEX.mkdir(parents=True, exist_ok=True)
        f = open(paths.INDEX / "update.lock", "a")
    except OSError:   # read-only index: nothing can write it, so there is nothing to guard
        return True
    if not _flock(f):
        f.close()
        return False
    _held.append(f)
    return True


def update_running() -> bool:
    """True while some process holds the writer lock."""
    if _held:
        return True
    lock = paths.INDEX / "update.lock"
    if fcntl is None or not lock.exists():
        return False
    try:
        with open(lock, "a") as f:
            if _flock(f):
                fcntl.flock(f, fcntl.LOCK_UN)
                return False
            return True
    except OSError:
        return False


def refresh_in_background() -> bool:
    """Start a detached `crowbar update` when the index is over a day old.

    At most one attempt per hour (lock file mtime), so an offline machine or a
    failing source does not respawn it on every call, and never while another
    update holds the lock. CROWBAR_NO_AUTO_UPDATE=1 turns it off."""
    s = index_status()
    if not s["auto_update"] or s["age_days"] is None or s["age_days"] < REFRESH_AFTER_DAYS:
        return False
    lock = paths.INDEX / "update.lock"
    if lock.exists() and time.time() - lock.stat().st_mtime < 3600:
        return False
    if update_running():   # an update past the hour is still writing
        return False
    try:
        lock.touch()
    except OSError:  # read-only index (e.g. a write-protected drive): query, don't refresh
        return False
    # nix-wrapped interpreters do not see the package on their own path
    pkg = str(pathlib.Path(__file__).resolve().parents[1])
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, (pkg, os.environ.get("PYTHONPATH")))))
    with open(paths.INDEX / "update.log", "ab") as log:
        subprocess.Popen([sys.executable, "-m", "crowbar.cli", "update", "--quiet", "--if-mounted"],
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env,
                         cwd=pkg, start_new_session=True)
    return True
