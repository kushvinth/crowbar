"""Command line interface. Terminal only - no web UI, no TUI dependency."""
from __future__ import annotations

import argparse
import calendar
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import textwrap
import threading
import time
from typing import NoReturn

from . import catalog, datasets, db, paths, query

TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
DIM, BOLD, RED, YEL, GRN, CYN, MAG, RST = (
    ("\033[2m", "\033[1m", "\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[35m", "\033[0m")
    if TTY else ("",) * 8)
SEV_COLOR = {"CRITICAL": RED, "HIGH": YEL, "MEDIUM": YEL, "LOW": GRN, "NONE": DIM}


# ---------------------------------------------------------------- formatting
def out_json(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def die(msg: str, code: int = 1) -> NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(code)


class Spinner:
    """Animated status line on a terminal; plain prints everywhere else."""
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, label: str):
        self.label, self.live = label, sys.stdout.isatty()
        self._lock, self._stop = threading.Lock(), threading.Event()
        self._t0 = time.time()

    def __enter__(self):
        if self.live:
            threading.Thread(target=self._spin, daemon=True).start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        with self._lock:
            self._clear()

    def _clear(self) -> None:
        if self.live:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

    def _spin(self) -> None:
        i = 0
        while not self._stop.wait(0.1):
            with self._lock:
                cols = shutil.get_terminal_size().columns
                line = f"{self.FRAMES[i % len(self.FRAMES)]} {self.label} ({time.time() - self._t0:.0f}s)"
                sys.stdout.write(f"\r\033[K{CYN}{line[:cols - 1]}{RST}")
                sys.stdout.flush()
            i += 1

    def say(self, msg: str, err: bool = False) -> None:
        with self._lock:
            self._clear()
            print(msg, file=sys.stderr if err else sys.stdout, flush=True)


def money(v) -> str:
    if v is None:
        return "-"
    if v == 0:
        return "free"
    return f"{v:.2f}" if v >= 0.01 else f"{v:.4f}"


def table(headers: list[str], rows: list[list], wrap_last: int = 0) -> None:
    if not rows:
        print(f"{DIM}no results{RST}")
        return
    cells = [[("" if c is None else str(c)) for c in r] for r in rows]
    if wrap_last:
        cells = [r[:-1] + [textwrap.shorten(r[-1], wrap_last, placeholder="…")] for r in cells]
    widths = [max(len(h), *(len(r[i]) for r in cells)) for i, h in enumerate(headers)]
    print("  ".join(f"{BOLD}{h:<{w}}{RST}" for h, w in zip(headers, widths)))
    print(f"{DIM}{'  '.join('─' * w for w in widths)}{RST}")
    for r in cells:
        print("  ".join(f"{c:<{w}}" for c, w in zip(r, widths)))


BANNER = """\
 ██████╗██████╗  ██████╗ ██╗    ██╗██████╗  █████╗ ██████╗
██╔════╝██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔══██╗██╔══██╗
██║     ██████╔╝██║   ██║██║ █╗ ██║██████╔╝███████║██████╔╝
██║     ██╔══██╗██║   ██║██║███╗██║██╔══██╗██╔══██║██╔══██╗
╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝██████╔╝██║  ██║██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"""


def banner() -> str:
    """The logo, red fading to magenta on a colour terminal."""
    if not TTY:
        return BANNER
    return "\n".join(f"\033[38;5;{c}m{line}{RST}"
                     for c, line in zip((196, 197, 198, 199, 200, 201), BANNER.splitlines()))


def ago(iso: str | None) -> str:
    """'2026-10-25T22:50:20Z' -> '7h ago'. Bare dates count from midnight UTC."""
    if not iso:
        return "-"
    timed = len(iso) >= 19
    try:
        t = calendar.timegm(time.strptime(iso[:19] if timed else iso[:10],
                                          "%Y-%m-%dT%H:%M:%S" if timed else "%Y-%m-%d"))
    except ValueError:
        return iso[:10]
    secs = max(0, time.time() - t)
    for unit, n in (("y", 31536000), ("mo", 2592000), ("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= n:
            return f"{int(secs // n)}{unit} ago"
    return "just now"


def heat(n: int, top: int = 5) -> str:
    """▰▰▰▱▱ - how many distinct places are talking about a CVE."""
    n = min(n, top)
    return f"{RED if n >= 3 else YEL if n == 2 else DIM}{'▰' * n}{RST}{DIM}{'▱' * (top - n)}{RST}"


def sev_badge(sev: str | None, cvss: float | None) -> str:
    s = (sev or "").upper()
    label = {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW"}.get(s, s[:4] or "?")
    return f"{SEV_COLOR.get(s, DIM)}{label:<4}{RST} {('%.1f' % cvss) if cvss is not None else ' - '}"


def risk_bits(r) -> str:
    bits = []
    if r["kev"]:
        bits.append(f"{RED}KEV{RST}")
    if r["epss"] is not None:
        bits.append(f"epss {r['epss']:.2f}")
    return " ".join(bits)


def connect_or_die():
    try:
        con = db.connect()
    except db.NotIndexed as exc:
        die(f"{exc}")
    if db.schema_version(con) != paths.SCHEMA_VERSION:
        old = db.schema_version(con) < paths.SCHEMA_VERSION   # update() migrates older schemas in place
        die(f"index schema v{db.schema_version(con)} != v{paths.SCHEMA_VERSION} - run: crowbar "
            f"{'update' if old else 'build'}")
    if datasets.refresh_in_background(datasets.index_status(db.meta(con))):
        print(f"{DIM}↻ index is over a day old - refreshing in the background{RST}", file=sys.stderr)
    return con


# ---------------------------------------------------------------- read commands
def cmd_search(args) -> None:
    con = connect_or_die()
    rows = query.search(
        con, args.query or "", limit=args.limit, offset=args.offset, sort=args.sort,
        severity=args.severity, year=args.year, since=args.since, kev=args.kev,
        exploit=args.exploit, epss=args.epss, cvss=args.cvss, cwe=args.cwe,
        product=args.product, vendor=args.vendor, ssvc=args.ssvc, poc=args.poc)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        tag = f" {CYN}exp×{r['exploits']}{RST}" if r["exploits"] else ""
        tag += f" {DIM}nuc×{r['nuclei_count']}{RST}" if r["nuclei_count"] else ""
        tag += f" {MAG}poc×{r['poc_count']}{RST}" if r.get("poc_count") else ""
        print(f"{BOLD}{r['id']}{RST} {sev_badge(r['severity'], r['cvss'])} {risk_bits(r)}{tag}".rstrip())
        print(f"  {DIM}{(r['published'] or '')[:10]}{RST}  "
              f"{textwrap.shorten(r['description'] or '', args.width - 4, placeholder='…')}")
    more = f" · next page: --offset {args.offset + args.limit}" if len(rows) == args.limit else ""
    print(f"\n{DIM}{len(rows)} shown{more}{RST}")


def cmd_browse(args) -> None:
    """Interactive fzf browser: type to filter, preview the CVE, enter to open."""
    con = connect_or_die()
    fzf = shutil.which("fzf")
    rows = query.search(con, args.query or "", limit=args.limit, kev=args.kev,
                        exploit=args.exploit, sort="relevance" if args.query else "newest")
    if not fzf or not (sys.stdin.isatty() and sys.stdout.isatty()):
        for r in rows:
            print(f"{r['id']}  {sev_badge(r['severity'], r['cvss'])}  {risk_bits(r)}  "
                  f"{(r['description'] or '')[:80]}")
        if not fzf:
            print("\n(fzf not installed - showing plain list)", file=sys.stderr)
        return
    lines = "\n".join(
        f"{r['id']}\t{r['severity'] or '-'}\t{r['cvss'] if r['cvss'] is not None else '-'}\t"
        f"{'KEV' if r['kev'] else ''}\t{(r['description'] or '')[:110]}"
        for r in rows)
    hv = shutil.which("crowbar") or str(paths.ROOT / "bin" / "crowbar")
    pick = subprocess.run(
        [fzf, "--ansi", "--delimiter=\t", "--with-nth=1,2,3,4,5",
         "--header", f"{len(rows)} CVEs - enter to open, esc to quit",
         "--preview", f"{hv} --width 100 cve {{1}}",
         "--preview-window", "right:62%:wrap"],
        input=lines, text=True, capture_output=True)
    cid = (pick.stdout or "").split("\t")[0].strip()
    if cid:
        subprocess.run([hv, "cve", cid])


def cmd_cve(args) -> None:
    con = connect_or_die()
    try:
        d = query.get_cve(con, args.id)
    except KeyError as exc:
        msg = exc.args[0]
        die(msg if " " in msg else f"{msg} not in index")
    if args.json:
        out_json(d)
        return
    print(f"{BOLD}{d['id']}{RST}  {sev_badge(d['severity'], d['cvss'])}  {risk_bits(d)}")
    print(f"{BOLD}{textwrap.shorten(d['description'] or '', args.width, placeholder='…')}{RST}\n")
    print(f"  {DIM}published{RST} {d['published']}   {DIM}modified{RST} {d['modified']}"
          f"   {DIM}status{RST} {d['status']}")
    if d["cvss_vector"]:
        print(f"  {DIM}vector{RST}    {d['cvss_vector']}")
    if d["epss"] is not None:
        print(f"  {DIM}epss{RST}      {d['epss']:.4f}  (percentile {d['epss_pct']:.2f})")
    if d["cwe"]:
        print(f"  {DIM}weakness{RST}  {', '.join(d['cwe'])}")
    if d["affects"]:
        labels = [a["label"] for a in d["affects"]]
        more = d["affects_total"] - 10
        print(f"  {DIM}affects{RST}   {textwrap.shorten(', '.join(labels[:10]), args.width - 14, placeholder=f'… (+{more} ranges)')}")
    if d["ssvc"]:
        s = d["ssvc"]
        print(f"  {DIM}ssvc{RST}      exploitation={s['exploitation']} automatable={s['automatable']}"
              f" impact={s['technical_impact']}")
    print()
    if d["kev_detail"]:
        k = d["kev_detail"]
        print(f"{RED}▌ CISA KEV{RST}  added {k['date_added']}  due {k['due']}  ransomware={k['ransomware']}")
        print(f"  {k['vendor']} {k['product']} - {k['name']}")
        if k["action"]:
            print(f"  {DIM}action:{RST} {textwrap.shorten(k['action'], args.width - 10, placeholder='…')}")
        print()
    if d["exploits"]:
        print(f"{MAG}▌ Exploit-DB ({d['exploits_total']}){RST}")
        for e in d["exploits"][:8]:
            print(f"  {e['id']:>6}  {(e['platform'] or '-'):<10} {(e['type'] or '-'):<8} "
                  f"{textwrap.shorten(e['description'] or '', args.width - 34, placeholder='…')}")
        print()
    if d["nuclei"]:
        print(f"{CYN}▌ Nuclei ({len(d['nuclei'])}){RST}")
        for n in d["nuclei"][:8]:
            print(f"  {(n['severity'] or '?'):<8} {n['id']}  {DIM}{n['path']}{RST}")
        print()
    if d["metasploit"]:
        print(f"{CYN}▌ Metasploit ({len(d['metasploit'])}){RST}")
        for m in d["metasploit"][:8]:
            print(f"  {m['type']:<9} {m['name']}")
        print()
    if d.get("pocs"):
        print(f"{MAG}▌ Public PoCs ({d['poc_count']}){RST}")
        for p in d["pocs"][:10]:
            print(f"  ★{p['stars']:<6} {p['repo']}  {DIM}{p['url']}{RST}")
        print()
    if d.get("mentions"):
        print(f"{GRN}▌ Talked about ({len(d['mentions'])}){RST}")
        for m in d["mentions"][:8]:
            score = f"▲{m['score']}" if m["score"] else ""
            print(f"  {m['source']:<15} {DIM}{ago(m['posted_at']):>8}{RST} {score:<6} "
                  f"{textwrap.shorten(m['title'] or '', max(20, args.width - 36), placeholder='…')}")
        print()
    if d.get("cna") and d["cna"].get("description") and d["cna"]["description"] != d["description"]:
        print(f"{DIM}CNA record ({d['cna']['assigner'] or 'unknown'}):{RST} "
              f"{textwrap.shorten(d['cna']['description'], args.width - 4, placeholder='…')}\n")
    if d.get("aliases"):
        print(f"{DIM}aliases{RST}  {', '.join(d['aliases'][:20])}")
    if d["references"]:
        print(f"{DIM}references ({d['references_total']}){RST}")
        for ref in d["references"][:10]:
            print(f"  {DIM}·{RST} {ref['url']}  {DIM}{ref['tags']}{RST}")


def cmd_product(args) -> None:
    con = connect_or_die()
    rows = query.products(con, args.name, version=args.version, limit=args.limit)
    if args.json:
        out_json(rows)
        return
    head = f"CVEs affecting {args.name!r}"
    if args.version:
        head += f" version {args.version}"
    print(f"{DIM}{head}{RST}\n")
    for r in rows:
        print(f"{BOLD}{r['id']}{RST} {sev_badge(r['severity'], r['cvss'])} {risk_bits(r)}  "
              f"{DIM}{(r['published'] or '')[:10]}{RST}")
        if r["matched"]:
            print(f"  {DIM}matched{RST} {', '.join(r['matched'])}")
        print(f"  {textwrap.shorten(r['description'] or '', args.width - 2, placeholder='…')}")


def cmd_kev(args) -> None:
    con = connect_or_die()
    rows = query.kev_list(con, args.query, args.limit)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        rw = f"{RED}ransom{RST}" if (r["ransomware"] or "").lower() == "known" else ""
        print(f"{BOLD}{r['cve']}{RST} {DIM}{r['date_added']}{RST} {rw}")
        print(f"  {r['vendor']} {r['product']} - {r['name']}")
    print(f"\n{DIM}{len(rows)} entries{RST}")


def cmd_exploit(args) -> None:
    con = connect_or_die()
    if args.query.isdigit():
        if args.fetch:
            try:
                e = query.exploit_fetch(con, args.query)
            except KeyError:
                die(f"exploit {args.query} not found")
        else:
            e = query.exploit_lookup(con, args.query)
            if e.get("error"):
                die(f"exploit {args.query} not found")
        if args.json:
            out_json(e)
        else:
            print(f"{BOLD}{e['id']}{RST} {e['platform']} {e['type']}  {e['description']}")
            print(f"{DIM}local:{RST} {e['local_path']}" if e["local_path"]
                  else f"{DIM}not on disk - {e['fetch'].split('   #')[0]}{RST}")
        return
    rows = query.exploit_search(con, args.query, args.limit)
    if args.json:
        out_json([{k: v for k, v in r.items() if k != "rank"} for r in rows])
        return
    for r in rows:
        v = f"{GRN}✓{RST}" if r["verified"] else " "
        print(f"{v} {BOLD}{r['id']:>6}{RST} {DIM}{(r['date'] or '')[:10]:<10}{RST} "
              f"{(r['platform'] or '-'):<12} "
              f"{textwrap.shorten(r['description'] or '', args.width - 40, placeholder='…')}")
        if r["codes"]:
            print(f"        {DIM}{r['codes']}{RST}")


def cmd_nuclei(args) -> None:
    con = connect_or_die()
    rows = query.nuclei_search(con, args.query, args.limit, args.domain)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        print(f"{BOLD}{r['id']}{RST} [{r['severity'] or '?'}] {r['domain']:<9} "
              f"{textwrap.shorten(r['name'] or '', args.width - 40, placeholder='…')}")
        print(f"  {DIM}{r['path']}  {r['cve']}{RST}")


def cmd_msf(args) -> None:
    con = connect_or_die()
    rows = query.msf_search(con, args.query, args.limit)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        print(f"{r['type']:<10} {BOLD}{r['name']}{RST}")


def cmd_models(args) -> None:
    con = connect_or_die()
    rows = query.models_list(con, args.query, args.provider, args.limit)
    if args.json:
        out_json(rows)
        return
    table(["provider", "model", "ctx", "out", "$in/M", "$out/M", "cap"],
          [[r["provider"], r["name"], f"{(r['context'] or 0) // 1000}k",
            f"{(r['output_limit'] or 0) // 1000}k", money(r["input_cost"]),
            money(r["output_cost"]),
            "".join(x for x, on in (("R", r["reasoning"]), ("T", r["tool_call"]), ("V", r["vision"])) if on)]
           for r in rows])


def cmd_attack(args) -> None:
    con = connect_or_die()
    rows = query.attack_lookup(con, args.query, args.limit, args.domain)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        print(f"{BOLD}{r['id']}{RST} {r['name']}  {DIM}{r['domain']} · {r['tactics']}{RST}")
        print(f"  {textwrap.shorten(r['description'] or '', args.width - 2, placeholder='…')}")


def cmd_cwe(args) -> None:
    con = connect_or_die()
    try:
        res = query.cwe_get(con, args.query, args.limit)
    except KeyError as exc:
        die(f"{exc.args[0]} not found")
    if args.json:
        out_json(res)
        return
    if isinstance(res, dict):
        print(f"{BOLD}{res['id']}{RST}  {res['name']}  {DIM}{res['abstraction']} {res['status']}{RST}\n")
        print(textwrap.fill(res["description"] or "", args.width))
        return
    for r in res:
        print(f"{r['id']:<9} {r['name']}")


def cmd_capec(args) -> None:
    con = connect_or_die()
    rows = query.capec_search(con, args.query, args.limit)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        print(f"{r['id']:<12} {r['name']}  {DIM}{r['severity'] or ''} {r['cwe']}{RST}")


def cmd_os(args) -> None:
    con = connect_or_die()
    rows = query.os_search(con, args.query, args.platform, args.impact,
                           args.exploited, args.since, args.limit)
    if args.json:
        out_json(rows)
        return
    head = "OS advisories"
    if args.platform:
        head += f" · {args.platform}"
    if args.impact:
        head += f" · {args.impact}"
    if args.exploited:
        head += " · exploited"
    print(f"{DIM}{head}{RST}\n")
    for r in rows:
        cve = r["cve"] or " - "
        print(f"{BOLD}{cve:<16}{RST} {r['platform']:<6} {r['severity'] or '-':<9} "
              f"{(r['impact'] or '-'):<14} {DIM}{(r['released'] or '')[:10]}{RST}  "
              f"{textwrap.shorten(r['product'] or '', args.width - 70, placeholder='…')}")
        if r["version"] and r["version"] not in (r["product"] or ""):
            print(f"  {DIM}{r['version']}{RST}")
    print(f"\n{DIM}{len(rows)} rows{RST}")


def cmd_advisory(args) -> None:
    con = connect_or_die()
    rows = query.advisory_search(con, args.query, args.ecosystem, args.package, args.limit)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        cve = f" {DIM}{r['cve']}{RST}" if r["cve"] else ""
        print(f"{BOLD}{r['id']}{RST} [{r['ecosystem'] or '?'}] {r['package']}{cve}")
        if r["summary"]:
            print(f"  {textwrap.shorten(r['summary'], args.width - 2, placeholder='…')}")
        for x in r.get("ranges", [])[:4]:
            bits = []
            if x["introduced"]:
                bits.append(f">={x['introduced']}")
            if x["fixed"]:
                bits.append(f"fixed {x['fixed']}")
            if x["last_affected"]:
                bits.append(f"<={x['last_affected']}")
            if x["versions"]:
                bits.append(x["versions"][:80])
            print(f"  {DIM}{x['package']} {' '.join(bits)}{RST}")


def cmd_code(args) -> None:
    con = connect_or_die()
    rows = query.code_search(con, args.query, args.limit)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        print(f"{BOLD}{r['path']}{RST}  {DIM}{r['exploit_id'] or ''}{RST}")
        print(f"  {r['snippet']}")


def cmd_bin(args) -> None:
    con = connect_or_die()
    rows = query.toolkit_search(con, args.query, args.source, args.limit)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        print(f"{BOLD}{r['name']}{RST} {DIM}{r['source']}{RST}  "
              f"{textwrap.shorten(r['description'] or '', args.width - 30, placeholder='…')}")
        print(f"  {DIM}{r['path']}  {r['tags']}{RST}")


def cmd_debian(args) -> None:
    con = connect_or_die()
    rows = query.debian_lookup(con, args.package, args.cve, args.limit)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        print(f"{BOLD}{r['cve']}{RST} {r['release']:<14} {r['status']:<16} "
              f"{DIM}fixed {r['fixed'] or '-'}{RST} {r['urgency'] or ''}")


def cmd_poc(args) -> None:
    """Public GitHub PoC repositories (metadata only, never executed)."""
    con = connect_or_die()
    if args.cve:
        rows = query.poc_search(con, args.query or "", cve=args.cve,
                                language=args.language, min_stars=args.min_stars,
                                limit=args.limit)
    elif args.top:
        rows = query.poc_cves(con, args.limit)
        if args.json:
            out_json(rows)
            return
        for r in rows:
            print(f"{BOLD}{r['cve_id']}{RST} {DIM}×{r['poc_count']} repos{RST}  "
                  f"{r['severity'] or '-'} {r['cvss'] if r['cvss'] is not None else '-'}  "
                  f"{r['description'] or ''}")
        return
    else:
        rows = query.poc_search(con, args.query or "", language=args.language,
                                min_stars=args.min_stars, limit=args.limit)
    if args.json:
        out_json(rows)
        return
    for r in rows:
        print(f"{BOLD}{r['cve_id']}{RST} {DIM}★{r['stars']}{RST} {r['repo']}")
        print(f"  {DIM}{r['url']}{RST}  {r['language'] or ''}  {r['description'] or ''}")


def cmd_sources(args) -> None:
    """Provenance: which source filled which table, with license and hash."""
    con = connect_or_die()
    rows = [dict(r) for r in con.execute(
        "SELECT source, url, path, license, sha256, fetched_at, loaded_at, "
        "record_count, status, note FROM source_state ORDER BY source")]
    if args.json:
        out_json(rows)
        return
    if not rows:
        print("no source_state rows (run: crowbar update)")
        return
    for r in rows:
        print(f"{BOLD}{r['source']}{RST}  {r['status']}  {r['record_count']:,} records  "
              f"{DIM}license={r['license'] or '?'}{RST}")
        print(f"  {DIM}{r['url']}{RST}")
        print(f"  {DIM}sha256 {r['sha256'] or '-'}{RST}")
        if r["note"]:
            print(f"  {DIM}{r['note']}{RST}")


def cmd_map(args) -> None:
    if args.tables:
        for t, desc in catalog.TABLES.items():
            print(f"{BOLD}{t:<20}{RST} {desc}")
        return
    manifest = datasets.load_manifest().get("datasets", {})
    items = datasets.registry(with_extra=True, with_bulk=True)
    rows = []
    for d in items:
        present, size = catalog.disk_state(d.dest)
        g = catalog.describe(d.name)
        rows.append({
            "name": d.name, "group": d.group, "tier": d.tier,
            "path": d.dest, "present": present, "bytes": size,
            "fetched_at": (manifest.get(d.name) or {}).get("fetched_at"),
            "tables": g["tables"], "commands": g["commands"], "note": d.note,
        })
    if args.json:
        out_json(rows)
        return
    table(["dataset", "tier", "status", "size", "indexes", "command"],
          [[r["name"], r["tier"], "ok" if r["present"] else "-",
            human_bytes(r["bytes"]), ",".join(r["tables"]) or "-",
            (r["commands"] or ["-"])[0]] for r in rows])
    print(f"\n{DIM}raw path root: {paths.DATA}{RST}")
    print(f"{DIM}table meanings: crowbar map --tables{RST}")


def human_bytes(n: float) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}G"


def cmd_sql(args) -> None:
    con = connect_or_die()
    try:
        rows = query.sql_readonly(con, args.query, args.limit)
    except (sqlite3.Error, ValueError) as exc:
        die(f"sql error: {exc}")
    if args.json:
        out_json(rows)
        return
    if rows:
        table(list(rows[0]), [list(r.values()) for r in rows])


def cmd_stats(args) -> None:
    con = connect_or_die()
    s = query.stats(con)
    if args.json:
        out_json(s)
        return
    meta = s.pop("meta", {})
    fresh = s.pop("freshness", {})
    print(f"{BOLD}corpus{RST}")
    for k in ("cve", "cve_kev", "cve_with_epss", "cve_with_exploit", "cve_with_nuclei",
              "cve_with_msf", "cpe_match", "kev", "exploit", "shellcode", "nuclei", "msf",
              "attack", "cwe", "capec", "model", "ssvc"):
        if k in s:
            print(f"  {k:<18} {s[k]:>10,}")
    print(f"  {'db':<18} {s['db_bytes'] / 1e6:>8.0f} MB   {DIM}{paths.DB}{RST}")
    print(f"\n{BOLD}state{RST}")
    for k in ("schema", "built_at", "updated_at"):
        print(f"  {k:<12} {meta.get(k, ' - ')}")
    if fresh:
        newest = max((v["fetched_at"] or "" for v in fresh.values()), default="")
        print(f"  {'datasets':<12} {len(fresh)} files, newest {newest}")
    print(f"\n{BOLD}coverage{RST}")
    if s.get("cve"):
        for k in ("cve_kev", "cve_with_epss", "cve_with_exploit", "cve_with_nuclei", "cve_with_msf"):
            print(f"  {k:<18} {100 * s.get(k, 0) / s['cve']:>5.1f}%")


def cmd_home(args) -> None:
    """`crowbar` with no command: logo, how fresh the index is, where to start."""
    print(banner())
    print(f"  {DIM}offline CVE intelligence for agents · rank by KEV > SSVC > EPSS > CVSS{RST}\n")
    if not paths.DB.exists():
        print(f"  {RED}●{RST} no index yet - {BOLD}crowbar sync --tier lite && crowbar build --tier lite{RST}"
              f" {DIM}(~150MB, a few minutes){RST}\n")
    else:
        con = connect_or_die()
        s = datasets.index_status(db.meta(con))
        newest = query.data_as_of(con)
        n = con.execute("SELECT count(*) FROM cve").fetchone()[0]
        dot = f"{YEL}●{RST} stale" if s["stale"] else f"{GRN}●{RST} fresh"
        print(f"  {dot}  updated {ago(s['last_update'])} · newest CVE {ago(newest['cve_published'])}"
              f" · newest KEV {ago(newest['kev_added'])} · {n:,} CVEs")
        if s["last_error"]:
            print(f"  {YEL}last update failed {ago(s['last_error']['at'])}: {s['last_error']['error']}{RST}")
        print()
    for cmd, what in (("trending", "what people are posting about this week"),
                      ("new", "KEV additions, new CVEs and PoCs in the last 7 days"),
                      ("cve CVE-2021-44228", "triage one CVE"),
                      ("product nginx --version 1.18.0", "is my version affected?"),
                      ("bench", "how fast is this index")):
        print(f"  {CYN}crowbar {cmd:<32}{RST} {DIM}{what}{RST}")
    print(f"\n  {DIM}crowbar --help for every command{RST}")


def cmd_trending(args) -> None:
    con = connect_or_die()
    rows = query.trending(con, days=args.days, limit=args.limit)
    if args.json:
        out_json(rows)
        return
    print(f"{BOLD}🔥 trending{RST} {DIM}- CVEs named on HN, oss-security, Full Disclosure, ZDI, "
          f"Mastodon and ENISA's exploited list in the last {args.days:g} days{RST}\n")
    if not rows:
        print(f"{DIM}nothing yet - run: crowbar update{RST}")
        return
    for r in rows:
        print(f"{heat(r['sources'])} {BOLD}{r['id']:<16}{RST} {sev_badge(r['severity'], r['cvss'])} "
              f"{risk_bits(r)}  {DIM}{r['posts']} post{'s' * (r['posts'] != 1)} · {r['seen_on'].replace(',', ' · ')} · "
              f"{ago(r['last_seen'])}{RST}")
        if r["description"]:
            print(f"      {textwrap.shorten(r['description'], args.width - 6, placeholder='…')}")


def cmd_new(args) -> None:
    con = connect_or_die()
    d = query.new_since(con, since=args.since, days=args.days, limit=args.limit)
    if args.json:
        out_json(d)
        return
    print(f"{BOLD}✨ new since {d['since']}{RST}\n")
    sections = (("kev", RED, "CISA KEV additions", lambda r: f"{r['cve']:<16} {DIM}{r['date_added']}{RST} "
                 f"{r['vendor']} {r['product']} - {r['name']}"),
                ("eu_exploited", RED, "ENISA exploited", lambda r: f"{r['cve']:<16} {DIM}{ago(r['exploited_since'])}"
                 f"{RST}{'  also in KEV' if r['kev'] else ''}"),
                ("published", YEL, "new CVEs (KEV > EPSS > CVSS first)", lambda r: f"{r['id']:<16} "
                 f"{sev_badge(r['severity'], r['cvss'])} {risk_bits(r)}  "
                 f"{textwrap.shorten(r['description'] or '', max(20, args.width - 40), placeholder='…')}"),
                ("pocs", MAG, "new public PoCs", lambda r: f"{r['cve']:<16} ★{r['stars'] or 0:<5} {r['repo']}"))
    for key, color, title, line in sections:
        part = d[key]
        print(f"{color}▌ {title} ({part['total']:,}){RST}")
        for r in part["rows"]:
            print(f"  {line(r)}")
        if part["total"] > len(part["rows"]):
            print(f"  {DIM}… {part['total'] - len(part['rows']):,} more (--limit, --json){RST}")
        print()


def cmd_bench(args) -> None:
    """Time the queries agents run most, on this machine's real index."""
    con = connect_or_die()
    kev = con.execute("SELECT cve FROM kev ORDER BY date_added DESC LIMIT 1").fetchone()
    some = con.execute("SELECT id FROM cve ORDER BY rowid DESC LIMIT 1").fetchone()
    cid = (kev and kev[0]) or (some and some[0]) or "CVE-2021-44228"
    cases = (("cve lookup", lambda: query.get_cve(con, cid)),
             ("full-text search", lambda: query.search(con, "remote code execution", limit=20)),
             ("product + version", lambda: query.products(con, "nginx", "1.18.0")),
             ("KEV list", lambda: query.kev_list(con, None, 25)),
             ("trending", lambda: query.trending(con)),
             ("new this week", lambda: query.new_since(con)),
             ("package advisory", lambda: query.advisory_search(con, package="lodash", ecosystem="npm")))
    results = []
    for name, fn in cases:
        times = []
        for _ in range(args.runs):
            t0 = time.perf_counter()
            try:
                fn()
            except (KeyError, sqlite3.Error):   # a lite index may lack the table or row
                times = []
                break
            times.append((time.perf_counter() - t0) * 1000)
        times.sort()
        results.append({"query": name, "median_ms": round(times[len(times) // 2], 2) if times else None,
                        "best_ms": round(times[0], 2) if times else None})
    n = con.execute("SELECT count(*) FROM cve").fetchone()[0]
    if args.json:
        out_json({"cves": n, "db_bytes": paths.DB.stat().st_size, "runs": args.runs, "results": results})
        return
    print(f"{BOLD}⚡ bench{RST} {DIM}- {n:,} CVEs · {datasets.human(paths.DB.stat().st_size)} · "
          f"median of {args.runs} runs{RST}\n")
    top = max((r["median_ms"] or 0 for r in results), default=1) or 1
    for r in results:
        if r["median_ms"] is None:
            print(f"  {r['query']:<18} {DIM}n/a on this tier{RST}")
            continue
        bar = "█" * max(1, round(24 * r["median_ms"] / top))
        color = GRN if r["median_ms"] < 10 else YEL if r["median_ms"] < 100 else RED
        print(f"  {r['query']:<18} {color}{r['median_ms']:>8.2f} ms{RST}  {color}{bar}{RST}")
    ok = sorted(r["median_ms"] for r in results if r["median_ms"] is not None)
    if ok:
        print(f"\n  {DIM}median query {ok[len(ok) // 2]:.2f} ms · no network, no API key, no rate limit{RST}")


def cmd_where(args) -> None:
    info = {
        "home": str(paths.ROOT),
        "home_link": str(paths.HOME_LINK) + (" (symlink)" if paths.HOME_LINK.is_symlink() else ""),
        "db": str(paths.DB),
        "data": str(paths.DATA),
        "manifest": str(paths.MANIFEST),
        "drive": paths.is_drive_root(),
        "datasets": {k: v["path"] for k, v in datasets.freshness().items()},
    }
    if args.json:
        out_json(info)
        return
    print(f"{BOLD}root{RST}      {info['home']}")
    print(f"{BOLD}home link{RST} {info['home_link']}")
    print(f"{BOLD}index{RST}     {info['db']}")
    print(f"{BOLD}data{RST}      {info['data']}")
    print(f"{BOLD}drive{RST}     {'yes' if info['drive'] else 'no'}")


# ---------------------------------------------------------------- data ops
def _report(r: dict, say) -> None:
    if r["status"] == "FAIL":
        say(f"  {RED}FAIL{RST} {r['name']:<22} {r.get('error', '')}", err=True)
    elif r["status"] in ("same", "exists"):
        say(f"  {DIM}same{RST} {r['name']:<22}")
    else:
        say(f"  {GRN}ok{RST}   {r['name']:<22} {datasets.human(r.get('bytes', 0)):>9s}")


def _record_tier(tier: str) -> None:
    m = datasets.load_manifest()
    m["tier"] = tier
    datasets.save_manifest(m)


def _writer_lock() -> None:
    if not datasets.acquire_update_lock():
        die("another crowbar sync/build/update is running - wait for it to finish")


def cmd_sync(args) -> None:
    _writer_lock()
    years = None
    if args.years:
        years = []
        for part in args.years.split(","):
            if "-" in part:
                a, b = part.split("-", 1)
                years += list(range(int(a), int(b) + 1))
            else:
                years.append(int(part))
    if getattr(args, "tier", None):
        items = datasets.tier_plan(args.tier)
        _record_tier(args.tier)
    else:
        items = datasets.plan(
            only=[s for s in (args.only or "").split(",") if s] or None,
            years=years, with_extra=args.extra, with_bulk=args.bulk)
    if not items:
        die("nothing selected")
    print(f"syncing {len(items)} datasets -> {paths.DATA}"
          + (f" (tier {args.tier})" if getattr(args, "tier", None) else ""))
    pending = [d.name for d in items]
    with Spinner("downloading") as sp:
        def progress(r: dict) -> None:
            pending.remove(r["name"])
            sp.label = f"downloading {len(items) - len(pending)}/{len(items)}: {', '.join(pending)}"
            _report(r, sp.say)
        sp.label = f"downloading 0/{len(items)}: {', '.join(pending)}"
        results = datasets.sync(items, force=args.force, jobs=args.jobs,
                                pull=args.pull, progress=progress)
    optional = {d.name for d in items if d.optional}
    bad = [r for r in results if r["status"] == "FAIL" and r["name"] not in optional]
    soft = [r["name"] for r in results if r["status"] == "FAIL" and r["name"] in optional]
    print(f"{len(results) - len(bad) - len(soft)}/{len(results)} ready")
    if soft:
        print(f"{YEL}skipped (optional, retried next update): {', '.join(soft)}{RST}", file=sys.stderr)
    if bad:
        die(", ".join(r["name"] for r in bad))


def cmd_pack(args) -> None:
    out = pathlib.Path(args.dir).expanduser()
    doc = datasets.pack(out)
    if not doc["datasets"]:
        die("nothing synced to pack - run: crowbar sync")
    total = sum(e["bytes"] for e in doc["datasets"].values())
    print(f"packed {len(doc['datasets'])} datasets ({datasets.human(total)}) -> {out}\n"
          f"upload every file in it, then point users at it: CROWBAR_MIRROR=<url of that folder>")


def cmd_build(args) -> None:
    from . import indexer
    if not paths.DATA.exists() or not any(paths.DATA.iterdir()):
        die("no data - run: crowbar sync")
    _writer_lock()
    if getattr(args, "tier", None):
        _record_tier(args.tier)
        missing = datasets.tier_missing(args.tier)
        if missing and not getattr(args, "allow_incomplete", False):
            die(f"tier {args.tier} is missing {', '.join(missing)} - nothing to build yet. "
                f"Run: crowbar sync --tier {args.tier} --force   (or build --allow-incomplete)")
        if missing:
            print(f"{YEL}WARNING: building an incomplete {args.tier} index "
                  f"(missing {', '.join(missing)}){RST}", file=sys.stderr)
    if args.json:
        stats = indexer.build(quick=args.quick, with_extra=args.extra, with_bulk=args.bulk,
                              progress=lambda msg: print(msg, file=sys.stderr))
    else:
        with Spinner("building index") as sp:
            stats = indexer.build(quick=args.quick, with_extra=args.extra, with_bulk=args.bulk,
                                  progress=lambda msg: sp.say(f"  {GRN}✓{RST} {msg}"))
    if args.json:
        out_json(stats)
        return
    print(f"\nbuilt {stats['cve']:,} CVEs · {stats.get('cpe_match', 0):,} CPE ranges · "
          f"{datasets.human(stats['db_bytes'])} in {stats['build_seconds']}s")


def cmd_update(args) -> None:
    from . import indexer
    if args.if_mounted and not _mounted():
        return
    _writer_lock()
    try:
        _update(args, indexer)
    except SystemExit as exc:
        if exc.code:
            datasets.note_update(f"update exited {exc.code} - see index/update.log")
        raise
    except Exception as exc:
        msg = str(exc) if isinstance(exc, ValueError) else f"{type(exc).__name__}: {exc}"
        datasets.note_update(msg.replace(str(paths.ROOT), "<root>"))
        raise
    datasets.note_update(None)


def _update(args, indexer) -> None:
    status = datasets.index_status()
    tier = status["tier"]
    if status["stale"] and args.no_sync:
        print(f"{YEL}index is {status['age_days']} days old: past the 8-day NVD change feed, "
              f"so CVEs changed in the gap stay stale until a run without --no-sync{RST}", file=sys.stderr)
    elif status["stale"]:
        # the modified feed only reaches back 8 days: re-sync and rebuild to close the gap
        ns = argparse.Namespace(tier=tier, years=None, only=None, force=False, jobs=args.jobs,
                                pull=False, allow_incomplete=True, quick=False, extra=args.extra,
                                bulk=False, json=args.json)
        cmd_sync(ns)
        cmd_build(ns)
        return
    groups = ["nvd", "kev", "epss", "exploitdb", "models", "cveorg", "poc", "chatter"]
    if args.deep:
        groups += ["nuclei", "metasploit", "attack", "cwe", "capec"]
    if tier and tier != "extreme":
        groups = [g for g in groups if g in datasets.tier_groups(tier)]
    items = [d for d in datasets.plan(with_extra=args.extra)
             if d.group in groups and d.name != "nvd-2002"]
    # only the incremental NVD feeds here; year snapshots are for `crowbar build`
    items = [d for d in items if not (d.group == "nvd" and d.name not in ("nvd-recent", "nvd-modified"))]
    if not args.no_sync:
        if not args.quiet:
            print(f"syncing {len(items)} datasets")
        results = datasets.sync(items, jobs=args.jobs, pull=args.deep,
                                progress=None if args.quiet else _report)
        # re-indexing old files would stamp a stale index as fresh and hide the gap
        # from the 8-day catch-up above
        nvd = [r for r in results if r["name"] == "nvd-modified" and r["status"] == "FAIL"]
        if nvd:
            raise ValueError(f"nvd-modified download failed, index left as is: {nvd[0].get('error', '')}")
    stats = indexer.update(deep=args.deep, progress=None if args.quiet else print)
    if args.json:
        out_json(stats)
    elif not args.quiet:
        print(f"updated {stats['rows_touched']} CVE rows in {stats['seconds']}s "
              f"({stats['cve']:,} total)")


def cmd_doctor(args) -> None:
    """Health check; `--json` gives agents the same facts, exit 1 = needs attention."""
    r: dict = {"python": sys.version.split()[0], "root": str(paths.ROOT),
               "drive": paths.is_drive_root(), "problems": []}
    if paths.HOME_LINK.is_symlink():
        r["home_link"] = os.readlink(paths.HOME_LINK)
    if paths.DB.exists():
        con = db.connect()
        r["schema"] = db.schema_version(con)
        r["integrity"] = con.execute("PRAGMA quick_check").fetchone()[0]
        s = query.stats(con)
        r["counts"] = {k: s.get(k, 0) for k in ("cve", "cve_kev", "cve_with_exploit", "cpe_match")}
        if r["schema"] != paths.SCHEMA_VERSION:
            r["problems"].append(f"schema v{r['schema']} != v{paths.SCHEMA_VERSION} - run: crowbar "
                                 f"{'update' if r['schema'] < paths.SCHEMA_VERSION else 'build'}")
        if r["integrity"] != "ok":
            r["problems"].append(f"integrity: {r['integrity']}")
    else:
        r["problems"].append("index missing - run: crowbar sync && crowbar build")
    m = datasets.load_manifest()
    r["datasets"] = len(m.get("datasets", {}))
    r["missing"] = [v["path"] for v in m.get("datasets", {}).values() if not (paths.DATA / v["path"]).exists()]
    r["tier"] = m.get("tier")
    if r["tier"]:
        incomplete = datasets.tier_missing(r["tier"])
        if incomplete:
            r["problems"].append(f"tier {r['tier']} is missing {', '.join(incomplete[:6])}"
                                 f"{' …' if len(incomplete) > 6 else ''} - re-run: crowbar sync --tier "
                                 f"{r['tier']} && crowbar build --tier {r['tier']}")
    if paths.HOME_LINK.is_symlink() and paths.HOME_LINK.exists():
        try:
            (paths.HOME_LINK / "index/state.json").read_text()
        except OSError:
            r["problems"].append("drive unreadable by this process - for the launchd agent, "
                                 "grant Full Disk Access to /bin/sh")
    r["fresh"] = datasets.index_status() if paths.DB.exists() else None
    if r["fresh"] and r["fresh"]["last_error"]:
        r["problems"].append(f"last update failed {r['fresh']['last_error']['at']}: "
                             f"{r['fresh']['last_error']['error']}")
    r["disk_free"] = shutil.disk_usage(paths.ROOT).free
    r["ok"] = not r["problems"]
    if args.json:
        out_json(r)
        sys.exit(0 if r["ok"] else 1)
    print(f"{BOLD}crowbar doctor{RST}")
    print(f"  python    {r['python']}\n  root      {r['root']}\n  drive     {'yes' if r['drive'] else 'no'}")
    if "home_link" in r:
        print(f"  home link {paths.HOME_LINK} -> {r['home_link']}")
    if "schema" in r:
        c = r["counts"]
        print(f"  schema    v{r['schema']} {'ok' if r['schema'] == paths.SCHEMA_VERSION else 'MISMATCH'}")
        print(f"  integrity {r['integrity']}")
        print(f"  cves      {c['cve']:,} · kev {c['cve_kev']:,} · exploits {c['cve_with_exploit']:,}"
              f" · cpe ranges {c['cpe_match']:,}")
    print(f"  datasets  {r['datasets']} tracked, {len(r['missing'])} missing")
    if r["tier"]:
        print(f"  tier      {r['tier']} ({datasets.TIER_SIZES.get(r['tier'], '?')})")
    for p in r["missing"][:5]:
        print(f"    {DIM}missing {p}{RST}")
    f = r["fresh"]
    if f and f["age_days"] is not None:
        print(f"  fresh     {f['age_days']} days since update{'' if f['auto_update'] else ' (auto-update off)'}")
        if f["stale"]:
            print(f"  {YEL}stale - run: crowbar update{RST}")
    print(f"  disk      {datasets.human(r['disk_free'])} free")
    if r["disk_free"] < 3 * 1024 ** 3:
        print(f"  {YEL}low disk - index rebuild needs ~2x current db size{RST}")
    for problem in r["problems"]:
        print(f"  {YEL}{problem}{RST}")
    print(f"\n{'ready' if r['ok'] else 'needs attention'}")
    sys.exit(0 if r["ok"] else 1)


# ---------------------------------------------------------------- project links
def _find_home() -> pathlib.Path:
    return paths.HOME_LINK if paths.HOME_LINK.exists() else paths.ROOT


def cmd_link(args) -> None:
    target = pathlib.Path(args.dir).expanduser().resolve()
    if not target.is_dir():
        die(f"{target} is not a directory")
    if target == paths.ROOT or paths.ROOT in target.parents:
        die("refusing to link the harness into itself")
    src = _find_home()
    link = target / ".crowbar"
    if link.is_symlink() or link.exists():
        if not args.force:
            die(f"{link} already exists (use --force)")
        link.unlink() if link.is_symlink() else shutil.rmtree(link)
    link.symlink_to(src, target_is_directory=True)

    skill_dst = target / ".opencode" / "skills" / "crowbar"
    if not skill_dst.exists() and paths.SKILL.exists():
        skill_dst.parent.mkdir(parents=True, exist_ok=True)
        skill_dst.symlink_to(paths.SKILL, target_is_directory=True)

    print(f"linked {link} -> {src}")
    print("  cli    .crowbar/bin/crowbar search \"...\"")
    print("  docs   .crowbar/AGENTS.md")
    print(f"  remove crowbar unlink {target}")


def cmd_unlink(args) -> None:
    target = pathlib.Path(args.dir).expanduser().resolve()
    removed = []
    link = target / ".crowbar"
    if link.is_symlink():
        link.unlink()
        removed.append(str(link))
    skill = target / ".opencode" / "skills" / "crowbar"
    if skill.is_symlink() and str(skill.resolve()).startswith(str(paths.ROOT)):
        skill.unlink()
        removed.append(str(skill))
    if not removed:
        die("nothing to unlink")
    print("removed " + ", ".join(removed))


# ---------------------------------------------------------------- drive ops
def _mounted() -> bool:
    if paths.HOME_LINK.is_symlink() and not paths.HOME_LINK.exists():
        return False
    return paths.ROOT.exists()


CODE = ["bin", "crowbar", "mcp", "scripts", "docs", ".opencode",
        "AGENTS.md", "README.md", "Makefile", ".gitignore"]


def _copy_db(src: pathlib.Path, dst: pathlib.Path) -> None:
    """Consistent snapshot even if a writer is active (sqlite backup API)."""
    if dst.exists():
        dst.unlink()
    s = sqlite3.connect(db.ro_uri(src), uri=True)
    d = sqlite3.connect(dst)
    try:
        with d:
            s.backup(d)
    finally:
        d.close()
        s.close()


def _db_ok(path: pathlib.Path) -> bool:
    journal = path.with_name(path.name + "-journal")
    if journal.exists() and journal.stat().st_size > 0:
        # unclean shutdown: open read-write once so SQLite rolls the hot journal back
        try:
            w = sqlite3.connect(path, timeout=30)
            w.execute("PRAGMA quick_check").fetchone()
            w.close()
        except sqlite3.DatabaseError:
            return False
    try:
        con = sqlite3.connect(db.ro_uri(path), uri=True)
        res = con.execute("PRAGMA integrity_check").fetchone()[0]
        con.close()
        return res == "ok"
    except sqlite3.DatabaseError:
        return False


def _verify(vault: pathlib.Path) -> list[tuple[str, str]]:
    bad: list[tuple[str, str]] = []
    dbf = vault / "index/crowbar.db"
    if not dbf.exists():
        bad.append(("crowbar.db", "missing"))
    elif dbf.stat().st_size == 0:
        bad.append(("crowbar.db", "empty (0 bytes) - rebuild"))
    elif not _db_ok(dbf):
        bad.append(("crowbar.db", "integrity check failed"))
    else:
        try:
            con = sqlite3.connect(db.ro_uri(dbf), uri=True)
            tabs = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if "cve" not in tabs:
                bad.append(("crowbar.db", "no schema - empty or wrong DB; rebuild"))
            elif con.execute("SELECT count(*) FROM cve").fetchone()[0] == 0:
                bad.append(("crowbar.db", "0 CVEs - build incomplete; rebuild"))
            con.close()
        except sqlite3.DatabaseError as exc:
            bad.append(("crowbar.db", f"unreadable: {exc}"))
    import json as _json
    man = vault / "index/manifest.json"
    if man.exists():
        for name, rec in _json.loads(man.read_text()).get("datasets", {}).items():
            p = vault / "data" / rec["path"]
            if not p.exists():
                bad.append((name, "missing"))
            elif rec.get("sha256") and datasets.sha256(p) != rec["sha256"]:
                bad.append((name, "hash mismatch"))
    return bad


def cmd_verify(args) -> None:
    problems = _verify(paths.ROOT)
    if args.json:
        out_json({"root": str(paths.ROOT), "ok": not problems,
                  "problems": [{"dataset": n, "issue": i} for n, i in problems]})
        return
    if not problems:
        print(f"{GRN}ok{RST} - index and all datasets match the manifest ({paths.ROOT})")
        return
    for n, i in problems:
        print(f"{RED}FAIL{RST} {n:<22} {i}")
    print(f"\n{len(problems)} problems - try: crowbar sync --only <dataset> --force && crowbar build")
    sys.exit(1)


def cmd_selftest(args) -> None:
    """Offline gate: static checks + every test suite + index/dataset verify.
    Never touches the network - run `crowbar sync`/`crowbar update` for that."""
    root = paths.ROOT
    steps = [
        ("static checks", [sys.executable, "scripts/check.py"]),
        ("unit tests", [sys.executable, "-m", "tests.test_unit"]),
        ("schema-v3 tests", [sys.executable, "-m", "tests.test_v3"]),
        ("corpus tests", [sys.executable, "-m", "tests.test_corpus"]),
    ]
    failed = []
    for label, cmd in steps:
        print(f"{CYN}▶ {label}{RST}")
        if subprocess.run(cmd, cwd=str(root)).returncode != 0:
            failed.append(label)
    print(f"{CYN}▶ index + dataset verify{RST}")
    if paths.DB.exists():
        problems = _verify(root)
        if problems:
            for n, i in problems:
                print(f"{RED}FAIL{RST} {n:<22} {i}")
            failed.append("verify")
        else:
            print(f"{GRN}ok{RST} - index and all datasets match the manifest")
    else:
        print(f"{YEL}skip{RST} - no index/crowbar.db (run: crowbar sync && crowbar build)")
    if failed:
        print(f"\n{RED}selftest FAILED{RST}: {', '.join(failed)}")
        sys.exit(1)
    print(f"\n{GRN}selftest passed{RST} - static checks, tests, and verify all green")


START_HERE = """# HACKVAULT - portable vulnerability index

This drive holds a complete, self-contained copy of the crowbar corpus:
every CVE (2002-today) with CPE version ranges, CISA KEV, EPSS, Exploit-DB,
Nuclei templates, Metasploit modules, MITRE ATT&CK (enterprise/mobile/ICS),
CWE, CAPEC, and the LLM model catalog.

Built {date}. Size: ~{size}.

## Use it

```bash
# from this folder
./bin/crowbar doctor
./bin/crowbar search "nginx rce" --kev
./bin/crowbar product openssh --version 9.7
./bin/crowbar cve CVE-2021-44228
./bin/crowbar browse
```

`~/.crowbar` points here, so projects can link to it:

```bash
cd /path/to/project
~/.crowbar/bin/crowbar link .
.crowbar/bin/crowbar product <name> --version <ver>
~/.crowbar/bin/crowbar unlink .
```

Agents get the MCP tools from the opencode config on the host
(`crowbar connect` registers them); the skill is at `.opencode/skills/crowbar/`.

## Update it

On the host (drive plugged in):

```bash
~/.crowbar/bin/crowbar update           # ~10-60 s: modified CVEs + KEV + EPSS + Exploit-DB
~/.crowbar/bin/crowbar update --deep    # also Nuclei / Metasploit / ATT&CK
~/.crowbar/bin/crowbar verify           # index + dataset hashes
```

Scheduling is declared in nix (`launchd.agents.crowbar`, see `docs/NIX.md`),
not installed imperatively. Until it is wired up, run `crowbar update` by hand after
plugging the drive in. For a full rebuild: `crowbar sync && crowbar build`.

## Verify before trusting it

```bash
./bin/crowbar doctor          # schema, integrity, freshness, disk
./scripts/selftest.py 2>/dev/null || python3 scripts/selftest.py
```

## Care

- Eject cleanly (`diskutil eject /Volumes/VAULT`) so the SQLite index is not
  torn mid-write.
- `data/` is upstream third-party content; see `docs/DATASETS.md` for licenses.
- Reference data is not authorization: only test systems you may test.
"""


def cmd_setup_drive(args) -> None:
    vault = pathlib.Path(args.path).expanduser().resolve()
    vault.mkdir(parents=True, exist_ok=True)
    if not os.access(vault, os.W_OK):
        die(f"{vault} is not writable")
    if any(vault.iterdir()) and not args.force:
        die(f"{vault} is not empty - pass --force to merge into it")
    print(f"installing vault -> {vault}")
    for name in CODE:
        src = paths.ROOT / name
        if not src.exists():
            continue
        dst = vault / name
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)   # refresh code in place
        else:
            shutil.copy2(src, dst)
    (vault / paths.DRIVE_MARKER).write_text(
        f"crowbar drive\ncreated {time.strftime('%Y-%m-%d')}\n")

    if not args.no_data:
        data_src, data_dst = paths.DATA, vault / "data"
        if not data_dst.exists():
            print(f"copying data ({datasets.human(_du(data_src))})…")
            shutil.copytree(data_src, data_dst)
        elif shutil.which("rsync"):
            # refresh an existing drive incrementally; keep drive-only files
            print("refreshing data (rsync)…")
            subprocess.run(["rsync", "-a", f"{data_src}/", f"{data_dst}/"], check=True)
        else:
            print("refreshing data (copy)…")
            shutil.copytree(data_src, data_dst, dirs_exist_ok=True)
        idx_dst = vault / "index"
        idx_dst.mkdir(exist_ok=True)
        for f in ("manifest.json", "state.json", "stats.json"):
            if (paths.INDEX / f).exists():
                shutil.copy2(paths.INDEX / f, idx_dst / f)
        print(f"copying index ({datasets.human(paths.DB.stat().st_size)})…")
        _copy_db(paths.DB, idx_dst / "crowbar.db")

        # verify and repair any file that was re-written while copying
        import json as _json
        man = _json.loads((idx_dst / "manifest.json").read_text()).get("datasets", {}) \
            if (idx_dst / "manifest.json").exists() else {}
        for name, rec in man.items():
            src_file, dst_file = paths.DATA / rec["path"], data_dst / rec["path"]
            if rec.get("sha256") and src_file.exists() and dst_file.exists() \
                    and datasets.sha256(dst_file) != rec["sha256"]:
                print(f"repairing {name}")
                shutil.copy2(src_file, dst_file)

    (vault / "START-HERE.md").write_text(
        START_HERE.format(date=time.strftime("%Y-%m-%d"),
                          size=datasets.human(_du(vault))))

    link = paths.HOME_LINK
    if link.is_symlink() or link.exists():
        if not args.force:
            print(f"{link} exists - not replacing (use --force)")
            link = None
        else:
            link.unlink() if link.is_symlink() else shutil.rmtree(link)
    if link is not None:
        link.symlink_to(vault, target_is_directory=True)
        print(f"linked ~/.crowbar -> {vault}")
    print("\nnext:")
    print(f"  {vault}/bin/crowbar doctor")
    print(f"  {vault}/bin/crowbar update            # when the drive is mounted")


def _du(p: pathlib.Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())


PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>sh.crowbar.update</string>
  <key>ProgramArguments</key><array><string>{wrapper}</string></array>
  <key>StartInterval</key><integer>{interval}</integer>
  <key>RunAtLoad</key><true/>
  <key>WatchPaths</key><array><string>/Volumes</string></array>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"""

WRAPPER = """#!/bin/sh
# crowbar auto-update.
# Prefer the drive copy; fall back to the local copy when the drive is absent
# or unreadable (macOS TCC blocks launchd jobs from /Volumes until "Full Disk
# Access" is granted to /bin/sh).
LOG="$HOME/Library/Logs/crowbar.log"
DRIVE="$HOME/.crowbar/bin/crowbar"
LOCAL="{root}/bin/crowbar"
PY="{python}"
run() {{ "$PY" "$1" update --quiet --if-mounted; }}

if [ -x "$DRIVE" ]; then
  run "$DRIVE" && exit 0
  echo "$(date '+%F %T') drive update failed (grant Full Disk Access to /bin/sh for /Volumes access); using local copy" >> "$LOG"
fi
if [ -x "$LOCAL" ]; then run "$LOCAL"
else PYTHONPATH="{pkg}" "$PY" -m crowbar.cli update --quiet; fi
exit 0
"""


def _write_wrapper() -> pathlib.Path:
    wrapper = pathlib.Path.home() / ".local/bin/crowbar-autoupdate"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(WRAPPER.format(root=paths.ROOT, python=sys.executable,
                                      pkg=pathlib.Path(__file__).resolve().parents[1]))
    wrapper.chmod(0o755)
    return wrapper


def cmd_install_agent(args) -> None:
    if pathlib.Path("/run/current-system").exists():
        print(f"{YEL}note:{RST} this machine is managed by nix. "
              f"Declaring the agent in home-manager is cleaner - see docs/NIX.md.", file=sys.stderr)
    wrapper = _write_wrapper()
    if sys.platform == "darwin":
        plist = pathlib.Path.home() / "Library/LaunchAgents/sh.crowbar.update.plist"
        plist.parent.mkdir(parents=True, exist_ok=True)
        log = pathlib.Path.home() / "Library/Logs/crowbar.log"
        plist.write_text(PLIST.format(wrapper=wrapper, interval=args.interval, log=log))
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(plist)],
                       capture_output=True)
        res = subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist)],
                             capture_output=True, text=True)
        if res.returncode != 0:
            die(f"launchctl: {res.stderr.strip()}")
        print(f"launchd agent installed: {plist}")
        print(f"  wrapper: {wrapper}")
        print(f"  every {args.interval}s and whenever /Volumes changes")
        print(f"  log: {log}")
    else:
        print("add to crontab -e:\n"
              f"  */{max(1, args.interval // 60)} * * * * {wrapper}")


def cmd_uninstall_agent(args) -> None:
    if sys.platform == "darwin":
        plist = pathlib.Path.home() / "Library/LaunchAgents/sh.crowbar.update.plist"
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(plist)],
                       capture_output=True)
        if plist.exists():
            plist.unlink()
    wrapper = pathlib.Path.home() / ".local/bin/crowbar-autoupdate"
    if wrapper.exists():
        wrapper.unlink()
    print("removed auto-update agent")


def cmd_watch(args) -> None:
    print(f"watching {paths.HOME_LINK} every {args.interval}s (ctrl-c to stop)")
    present = _mounted()
    while True:
        time.sleep(args.interval)
        now = _mounted()
        if now and not present:
            print(f"[{time.strftime('%H:%M:%S')}] drive appeared - updating")
            subprocess.run([sys.executable, str(paths.ROOT / "bin/crowbar"), "update", "--quiet"])
        elif not now and present:
            print(f"[{time.strftime('%H:%M:%S')}] drive removed")
        present = now


# ---------------------------------------------------------------- opencode
def _mcp_command(local: bool = False) -> list[str]:
    """Portable launch command for the MCP server. Defaults to the published
    package via uvx; --local uses the source checkout's mcp/server.py."""
    if local and (paths.ROOT / "mcp/server.py").exists():
        return [sys.executable, str(paths.ROOT / "mcp/server.py")]
    return ["uvx", "--from", "crowbar-cli", "crowbar-mcp"]


def cmd_connect(args) -> None:
    host = getattr(args, "host", "opencode")
    cmd = _mcp_command(local=getattr(args, "local", False))
    if getattr(args, "print", False):
        host = "print"

    if host in ("print", "claude", "codex", "cursor", "gemini"):
        block = {"mcpServers": {"crowbar": {"command": cmd[0], "args": cmd[1:]}}}
        if host == "claude":
            print("# Claude Code - run this, or paste the block into .mcp.json:")
            print(f"claude mcp add crowbar -- {' '.join(cmd)}\n")
        elif host != "print":
            print(f"# {host}: add this to the host's MCP server config:")
        out_json(block)
        if host in ("claude", "codex") and paths.SKILL.exists():
            print(f"\n# skill: {paths.SKILL / 'SKILL.md'} (install into the host's skills dir)")
        return

    # opencode: write the config file and install the skill
    block = {"type": "local", "command": cmd, "enabled": True, "timeout": 15000}
    target = (pathlib.Path.home() / ".config/opencode/opencode.json"
              if args.global_ else pathlib.Path(args.target).resolve())
    cfg = {}
    if target.exists():
        try:
            cfg = json.loads(target.read_text() or "{}")
        except json.JSONDecodeError:
            die(f"{target} is not valid JSON - fix it first")
    cfg.setdefault("$schema", "https://opencode.ai/config.json")
    cfg.setdefault("mcp", {})["crowbar"] = block
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(cfg, indent=2) + "\n")
    print(f"mcp server registered -> {target}")
    if not args.no_skill and paths.SKILL.exists():
        dst = target.parent / ".opencode/skills/crowbar"
        dst.mkdir(parents=True, exist_ok=True)
        shutil.copy2(paths.SKILL / "SKILL.md", dst / "SKILL.md")
        print(f"skill installed      -> {dst / 'SKILL.md'}")
    print("restart opencode; the crowbar tools will appear automatically")


def cmd_mcp(args) -> None:
    from . import mcp
    mcp.serve()


# ---------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    from crowbar import __version__
    p = argparse.ArgumentParser(prog="crowbar", description="crowbar - local vulnerability index (terminal only)")
    p.add_argument("--version", action="version", version=f"crowbar {__version__}")
    p.add_argument("--width", type=int, default=110)
    p.set_defaults(fn=cmd_home)
    sub = p.add_subparsers(dest="cmd")

    def add(name, fn, help_):
        s = sub.add_parser(name, help=help_)
        s.set_defaults(fn=fn)
        return s

    s = add("search", cmd_search, "full-text CVE search")
    s.add_argument("query", nargs="?")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--sort", choices=["relevance", "newest", "oldest", "cvss", "epss"], default="relevance")
    s.add_argument("--severity")
    s.add_argument("--year", type=int)
    s.add_argument("--since")
    s.add_argument("--kev", action="store_true")
    s.add_argument("--exploit", action="store_true")
    s.add_argument("--epss", type=float)
    s.add_argument("--cvss", type=float)
    s.add_argument("--cwe")
    s.add_argument("--product")
    s.add_argument("--vendor")
    s.add_argument("--ssvc", help="CISA SSVC exploitation: none|poc|active")
    s.add_argument("--poc", action="store_true", help="only CVEs with a public PoC")
    s.add_argument("--json", action="store_true")

    s = add("browse", cmd_browse, "interactive fzf browser")
    s.add_argument("query", nargs="?")
    s.add_argument("--limit", type=int, default=500)
    s.add_argument("--kev", action="store_true")
    s.add_argument("--exploit", action="store_true")

    s = add("cve", cmd_cve, "one CVE in full")
    s.add_argument("id")
    s.add_argument("--json", action="store_true")

    s = add("product", cmd_product, "CVEs affecting a product, optionally a version")
    s.add_argument("name")
    s.add_argument("--version", help="exact version to test against CPE ranges, e.g. 1.18.0")
    s.add_argument("--limit", type=int, default=25)
    s.add_argument("--json", action="store_true")

    s = add("trending", cmd_trending, "CVEs people are posting about (HN, mailing lists, ZDI, Mastodon, EUVD)")
    s.add_argument("--days", type=float, default=7)
    s.add_argument("--limit", type=int, default=25)
    s.add_argument("--json", action="store_true")

    s = add("new", cmd_new, "what changed: KEV/EUVD exploited additions, new CVEs, new PoCs")
    s.add_argument("--since", help="YYYY-MM-DD (default: --days ago)")
    s.add_argument("--days", type=float, default=7)
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--json", action="store_true")

    s = add("bench", cmd_bench, "time common queries on this index")
    s.add_argument("--runs", type=int, default=5)
    s.add_argument("--json", action="store_true")

    s = add("kev", cmd_kev, "CISA Known Exploited Vulnerabilities")
    s.add_argument("query", nargs="?")
    s.add_argument("--limit", type=int, default=25)
    s.add_argument("--json", action="store_true")

    s = add("exploit", cmd_exploit, "search Exploit-DB, or show one by id")
    s.add_argument("query")
    s.add_argument("--fetch", action="store_true", help="download the source for an id")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")

    s = add("nuclei", cmd_nuclei, "search Nuclei templates")
    s.add_argument("query", nargs="?")
    s.add_argument("--domain", help="http, network, dns, file, headless, cloud, javascript, ssl, code")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")

    s = add("msf", cmd_msf, "search Metasploit modules")
    s.add_argument("query", nargs="?")
    s.add_argument("--limit", type=int, default=30)
    s.add_argument("--json", action="store_true")

    s = add("models", cmd_models, "LLM catalog: context, price, capabilities")
    s.add_argument("query", nargs="?")
    s.add_argument("--provider")
    s.add_argument("--limit", type=int, default=40)
    s.add_argument("--json", action="store_true")

    s = add("attack", cmd_attack, "MITRE ATT&CK techniques")
    s.add_argument("query", nargs="?")
    s.add_argument("--domain", choices=["enterprise", "mobile", "ics"])
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--json", action="store_true")

    s = add("cwe", cmd_cwe, "CWE weakness lookup")
    s.add_argument("query", nargs="?")
    s.add_argument("--limit", type=int, default=30)
    s.add_argument("--json", action="store_true")

    s = add("capec", cmd_capec, "CAPEC attack patterns")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=15)
    s.add_argument("--json", action="store_true")

    s = add("os", cmd_os, "Windows / iOS / macOS vendor advisories")
    s.add_argument("query", nargs="?", default=None)
    s.add_argument("--platform", choices=["windows", "ios", "macos", "apple"])
    s.add_argument("--impact", help="RCE, EoP, DoS, InfoDisclosure, Spoofing, Bypass")
    s.add_argument("--exploited", action="store_true")
    s.add_argument("--since")
    s.add_argument("--limit", type=int, default=40)
    s.add_argument("--json", action="store_true")

    s = add("advisory", cmd_advisory, "OSV/GHSA advisories by package or ecosystem")
    s.add_argument("query", nargs="?", default=None)
    s.add_argument("--ecosystem")
    s.add_argument("--package")
    s.add_argument("--limit", type=int, default=30)
    s.add_argument("--json", action="store_true")

    s = add("code", cmd_code, "full-text search inside Exploit-DB sources")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")

    s = add("bin", cmd_bin, "GTFOBins / LOLBAS / PayloadsAllTheThings")
    s.add_argument("query", nargs="?")
    s.add_argument("--source", choices=["gtfobins", "lolbas", "payloads"])
    s.add_argument("--limit", type=int, default=25)
    s.add_argument("--json", action="store_true")

    s = add("debian", cmd_debian, "Debian tracker: fixed versions per release")
    s.add_argument("package")
    s.add_argument("--cve")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--json", action="store_true")

    s = add("poc", cmd_poc, "public GitHub PoC repositories (metadata only)")
    s.add_argument("query", nargs="?", default="")
    s.add_argument("--cve")
    s.add_argument("--language")
    s.add_argument("--min-stars", type=int, default=0)
    s.add_argument("--top", action="store_true", help="CVEs with the most PoCs")
    s.add_argument("--limit", type=int, default=25)
    s.add_argument("--json", action="store_true")

    s = add("sources", cmd_sources, "source provenance: url, license, sha256, row counts")
    s.add_argument("--json", action="store_true")

    s = add("map", cmd_map, "dataset -> path -> index table map")
    s.add_argument("--tables", action="store_true", help="explain every table")
    s.add_argument("--json", action="store_true")

    s = add("sql", cmd_sql, "read-only SQL escape hatch")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=200)
    s.add_argument("--json", action="store_true")

    s = add("stats", cmd_stats, "corpus statistics and freshness")
    s.add_argument("--json", action="store_true")

    add("where", cmd_where, "print paths").add_argument("--json", action="store_true")
    s = add("doctor", cmd_doctor, "health check")
    s.add_argument("--json", action="store_true")

    s = add("sync", cmd_sync, "download datasets")
    s.add_argument("--tier", choices=datasets.TIER_NAMES,
                   help="size tier: lite ~150MB, medium ~500MB, heavy ~2GB, extreme full (each a superset)")
    s.add_argument("--only")
    s.add_argument("--years")
    s.add_argument("--extra", action="store_true", help="ATT&CK mobile/ics + CISA Vulnrichment")
    s.add_argument("--bulk", action="store_true", help="+ OSV ecosystems, Debian tracker, full Exploit-DB")
    s.add_argument("--force", action="store_true")
    s.add_argument("--pull", action="store_true", help="git pull existing clones")
    s.add_argument("--jobs", type=int, default=4)

    s = add("pack", cmd_pack, "package synced datasets as a mirror for CROWBAR_MIRROR")
    s.add_argument("dir")

    s = add("build", cmd_build, "build the index from downloaded data")
    s.add_argument("--tier", choices=datasets.TIER_NAMES, help="record the size tier this index was built for")
    s.add_argument("--allow-incomplete", action="store_true", help="build even if some tier datasets are missing")
    s.add_argument("--quick", action="store_true", help="CVEs + exploits only")
    s.add_argument("--extra", action="store_true")
    s.add_argument("--bulk", action="store_true")
    s.add_argument("--json", action="store_true")

    s = add("update", cmd_update, "incremental refresh (modified CVEs + intel)")
    s.add_argument("--deep", action="store_true", help="also reindex Nuclei/MSF/ATT&CK")
    s.add_argument("--if-mounted", action="store_true", help="no-op when the drive is absent")
    s.add_argument("--no-sync", action="store_true")
    s.add_argument("--extra", action="store_true")
    s.add_argument("--jobs", type=int, default=4)
    s.add_argument("--quiet", action="store_true")
    s.add_argument("--json", action="store_true")

    s = add("link", cmd_link, "link the corpus into a project as .crowbar")
    s.add_argument("dir", nargs="?", default=".")
    s.add_argument("--force", action="store_true")

    s = add("unlink", cmd_unlink, "remove the project link")
    s.add_argument("dir", nargs="?", default=".")

    s = add("verify", cmd_verify, "check index + dataset hashes")
    s.add_argument("--json", action="store_true")

    add("selftest", cmd_selftest, "offline gate: static checks + tests + verify (no sync)")

    s = add("setup-drive", cmd_setup_drive, "install the harness on a USB drive")
    s.add_argument("path")
    s.add_argument("--no-data", action="store_true", help="code only, no data/index copy")
    s.add_argument("--force", action="store_true")

    s = add("install-agent", cmd_install_agent, "refresh automatically when the drive appears")
    s.add_argument("--interval", type=int, default=600)

    add("uninstall-agent", cmd_uninstall_agent, "remove the launchd agent")

    s = add("watch", cmd_watch, "foreground mount watcher")
    s.add_argument("--interval", type=int, default=60)

    s = add("connect", cmd_connect, "register the MCP server with an agent host")
    s.add_argument("--host", choices=["opencode", "claude", "codex", "cursor", "gemini", "print"],
                   default="opencode", help="which agent host to wire up (default: opencode)")
    s.add_argument("--local", action="store_true", help="launch from this source checkout instead of uvx")
    s.add_argument("--target", default=str(paths.ROOT.parent / "opencode.json"))
    s.add_argument("--global", dest="global_", action="store_true")
    s.add_argument("--no-skill", action="store_true")
    s.add_argument("--print", action="store_true")

    add("mcp", cmd_mcp, "run the MCP server on stdio")
    return p


def main() -> None:
    args = build_parser().parse_args()
    try:
        args.fn(args)
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        sys.exit(130)
    except db.NotIndexed as exc:
        die(str(exc))
    except ValueError as exc:
        die(str(exc))
    except OSError as exc:   # network or disk: a message, not a traceback
        die(f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
