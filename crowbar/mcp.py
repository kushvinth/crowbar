"""MCP stdio server. Zero dependencies; calls the query layer directly."""
from __future__ import annotations

from crowbar import __version__

import json
import os
import sqlite3
import sys
import time
import traceback

from . import catalog, datasets, db, paths, query

# Hard safety ceiling for a single tool response (~bytes). The query layer
# keeps normal responses far smaller; this only catches pathological results
# (e.g. cb_sql with a huge limit) and never emits invalid JSON.
MAX_CHARS = 120_000


def fit_response(result) -> tuple[str, bool]:
    """Serialise a tool result, replacing an over-ceiling payload with a
    valid-JSON overflow notice instead of slicing mid-structure."""
    text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    if len(text) <= MAX_CHARS:
        return text, False
    notice = {
        "error": "result_too_large",
        "bytes": len(text),
        "limit": MAX_CHARS,
        "hint": "narrow the query or lower 'limit'; fetch one record with cb_cve",
    }
    return json.dumps(notice, indent=2), True

TOOLS = [
    {
        "name": "cb_search",
        "description": ("Full-text search across every CVE (2002-today). Ranked by relevance "
                        "blended with CISA KEV, EPSS and public-exploit availability. Filters: "
                        "kev, exploit, min_epss, min_cvss, severity, year, since, cwe, product, "
                        "vendor, ssvc, poc."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 15},
                "offset": {"type": "integer", "minimum": 0, "default": 0},
                "sort": {"type": "string", "enum": ["relevance", "newest", "oldest", "cvss", "epss"]},
                "kev": {"type": "boolean"},
                "exploit": {"type": "boolean"},
                "min_epss": {"type": "number"},
                "min_cvss": {"type": "number"},
                "severity": {"type": "string"},
                "year": {"type": "integer"},
                "since": {"type": "string"},
                "cwe": {"type": "string"},
                "product": {"type": "string"},
                "vendor": {"type": "string"},
                "ssvc": {"type": "string", "description": "none | poc | active"},
                "poc": {"type": "boolean", "description": "only CVEs with a public PoC"},
            },
        },
        "fn": lambda con, a: query.search(
            con, a.get("query", ""), limit=a.get("limit", 15),
            offset=a.get("offset", 0), sort=a.get("sort", "relevance"),
            kev=bool(a.get("kev")), exploit=bool(a.get("exploit")),
            epss=a.get("min_epss"), cvss=a.get("min_cvss"), severity=a.get("severity"),
            year=a.get("year"), since=a.get("since"), cwe=a.get("cwe"),
            product=a.get("product"), vendor=a.get("vendor"), ssvc=a.get("ssvc"),
            poc=bool(a.get("poc"))),
    },
    {
        "name": "cb_cve",
        "description": ("One CVE in full: CVSS, EPSS, KEV, CWE, CPE version ranges, references, "
                        "Exploit-DB / Nuclei / Metasploit hits, SSVC decision points."),
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}},
                        "required": ["id"]},
        "fn": lambda con, a: query.get_cve(con, a["id"]),
    },
    {
        "name": "cb_product",
        "description": ("CVEs affecting a product/vendor. Pass version to test NVD CPE version "
                        "ranges, e.g. {name: nginx, version: 1.18.0}."),
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"},
                           "version": {"type": "string"},
                           "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25}},
            "required": ["name"],
        },
        "fn": lambda con, a: query.products(con, a["name"], a.get("version"),
                                       a.get("limit", 25)),
    },
    {
        "name": "cb_trending",
        "description": ("CVEs people are posting about right now, ranked by how many distinct places "
                        "name them (Hacker News, oss-security, Full Disclosure, ZDI, Mastodon, ENISA "
                        "EUVD exploited) with KEV/EPSS/CVSS beside each."),
        "inputSchema": {"type": "object", "properties": {
            "days": {"type": "number", "minimum": 1, "maximum": 365, "default": 7},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25}}},
        "fn": lambda con, a: query.trending(con, a.get("days", 7), a.get("limit", 25)),
    },
    {
        "name": "cb_new",
        "description": ("What changed since a date (default 7 days): CISA KEV and ENISA exploited "
                        "additions, newly published CVEs (KEV > EPSS > CVSS first), new public PoCs. "
                        "Each part has `total` and the top `rows`."),
        "inputSchema": {"type": "object", "properties": {
            "since": {"type": "string", "description": "YYYY-MM-DD"},
            "days": {"type": "number", "minimum": 1, "maximum": 365, "default": 7},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 10}}},
        "fn": lambda con, a: query.new_since(con, a.get("since"), a.get("days", 7), a.get("limit", 10)),
    },
    {
        "name": "cb_kev",
        "description": "CISA Known Exploited Vulnerabilities catalog.",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25}}},
        "fn": lambda con, a: query.kev_list(con, a.get("query"), a.get("limit", 25)),
    },
    {
        "name": "cb_exploit",
        "description": ("Search the Exploit-DB index (46k entries), offline. To download the "
                        "source for a numeric id, use the CLI: `crowbar exploit <id>`. Nothing is executed."),
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
            "required": ["query"]},
        "fn": lambda con, a: query.exploit_lookup(con, a["query"])
                         if a["query"].isdigit()
                         else query.exploit_search(con, a["query"], a.get("limit", 20)),
    },
    {
        "name": "cb_nuclei",
        "description": "Search Nuclei templates; returns YAML paths for exact matchers.",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "domain": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
            "required": ["query"]},
        "fn": lambda con, a: query.nuclei_search(con, a["query"], a.get("limit", 20),
                                            a.get("domain")),
    },
    {
        "name": "cb_msf",
        "description": "Search Metasploit module paths.",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 30}},
            "required": ["query"]},
        "fn": lambda con, a: query.msf_search(con, a["query"], a.get("limit", 30)),
    },
    {
        "name": "cb_models",
        "description": "LLM catalog: context window, price per M tokens, capabilities.",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"}, "provider": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 40}}},
        "fn": lambda con, a: query.models_list(con, a.get("query"), a.get("provider"),
                                          a.get("limit", 40)),
    },
    {
        "name": "cb_attack",
        "description": "MITRE ATT&CK technique lookup (enterprise, mobile, ics).",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"}, "domain": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}},
            "required": ["query"]},
        "fn": lambda con, a: query.attack_lookup(con, a["query"], a.get("limit", 10),
                                            a.get("domain")),
    },
    {
        "name": "cb_cwe",
        "description": "CWE definitions (id or keyword).",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}}},
        "fn": lambda con, a: query.cwe_get(con, a.get("query"), a.get("limit", 20)),
    },
    {
        "name": "cb_os",
        "description": ("Vendor OS advisories: Windows (MSRC Security Update Guide) and Apple "
                        "iOS/iPadOS/macOS security releases. Filter by platform, impact (RCE, "
                        "EoP, DoS, InfoDisclosure, Spoofing, Bypass) or exploited."),
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "platform": {"type": "string", "enum": ["windows", "ios", "macos", "apple"]},
            "impact": {"type": "string"},
            "exploited": {"type": "boolean"},
            "since": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 40}}},
        "fn": lambda con, a: query.os_search(con, a.get("query"), a.get("platform"),
                                        a.get("impact"), bool(a.get("exploited")),
                                        a.get("since"), a.get("limit", 40)),
    },
    {
        "name": "cb_advisory",
        "description": ("OSV/GHSA advisories with introduced/fixed version ranges. Filter by "
                        "ecosystem (npm, PyPI, Go, Maven, NuGet, RubyGems, crates.io, Packagist, "
                        "Debian, Alpine) or exact package name."),
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"}, "ecosystem": {"type": "string"},
            "package": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 30}}},
        "fn": lambda con, a: query.advisory_search(con, a.get("query"), a.get("ecosystem"),
                                              a.get("package"), a.get("limit", 30)),
    },
    {
        "name": "cb_code",
        "description": "Full-text search inside Exploit-DB source code; returns path + snippet.",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
            "required": ["query"]},
        "fn": lambda con, a: query.code_search(con, a["query"], a.get("limit", 20)),
    },
    {
        "name": "cb_binary",
        "description": ("Living-off-the-land binary abuse: GTFOBins (unix), LOLBAS (windows), "
                        "PayloadsAllTheThings (web payloads)."),
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "source": {"type": "string", "enum": ["gtfobins", "lolbas", "payloads"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25}},
            "required": ["query"]},
        "fn": lambda con, a: query.toolkit_search(con, a["query"], a.get("source"),
                                             a.get("limit", 25)),
    },
    {
        "name": "cb_debian",
        "description": "Debian security tracker: per-release status and fixed version for a package.",
        "inputSchema": {"type": "object", "properties": {
            "package": {"type": "string"}, "cve": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50}},
            "required": ["package"]},
        "fn": lambda con, a: query.debian_lookup(con, a["package"], a.get("cve"), a.get("limit", 50)),
    },
    {
        "name": "cb_poc",
        "description": ("Public GitHub PoC repositories (PoC-in-GitHub metadata). Never "
                        "executed. Filter by CVE, language or minimum stars, or list the "
                        "CVEs with the most PoCs."),
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "cve": {"type": "string"},
            "language": {"type": "string"},
            "min_stars": {"type": "integer", "minimum": 0, "default": 0},
            "top": {"type": "boolean", "description": "CVEs ranked by PoC count"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25}}},
        "fn": lambda con, a: (query.poc_cves(con, a.get("limit", 25))
                         if a.get("top")
                         else query.poc_search(con, a.get("query", ""), cve=a.get("cve"),
                                               language=a.get("language"),
                                               min_stars=a.get("min_stars", 0),
                                               limit=a.get("limit", 25))),
    },
    {
        "name": "cb_sources",
        "description": ("Source provenance: which upstream source filled the index, its URL, "
                        "license, SHA-256, load time and row count."),
        "inputSchema": {"type": "object", "properties": {}},
        "fn": lambda con, a: [dict(r) for r in con.execute(
            "SELECT source, url, license, sha256, fetched_at, loaded_at, record_count, "
            "status, note FROM source_state ORDER BY source")],
    },
    {
        "name": "cb_tables",
        "description": "Data map: every index table, what it holds, and which command/dataset feeds it.",
        "inputSchema": {"type": "object", "properties": {}},
        "fn": lambda con, a: {"tables": catalog.TABLES, "datasets": catalog.GROUPS},
    },
    {
        "name": "cb_sql",
        "description": ("Read-only SQL. Tables: cve, cve_cwe, cve_product, cpe_match, cve_ref, "
                        "cve_exploit, cve_nuclei, cve_msf, kev, exploit, shellcode, nuclei, msf, "
                        "attack, cwe, capec, model, ssvc, advisory, package_range, debian, "
                        "os_advisory, toolkit, cve_cna, cve_meta, poc, poc_orphan, "
                        "cve_alias, source_state, exploit_code_fts, toolkit_fts, meta."),
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}},
            "required": ["query"]},
        "fn": lambda con, a: query.sql_readonly(con, a["query"], a.get("limit", 100)),
    },
    {
        "name": "cb_stats",
        "description": ("Corpus health and freshness. `index.age_days` is days since the last "
                        "update; `index.stale` means older than the 8-day NVD change window, so "
                        "recent CVEs may be missing or outdated - say so and run `crowbar update`. "
                        "`index.last_error` is why the last background update failed."),
        "inputSchema": {"type": "object", "properties": {}},
        # the per-dataset freshness map is large; index_status() is the summary agents need
        "fn": lambda con, a: {**{k: v for k, v in query.stats(con).items() if k != "freshness"},
                              "index": datasets.index_status()},
    },
]
BY_NAME = {t["name"]: t for t in TOOLS}


class BadArgs(ValueError):
    """Client-supplied arguments failed the tool's inputSchema."""


def validate_args(schema: dict, args: dict) -> dict:
    """Enforce the inputSchema the server advertises: required args must be
    present, and integer args are clamped to their declared min/max so an
    unbounded or negative `limit` can't materialize a whole table."""
    props = schema.get("properties") or {}
    for name in schema.get("required") or []:
        if name not in args:
            raise BadArgs(f"missing required argument: {name}")
    for name, spec in props.items():
        if name in args and spec.get("type") == "integer" and isinstance(args[name], int):
            lo, hi = spec.get("minimum"), spec.get("maximum")
            if lo is not None:
                args[name] = max(lo, args[name])
            if hi is not None:
                args[name] = min(hi, args[name])
    return args


# ---------------------------------------------------------------- protocol
def respond(msg_id, result=None, error=None) -> None:
    payload = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()



def handle(req: dict) -> None:
    method, rid = req.get("method"), req.get("id")
    if method == "initialize":
        respond(rid, {
            "protocolVersion": req.get("params", {}).get("protocolVersion") or "2025-06-18",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "crowbar", "version": __version__},
            "instructions": ("Local vulnerability intelligence: CVEs 2002-today, KEV, EPSS, "
                             "CPE version ranges, Exploit-DB (index + source code), Nuclei, "
                             "Metasploit, OSV/GHSA, Debian tracker, MSRC Windows and Apple "
                             "iOS/macOS advisories, GTFOBins/LOLBAS, ATT&CK, CWE, CAPEC, LLM "
                             "catalog. Start with cb_stats; use cb_map-equivalent `crowbar map` in CLI "
                             "for the table map."),
        })
        return
    if method in ("notifications/initialized", "notifications/cancelled"):
        return
    if method == "ping":
        respond(rid, {})
        return
    if method == "tools/list":
        respond(rid, {"tools": [{"name": t["name"], "description": t["description"],
                                 "inputSchema": t["inputSchema"]} for t in TOOLS]})
        return
    if method == "tools/call":
        params = req.get("params") or {}
        tool = BY_NAME.get(params.get("name"))
        if not tool:
            respond(rid, error={"code": -32602, "message": f"unknown tool: {params.get('name')}"})
            return
        try:
            args = validate_args(tool["inputSchema"], params.get("arguments") or {})
        except BadArgs as exc:
            respond(rid, error={"code": -32602, "message": str(exc)})
            return
        try:
            con = connection()
            err = db.schema_error(con)
            if err:   # wrong or damaged index: reopen on the next call
                close_connection()
                respond(rid, {"content": [{"type": "text", "text": err}], "isError": True})
                return
            result = tool["fn"](con, args)
            if tool["name"] == "cb_sql" and args["query"].lstrip().lower().startswith("pragma"):
                close_connection()   # a PRAGMA would otherwise stick for every later call
            text, over = fit_response(result)
            content = [{"type": "text", "text": text}]
            warn = check_freshness()
            if warn:
                content.append({"type": "text", "text": warn})
            respond(rid, {"content": content, "isError": over})
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, sqlite3.DatabaseError):
                close_connection()   # next call reopens (file swapped or damaged under us)
            # Full detail (incl. filesystem paths) to stderr only; the client
            # gets the exception type and a root-redacted message.
            print(f"crowbar tool {tool['name']} failed:\n{traceback.format_exc()}",
                  file=sys.stderr)
            msg = f"{type(exc).__name__}: {exc}".replace(str(paths.ROOT), "<root>")
            respond(rid, {"content": [{"type": "text", "text": msg}], "isError": True})
        return
    if rid is not None:
        respond(rid, error={"code": -32601, "message": f"method not found: {method}"})


_con: list = [None, None]   # connection, (inode, mtime_ns) of the file it opened


def connection() -> sqlite3.Connection:
    """One read-only connection for the server's lifetime, reopened when the index
    file changed underneath it: `update` swaps the file (new inode) or rewrites it
    in place (same inode, new mtime)."""
    try:
        st = paths.DB.stat()
        key = (st.st_ino, st.st_mtime_ns)
    except OSError:
        key = None
    if _con[0] is None or _con[1] != key:
        close_connection()
        _con[0], _con[1] = db.connect(), key
    return _con[0]


def close_connection() -> None:
    if _con[0] is not None:
        _con[0].close()
    _con[0] = None


_checked = [0.0]


def check_freshness() -> str | None:
    """At most every 10 minutes: start a background refresh if the index is a day old,
    and return a note for the agent when it is stale (so a server that runs for days
    neither serves old data silently nor waits for a restart to refresh)."""
    if time.time() - _checked[0] < 600 or not paths.DB.exists():
        return None
    _checked[0] = time.time()
    s = datasets.index_status()
    if datasets.refresh_in_background(s):
        print("crowbar mcp: index over a day old, refreshing in the background", file=sys.stderr)
    if not s["stale"]:
        return None
    err = f"; last update failed: {s['last_error']['error']}" if s["last_error"] else ""
    return (f"note: the crowbar index is {s['age_days']} days old{err}. CVEs published or "
            f"changed since then may be missing - tell the user and suggest `crowbar update`.")


def serve() -> None:
    if os.environ.get("CROWBAR_DEBUG"):
        print(f"crowbar mcp: {len(TOOLS)} tools, root={paths.ROOT}", file=sys.stderr)
    # refresh early; the first tool call still checks, so it can warn the agent
    if paths.DB.exists() and datasets.refresh_in_background():
        print("crowbar mcp: index over a day old, refreshing in the background", file=sys.stderr)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            respond(None, error={"code": -32700, "message": "parse error"})
            continue
        try:
            handle(req)
        except Exception as exc:  # noqa: BLE001
            if os.environ.get("CROWBAR_DEBUG"):
                traceback.print_exc()
            respond(req.get("id"), error={"code": -32603, "message": str(exc)})


if __name__ == "__main__":
    serve()
