"""Static map: dataset -> files on disk -> index tables -> query surface.

Agents read this instead of guessing where a fact lives. Keep it in sync when a
dataset or table is added; `crowbar map` renders it together with live status.
"""

from __future__ import annotations

from . import chatter, paths

# dataset group -> (on-disk path, tables it populates, example command)
GROUPS: dict[str, dict] = {
    "nvd": {
        "path": "data/nvd/*.json.gz",
        "tables": ["cve", "cve_cwe", "cve_product", "cpe_match", "cve_ref", "cve_fts"],
        "commands": ["crowbar search", "crowbar cve", "crowbar product"],
    },
    "cveorg": {
        "path": "data/intel/cveorg/cvelistV5-main.tar.gz",
        "tables": [
            "cve_cna",
            "cve_cna_ref",
            "cve_cna_product",
            "cve",
            "cve_cwe",
            "cve_product",
            "cve_ref",
            "cve_fts",
            "cve_meta",
            "source_state",
        ],
        "commands": ["crowbar cve", "crowbar search", "crowbar sources"],
    },
    "poc": {
        "path": "data/intel/poc-in-github/PoC-in-GitHub-master.tar.gz",
        "tables": ["poc", "poc_orphan", "cve_meta"],
        "commands": ["crowbar poc", "crowbar search --poc"],
    },
    "chatter": {
        "path": "data/chatter/*.jsonl",
        "tables": ["mention"],
        "commands": ["crowbar trending", "crowbar new", "crowbar cve"],
    },
    "kev": {
        "path": "data/kev/known_exploited_vulnerabilities.json",
        "tables": ["kev", "cve.kev"],
        "commands": ["crowbar kev", "crowbar search --kev"],
    },
    "epss": {
        "path": "data/epss/epss_scores-current.csv.gz",
        "tables": ["cve.epss", "cve.epss_pct"],
        "commands": ["crowbar search --epss"],
    },
    "exploitdb": {
        "path": "data/exploitdb/files_exploits.csv, data/exploitdb/full/",
        "tables": ["exploit", "shellcode", "cve_exploit", "exploit_fts", "exploit_code_fts"],
        "commands": ["crowbar exploit", "crowbar code"],
    },
    "nuclei": {
        "path": "data/nuclei/templates/**/*.yaml",
        "tables": ["nuclei", "cve_nuclei", "nuclei_fts"],
        "commands": ["crowbar nuclei"],
    },
    "metasploit": {
        "path": "data/metasploit/tree.json, data/metasploit/source/modules/",
        "tables": ["msf", "cve_msf"],
        "commands": ["crowbar msf"],
    },
    "attack": {
        "path": "data/attack/*-attack.json",
        "tables": ["attack"],
        "commands": ["crowbar attack"],
    },
    "cwe": {
        "path": "data/cwe/cwec_latest.xml.zip",
        "tables": ["cwe", "cve_cwe"],
        "commands": ["crowbar cwe"],
    },
    "capec": {
        "path": "data/capec/capec_latest.xml",
        "tables": ["capec"],
        "commands": ["crowbar capec"],
    },
    "models": {
        "path": "data/models/models.dev.json",
        "tables": ["model", "model_fts"],
        "commands": ["crowbar models"],
    },
    "vulnrichment": {
        "path": "data/vulnrichment/**/*.json",
        "tables": ["ssvc"],
        "commands": ["crowbar search --ssvc active"],
    },
    "osv": {
        "path": "data/osv/<ecosystem>.zip",
        "tables": ["advisory", "package_range"],
        "commands": ["crowbar advisory"],
    },
    "debian": {
        "path": "data/debian/tracker.json",
        "tables": ["debian"],
        "commands": ["crowbar debian"],
    },
    "vendor": {
        "path": "data/msrc/sug.json, data/apple/{index.html,pages/}",
        "tables": ["os_advisory"],
        "commands": ["crowbar os"],
    },
    "toolkit": {
        "path": "data/toolkit/{gtfobins,lolbas,payloads}/",
        "tables": ["toolkit", "toolkit_fts"],
        "commands": ["crowbar bin"],
    },
}

# table -> one-line meaning (used by `crowbar map --tables`)
TABLES: dict[str, str] = {
    "cve": "one row per CVE: description, CVSS, EPSS, KEV flag, exploit/nuclei/msf flags",
    "cve_cna": "CVE List v5 CNA record, stored beside (not replacing) NVD values",
    "cve_cna_ref": "CNA reference URLs (CVE List), kept apart from NVD references",
    "cve_cna_product": "CNA affected vendor/product pairs",
    "cve_meta": "publication year vs CVE-ID year, and public-PoC counts",
    "poc": "public GitHub PoC repositories (metadata only, never executed)",
    "mention": "posts naming a CVE: HN, oss-security, Full Disclosure, ZDI, Mastodon, EUVD exploited",
    "poc_orphan": "PoC CVEs that are absent from the local CVE index",
    "cve_alias": "CVE -> GHSA/OSV alias mapping",
    "source_state": "source URL/license/SHA-256, load time, record count, status",
    "cve_cwe": "CVE -> CWE classification",
    "cve_product": "CVE -> vendor/product candidates (from CPE)",
    "cpe_match": "exact version ranges per CVE (use with `crowbar product --version`)",
    "cve_ref": "reference URLs + tags",
    "cve_exploit": "CVE -> Exploit-DB id",
    "cve_nuclei": "CVE -> Nuclei template id",
    "cve_msf": "CVE -> Metasploit module path (parsed from module sources)",
    "kev": "CISA Known Exploited Vulnerabilities",
    "exploit": "Exploit-DB index row",
    "shellcode": "Exploit-DB shellcode row",
    "nuclei": "Nuclei template metadata",
    "msf": "Metasploit module metadata + CVE refs",
    "attack": "MITRE ATT&CK technique (enterprise/mobile/ics)",
    "cwe": "CWE definition",
    "capec": "CAPEC attack pattern",
    "model": "LLM catalog (context, price, capabilities)",
    "ssvc": "CISA SSVC decision points per CVE",
    "advisory": "OSV/GHSA advisories (ecosystem, package, aliases)",
    "package_range": "OSV introduced/fixed version ranges",
    "debian": "Debian tracker: package x release x CVE status + fixed version",
    "os_advisory": "vendor OS advisories: Windows (MSRC) + Apple iOS/macOS",
    "toolkit": "GTFOBins / LOLBAS / PayloadsAllTheThings entries",
    "exploit_code_fts": "full-text index over Exploit-DB source code",
    "toolkit_fts": "full-text index over toolkit entries",
    "cve_fts": "full-text index over CVE descriptions + products",
    "exploit_fts": "full-text index over Exploit-DB descriptions",
    "nuclei_fts": "full-text index over Nuclei templates",
    "model_fts": "full-text index over model names",
}


def group_of(dataset_name: str) -> str:
    for prefix in ("nvd", "osv", "exploitdb", "attack", "metasploit", "cveorg", "poc"):
        if dataset_name.startswith(prefix):
            return {"metasploit": "metasploit"}.get(prefix, prefix)
    if dataset_name in ("gtfobins", "lolbas", "payloads"):
        return "toolkit"
    if dataset_name in ("metasploit", "msf-source"):
        return "metasploit"
    if dataset_name in ("debian-tracker",):
        return "debian"
    if dataset_name in ("msrc", "apple"):
        return "vendor"
    if dataset_name in chatter.SOURCES:
        return "chatter"
    return dataset_name


def describe(name: str) -> dict:
    return GROUPS.get(group_of(name), {"path": "?", "tables": [], "commands": []})


def disk_state(dest: str) -> tuple[bool, int]:
    p = paths.DATA / dest
    if not p.exists():
        return False, 0
    if p.is_file():
        return True, p.stat().st_size
    total = 0
    for f in p.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return True, total
