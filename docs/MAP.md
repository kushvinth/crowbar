# crowbar map

Where everything lives, how bytes become tables, and which file answers which
question. `crowbar map` prints the same dataset→table map from `crowbar/catalog.py`
at runtime; this file is the orientation layer for humans and agents.

## Tree

```
crowbar/
├── bin/crowbar                  CLI entry point (thin shim → crowbar.cli:main)
├── mcp/server.py           MCP stdio entry point (thin shim → crowbar.mcp:serve)
├── crowbar/
│   ├── paths.py            CROWBAR_HOME-relative paths, schema/version constants
│   ├── datasets.py         dataset registry, downloader, manifest/state, freshness
│   ├── indexer.py          SQLite schema, parsers, build/update orchestration
│   ├── loaders.py          bulk loaders (OSV, Debian, MSRC, Apple, MSF source,
│   │                       Exploit-DB code, GTFOBins/LOLBAS/Payloads)
│   ├── catalog.py          dataset → group → path → tables → command map
│   ├── db.py               read-only connections, counts, schema version
│   ├── query.py            all read queries (FTS, version matching, joins)
│   ├── cli.py              argparse commands + rendering
│   └── mcp.py              JSON-RPC tools (calls query.py in-process)
├── data/                   raw upstream corpora (gitignored, 3.3 GB)
├── index/crowbar.db             SQLite index (~1.7 GB, gitignored)
├── scripts/
│   ├── selftest.py         end-to-end corpus health checks
│   ├── check.py            static consistency (schema/catalog/docs/style)
│   └── make_fixture.py     tiny synthetic index for CI / tests
├── tests/
│   ├── support.py          fixture builder + subprocess helpers
│   ├── test_unit.py        111 fixture tests (CI, no corpus needed)
│   └── test_corpus.py      generated corpus tests (skipped without index)
├── docs/
│   ├── MAP.md              this file
│   ├── DATASETS.md         source list, tiers, caveats
│   └── NIX.md              launchd module for scheduled refresh
├── AGENTS.md               traversal manual: tables, commands, recipes
├── README.md               install / workflow
└── TODO.md                 open work
```

## Data flow

```
upstream feed / git repo
        │  crowbar sync [--bulk]        (datasets.py)
        ▼
data/<group>/…                     raw files, never modified
        │  crowbar build / crowbar update    (indexer.py → loaders.py)
        ▼
index/crowbar.db                        SQLite, schema v4 (row counts below are a full-corpus snapshot; crowbar stats is authoritative)
        │  query.py
        ├── bin/crowbar …               CLI
        └── mcp/server.py          MCP tools
```

`crowbar build` writes `index/crowbar.db.tmp`, then atomically replaces `index/crowbar.db`.
Bulk loaders run whenever their data directory exists, even without `--bulk`;
`--bulk` only affects the download step.

## Tables by domain

### NVD / CVE core

| Table | Rows | Meaning |
|---|---:|---|
| `cve` | 408,816 | one row per CVE (CVSS, EPSS, KEV flag, description, year) |
| `cve_cwe` | ~1.4M | CVE → CWE |
| `cve_product` | ~2.1M | CVE → vendor/product (strings only) |
| `cpe_match` | 2,059,621 | CVE → vendor/product/version ranges (the precise applicability layer) |
| `cve_ref` | ~1.5M | references with tags |
| `cve_exploit` | ~47k | CVE → Exploit-DB id |
| `cve_nuclei` | ~14k | CVE → Nuclei template id |
| `cve_msf` | 1,171 | CVE → Metasploit module path |
| `ssvc` | 200,782 | CISA SSVC decision points (Vulnrichment) |
| `cve_fts` | 408,816 | FTS5 description + product terms |

### Exploit / tooling

| Table | Rows | Meaning |
|---|---:|---|
| `exploit` | 46,698 | Exploit-DB metadata |
| `exploit_fts` | 46,698 | FTS5 description/tags/CVE |
| `exploit_code_fts` | 46,454 | full Exploit-DB source text (snippet search) |
| `shellcode` | ~1.2k | Exploit-DB shellcode archive |
| `nuclei` | 13,866 | templates (id, name, severity, tags, CVE, path) |
| `nuclei_fts` | 13,866 | FTS5 id/name/tags/CVE |
| `msf` | 5,128 | Metasploit modules (name, platform, CVE, description) |
| `attack` | 935 | MITRE ATT&CK enterprise/mobile/ICS |
| `cwe` | 969 | MITRE CWE |
| `capec` | 615 | MITRE CAPEC |
| `toolkit` | 1,011 | GTFOBins / LOLBAS / PayloadsAllTheThings |
| `toolkit_fts` | 1,011 | FTS5 name/description/tags |

### Ecosystem and OS advisories

| Table | Rows | Meaning |
|---|---:|---|
| `advisory` | 367,268 | OSV advisories (npm, PyPI, Go, crates.io, …) |
| `package_range` | 566,653 | OSV affected version ranges |
| `debian` | 266,367 | Debian security tracker (package × release × CVE) |
| `os_advisory` | 38,839 | MSRC Windows + Apple iOS/macOS advisories |

### Models and metadata

| Table | Rows | Meaning |
|---|---:|---|
| `model` | 9,081 | LLM catalog (provider, context, cost, modalities) |
| `model_fts` | 9,081 | FTS5 provider/id/name |
| `kev` | 1,748 | CISA Known Exploited Vulnerabilities |
| `meta` | - | schema version, build timestamps |

## data/ layout

| Path | Size | Source |
|---|---:|---|
| `data/nvd/` | 242 MB | NVD 2.0 JSON feeds, 2002→today + recent/modified |
| `data/epss/` | 2.7 MB | FIRST EPSS CSV |
| `data/kev/` | 1.8 MB | CISA KEV JSON |
| `data/cwe/`, `data/capec/` | 5.7 MB | MITRE XML |
| `data/attack/` | 64 MB | ATT&CK enterprise/mobile/ICS JSON |
| `data/nuclei/` | 97 MB | Nuclei templates git repo |
| `data/exploitdb/` | 363 MB | Exploit-DB metadata + full source |
| `data/metasploit/` | 55 MB | Metasploit framework source (sparse) |
| `data/osv/` | 364 MB | one zip per ecosystem (10) |
| `data/debian/` | 81 MB | Debian security tracker |
| `data/msrc/` | 91 MB | MSRC Security Update Guide API dump |
| `data/apple/` | 49 MB | Apple security releases (index + pages) |
| `data/toolkit/` | 28 MB | GTFOBins, LOLBAS, PayloadsAllTheThings |
| `data/vulnrichment/` | 1.9 GB | CISA Vulnrichment (SSVC + CPE enrichment) |
| `data/models/` | 5.6 MB | LLM model catalog snapshot |

## Which path answers which question

| Question | Command | MCP tool | Tables |
|---|---|---|---|
| Is product X version Y vulnerable? | `crowbar product X --version Y` | `cb_product` | `cpe_match` |
| What is CVE-…? | `crowbar cve CVE-…` | `cb_cve` | `cve` + joins |
| Search descriptions/products | `crowbar search "term"` | `cb_search` | `cve_fts` |
| What is exploited in the wild? | `crowbar kev` | `cb_kev` | `kev` |
| Public exploit code? | `crowbar exploit "term"` / `crowbar code "term"` | `cb_exploit` / `cb_code` | `exploit(_fts)` / `exploit_code_fts` |
| Detection template? | `crowbar nuclei "term"` | `cb_nuclei` | `nuclei` |
| Metasploit module? | `crowbar msf "term"` | `cb_msf` | `msf` |
| Windows / iOS / macOS advisory? | `crowbar os [--platform] [--impact]` | `cb_os` | `os_advisory` |
| npm/PyPI/Go advisory? | `crowbar advisory [--package] [--ecosystem]` | `cb_advisory` | `advisory`, `package_range` |
| Debian package status? | `crowbar debian PACKAGE` | `cb_debian` | `debian` |
| Public PoC repository? | `crowbar poc [q] [--cve] [--top]` | `cb_poc` | `poc`, `poc_orphan` |
| Which source filled the index? | `crowbar sources` | `cb_sources` | `source_state` |
| Living-off-the-land binary? | `crowbar bin BINARY` | `cb_binary` | `toolkit_fts` |
| ATT&CK technique? | `crowbar attack T1059` | `cb_attack` | `attack` |
| Weakness / attack pattern? | `crowbar cwe` / `crowbar capec` | `cb_cwe` / - | `cwe` / `capec` |
| LLM model specs? | `crowbar models` | `cb_models` | `model` |
| Arbitrary read-only SQL | `crowbar sql "SELECT …"` | `cb_sql` | any |
| Schema / dataset map | `crowbar map [--tables]` | `cb_tables` | `catalog.py` |

## Tests and CI

```
python3 -m tests.test_unit     # 90 cases, fixture DB, no corpus
python3 -m tests.test_corpus   # generated cases against index/crowbar.db
python3 scripts/selftest.py    # corpus health, row counts, recovery
python3 scripts/check.py       # schema/catalog/docs/style consistency
pre-commit run --all-files     # compile + check + unit tests + gitleaks
```

`test_corpus.py` samples its own rows (deterministic offsets) and generates one
test per row/term, so a full run exercises every table and every read path.
`test_unit.py` builds a synthetic index with all 30 tables and runs the CLI and
MCP server as subprocesses, which is what CI executes.

## Guardrails

- Never write to `data/` or `index/` by hand; `crowbar sync` / `crowbar build` own them.
- `crowbar sql` and MCP `cb_sql` are read-only (`PRAGMA query_only`).
- Do not add a Python dependency: stdlib only (SQLite FTS5 + urllib).
- A build needs ~2× the index size temporarily; do not interrupt on the USB copy.
- Nix owns scheduling (see `docs/NIX.md`); do not install launchd jobs by hand.
