# AGENTS.md - crowbar traversal manual

Offline vulnerability intelligence at the repo root (or `.crowbar/` in a linked
project). One SQLite+FTS5 database, one CLI, one MCP server.

**Three ways in, in order of preference:**

1. MCP tools (`cb_*`) when the server is connected.
2. `bin/crowbar <cmd> --json` - stable JSON, no parsing needed.
3. Read-only SQL on `index/crowbar.db` via `crowbar sql` (never write).

Never answer CVE facts from memory. If a fact is not in the DB, say so.

## Product and authority

crowbar is a local, read-only vulnerability-intelligence index with shared
CLI and MCP workflows. It grounds answers in indexed upstream data - it is not
a scanner and not authorization. Only test systems the user owns or may test.
Rank threat by **KEV / SSVC active > EPSS > CVSS**, never CVSS alone. KEV and
SSVC describe exploitation observed elsewhere; EPSS is a model estimate; a
missing row is not proof of "not affected".

## Performance (agent tokens first)

Return the smallest sufficient answer. `cb_cve` caps the large per-CVE arrays
(`affects`, `references`, `products`, `exploits`) at 50 rows each and reports an
`affects_total` / `references_total` / `products_total` count; use `crowbar sql` or
the CLI for the full list. Any tool response over the hard ceiling comes back as
a valid-JSON `result_too_large` notice, never a sliced payload - so narrow the
query or lower `limit` rather than parsing a truncated blob.

Contributing to the repo itself: see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 0. Orient (do this first, every session)

```bash
.crowbar/bin/crowbar doctor          # built? schema? stale?  (exit 1 = needs work)
.crowbar/bin/crowbar stats --json    # row counts + freshness
.crowbar/bin/crowbar map             # dataset -> path -> tables -> command
.crowbar/bin/crowbar map --tables    # what every table means
.crowbar/bin/crowbar where --json    # absolute paths
```

If the index is missing: `crowbar sync && crowbar build` (minutes - tell the user).
`crowbar update` is the cheap refresh (≈10 s). `crowbar update --deep` reindexes the
intel tables.

Freshness: the CLI and the MCP server start a background `crowbar update` once
the index is a day old (at most hourly; `CROWBAR_NO_AUTO_UPDATE=1` turns it off,
log in `index/update.log`). `cb_stats` → `index.age_days` / `index.stale`; stale
means older than NVD's 8-day change window, so say recent CVEs may be missing.
`index.last_error` says why the last refresh failed; a failed NVD download leaves
the age untouched. `cb_stats` → `data_as_of` gives the newest CVE/KEV/PoC/mention
timestamps. The MCP server re-checks every 10 minutes and appends a note to tool
results while the index is stale.
An installed package keeps its index in `~/.crowbar` (`CROWBAR_HOME` overrides).

---

## 1. Repo map

```
crowbar/
├── bin/crowbar                  CLI shim (works through symlinks)
├── mcp/server.py           MCP stdio shim -> crowbar.mcp
├── crowbar/
│   ├── paths.py            root resolution, YEARS, SCHEMA_VERSION
│   ├── datasets.py         registry + downloader + manifest/freshness
│   ├── indexer.py          schema, NVD/KEV/intel loaders, build(), update()
│   ├── chatter.py          CVE mentions: HN, mailing lists, ZDI, Mastodon, EUVD
│   ├── loaders.py          bulk loaders: OSV, Debian, MSRC, Apple, toolkit,
│   │                       Exploit-DB source code, Metasploit sources
│   ├── catalog.py          static dataset -> table -> command map (crowbar map)
│   ├── query.py            read layer; every function returns dicts
│   ├── cli.py              terminal commands (single source of truth)
│   └── mcp.py              MCP tool definitions (calls query.py directly)
├── scripts/
│   ├── selftest.py         end-to-end corpus checks
│   ├── check.py            static checks (schema/catalog/docs/style)
│   └── make_fixture.py     tiny synthetic index for CI
├── tests/
│   ├── test_unit.py        131 fixture tests (CI, no corpus needed)
│   └── test_corpus.py      generated tests against index/crowbar.db
├── docs/
│   ├── DATASETS.md         per-source license, shape, caveats
│   ├── MAP.md              full tree + data flow
│   └── NIX.md              scheduling via home-manager (no launchctl)
├── data/                   raw upstream corpora (git-ignored, ~3.3 GB)
├── index/
│   ├── crowbar.db               the index (query this)
│   ├── manifest.json       url/bytes/sha256/fetched_at per dataset
│   ├── state.json          schema, built_at, updated_at
│   └── stats.json          last build/update summary
├── AGENTS.md               this file
├── README.md               user docs
├── TODO.md                 known gaps
└── Makefile                sync / build / update / test / doctor
```

Raw data is grouped by source; `crowbar map` is authoritative for the mapping:

```
data/nvd/          NVD year + recent/modified feeds (gzip)
data/kev/          CISA KEV
data/epss/         EPSS scores
data/cwe/ capec/   MITRE taxonomies
data/attack/       ATT&CK enterprise/mobile/ics
data/vulnrichment/ CISA SSVC (per-CVE JSON)
data/exploitdb/    index CSVs + full/ source tree
data/nuclei/       template YAML
data/metasploit/   tree.json + source/modules/
data/osv/          per-ecosystem advisory zips
data/debian/       tracker.json
data/msrc/         Microsoft Security Update Guide (sug.json)
data/apple/        security release index + advisory pages
data/toolkit/      gtfobins, lolbas, payloads
data/models/       models.dev catalog
data/chatter/      append-only JSONL archives of posts naming a CVE
```

---

## 2. Tables

```sql
-- core
cve(id PK, published, modified, status, description,
    cvss, cvss_version, cvss_vector, severity,
    kev INT, epss REAL, epss_pct REAL,
    has_exploit INT, has_nuclei INT, has_msf INT, year INT)
cve_cwe(cve_id, cwe)
cve_product(cve_id, vendor, product)
cpe_match(cve_id, part, vendor, product, version,
          v_start_incl, v_start_excl, v_end_incl, v_end_excl)
cve_ref(cve_id, url, tags)
cve_exploit(cve_id, exploit_id)
cve_nuclei(cve_id, template_id)
cve_msf(cve_id, module_path)

-- intel
kev(cve PK, vendor, product, name, date_added, ransomware, action, due, notes,
    epss, epss_pct)   -- EPSS on every KEV row, even CVEs outside the tier's NVD years
exploit(id PK, file, description, date, author, type, platform,
        verified, codes, tags, url, raw)
shellcode(id PK, file, description, date, platform, url)
nuclei(id PK, name, severity, tags, cve, path, description, domain)
msf(path PK, type, name, platform, privileged, disclosure_date,
    description, cves)
attack(id, domain, name, tactics, platforms, description, url)  -- PK(id,domain)
cwe(id PK, name, abstraction, status, description)
capec(id PK, name, severity, likelihood, cwe, description)
model(provider, provider_name, id, name, context, output_limit,
      input_cost, output_cost, released, reasoning, tool_call, vision)
ssvc(cve_id PK, exploitation, automatable, technical_impact, timestamp, source)
mention(source, cve_id, url, title, posted_at, score)  -- hn, oss-security,
        -- fulldisclosure, zdi, mastodon, euvd-exploited; titles/links only

-- bulk / ecosystem / vendor
advisory(source, id, ecosystem, package, cve, summary, severity,
         published, modified, url, aliases, affected_count)
package_range(advisory_id, ecosystem, package, introduced, fixed,
              last_affected, versions)
debian(package, release, cve, status, fixed, urgency, description)
os_advisory(source, cve, platform, product, version, title, severity,
            impact, exploited, released, url)
toolkit(source, name, path, description, tags)

-- full-text
cve_fts(id, description, products)
exploit_fts(id, description, tags, codes)
nuclei_fts(id, name, tags, cve)
model_fts(provider, id, name)
exploit_code_fts(exploit_id, path, content)   -- Exploit-DB source code
toolkit_fts(source, name, description, tags)

-- schema v3: CNA + public PoC + provenance
cve_cna(cve_id PK, assigner, state, published, updated, title, description,
        cvss, cvss_version, cvss_vector, severity, record_path, source,
        source_url, source_sha256, fetched_at)
cve_cna_ref(cve_id, url, tags)            -- CNA references, kept apart from NVD
cve_cna_product(cve_id, vendor, product)  -- CNA affected products
cve_meta(cve_id PK, published_year, cve_year, has_poc, poc_count)
poc(source, cve_id, repo, url, repo_id, stars, language,
    created_at, pushed_at, description, fetched_at)
poc_orphan(cve_id PK, count)   -- PoCs for CVEs the index does not carry
cve_alias(cve_id, alias, source)
source_state(source PK, url, path, license, sha256, fetched_at, loaded_at,
             record_count, status, note)

meta(key, value)
```

`cve_cna` holds the **CNA-authored** record (CVE List v5) beside the NVD row;
it never replaces `cve.description` or `cve.cvss`. `cve_meta.published_year` is
the publication year, `cve_meta.cve_year` the year in the CVE ID - they differ
for ~85k records. `poc` holds repository metadata only; no PoC is ever cloned
or executed.

`os_advisory.platform` is `windows` (MSRC) or `ios` / `macos` / `apple`
(Apple). `impact` is normalized: `RCE`, `EoP`, `DoS`, `InfoDisclosure`,
`Spoofing`, `Bypass`, `Tampering`.

---

## 3. Which path answers which question

| question | use | not this |
|---|---|---|
| is product X version Y affected? | `crowbar product X --version Y` (`cpe_match`) | `crowbar search --product` |
| what does CVE-X mean? | `crowbar cve CVE-X` | search |
| CVE in an npm/PyPI/Go package | `crowbar advisory --package pkg` or `crowbar cve` → `advisories` | CVE search |
| Windows / iOS / macOS advisory | `crowbar os` (`--platform`, `--impact RCE`) | vendor CVE title grep |
| Debian fixed version | `crowbar debian pkg` | NVD |
| public PoC repository for a CVE | `crowbar poc --cve CVE-X` | `crowbar cve` → `pocs` |
| CNA-authored description / refs | `crowbar cve CVE-X` → `cna` | NVD description |
| which source filled a table | `crowbar sources` | - |
| PoC code, not just a title | `crowbar code "<snippet>"` | `crowbar exploit` |
| living-off-the-land binary | `crowbar bin <name>` | ATT&CK |
| technique for an actor/behavior | `crowbar attack <q>` | CWE |
| weakness class | `crowbar cwe <n>` / `crowbar capec <q>` | CVE |
| model pricing/context | `crowbar models` | - |
| what's being discussed / exploited now | `crowbar trending` (`cb_trending`) | search |
| what changed since a date | `crowbar new --since D` (`cb_new`) | `--since` on search |
| how fast is this index | `crowbar bench` | - |

---

## 4. Recipes

### Triage one CVE

```bash
.crowbar/bin/crowbar cve CVE-2021-44228 --json | jq \
  '{id,severity,cvss,epss,kev,cwe,ssvc,
    exploits:(.exploits|length), nuclei:(.nuclei|length),
    os:.os, advisories:.advisories, ranges:[.affects[].label]}'
```

Interpretation order:

1. `kev == 1` → confirmed exploitation somewhere in the wild.
2. `ssvc.exploitation` → `active` / `poc` / `none`.
3. `epss` (30-day probability) and `epss_pct`.
4. `cvss` / `severity` → impact if triggered.
5. `exploits` / `nuclei` / `metasploit` → working or near-working PoC.
6. `os` / `advisories` / `debian` → vendor and distro applicability.
7. `cwe` / `capec` → bug class → mitigations and detection.

Never present CVSS alone as "risk". KEV ≫ SSVC ≫ EPSS ≫ CVSS.

### "We run <product> <version> - what's exploitable?"

```bash
crowbar product nginx --version 1.18.0 --json
```

Tests every `cpe_match` row against the version (exact or start/end bounds) and
returns only real hits plus the matched range. Rank by `kev`, `epss`,
`has_exploit`. NVD CPE data is incomplete for some vendors (notably Apple);
cross-check `crowbar os`.

### Ecosystem package

```bash
crowbar advisory --package lodash --ecosystem npm --json
crowbar advisory "prototype pollution" --limit 20
```

Each result carries `ranges[]` with `introduced` / `fixed` / `last_affected`.
`crowbar cve` also lists advisory ids and Debian fixed versions.

### Windows / iOS / macOS

```bash
crowbar os --platform windows --impact RCE --since 2025-01-01
crowbar os "Windows 11" --json
crowbar os --platform ios
crowbar os --platform macos --limit 100
```

MSRC rows carry `severity` and normalized `impact`; Apple rows carry the
product/version title and the CVEs extracted from each advisory page.

### PoC / exploit code

```bash
crowbar exploit "log4j jndi" --json     # Exploit-DB index
crowbar exploit 50592                   # download source, prints local path
crowbar code "jndi lookup ldap"         # search inside the sources, returns snippet
crowbar nuclei "cve-2021-44228" --json  # template path
crowbar msf ms17 --json
```

Nuclei YAML is at `data/nuclei/templates/<path>`; Exploit-DB sources at
`data/exploitdb/full/<path>`. Neither is executed.

### Search

```bash
crowbar search "remote code execution" --limit 50 --json
```

AND over FTS5 tokens (prefix ≥4 chars), falling back to the longest term.
Filters: `--kev --exploit --epss N --cvss N --severity A,B --year Y --since DATE
--cwe CWE-N --product P --vendor V --ssvc active`.

Ranking: `10·normalized_bm25 + 4·KEV + 5·EPSS + 1.5·min(exploits,3)`.
`--sort newest|cvss|epss` overrides.

### SQL escape hatch

```bash
crowbar sql "select cve, vendor, product, name, date_added from kev
        where date_added >= date('now','-90 day') order by date_added desc" --json

crowbar sql "select c.id, c.epss, c.cvss from cve c
        where c.epss > 0.5 and c.kev = 0 and c.has_exploit = 1
        order by c.epss desc limit 50" --json

crowbar sql "select advisory_id, ecosystem, package, fixed from package_range
        where package='log4j-core'" --json

crowbar sql "select cve, product, version, impact from os_advisory
        where platform='windows' and impact='RCE'
        and released >= '2026-01-01' order by released desc" --json
```

`crowbar sql` is `PRAGMA query_only=ON`: no writes, no DDL.

### ATT&CK / CWE / CAPEC / models

```bash
crowbar attack T1059 --json
crowbar attack "credential dumping" --domain enterprise --json
crowbar attack plc --domain ics --json
crowbar cwe 79
crowbar capec 66
crowbar models --json | jq '[.[]|{provider,id,context,input_cost}]|sort_by(.input_cost)[:10]'
```

---

## 5. Project linking

```bash
crowbar link /path/to/project     # .crowbar -> corpus, .opencode/skills/crowbar -> skill
crowbar unlink /path/to/project
```

Inside a linked project use `.crowbar/bin/crowbar`. Unlinking removes only the
symlinks. The MCP server works in every project whether or not it is linked.

---

## 6. Guardrails

- **Authorization first.** Only test hosts you own or are permitted to test.
- Exploits are untrusted code. Run in a disposable VM/container.
  `crowbar exploit <id>` downloads source; it never executes it.
- KEV/SSVC describe observed exploitation elsewhere, not your host.
- EPSS is model output, not a verdict.
- `cpe_match` keeps NVD's `vulnerable=true` rows; wildcard vendors/products are
  dropped. If a CVE has no CPE data, read the raw NVD JSON.
- OSV/Apple/MSRC coverage is advisory-driven, not exhaustive. Absence of a row
  is not proof of "not affected".

---

## 7. Maintenance

```bash
crowbar sync                 # fetch changed datasets (sha256 + HTTP 304)
crowbar sync --bulk          # + OSV zips, Debian tracker, full Exploit-DB, toolkit
crowbar build                # full rebuild, atomic swap (heavy with bulk data)
crowbar update               # in-place incremental (~10 s)
crowbar update --deep        # + Nuclei / MSF / ATT&CK / vendor + toolkit tables
crowbar verify               # SQLite integrity + sha256 of every dataset
crowbar pack <dir>           # package synced data as a mirror (CROWBAR_MIRROR=<url>)
crowbar stats                # coverage + freshness
python3 scripts/selftest.py    # corpus health checks
python3 scripts/check.py       # schema/catalog/docs/style consistency
python3 -m tests.test_unit     # 131 fixture tests (also runs in CI)
python3 -m tests.test_corpus   # generated corpus tests
pre-commit run --all-files     # check + unit + corpus + gitleaks
```

CI (`.github/workflows/`): `ci.yml` runs lint (ruff, shellcheck, actionlint),
check + fixture tests on Linux/macOS × Python 3.11–3.14, wheel/sdist/uvx/nix/docker
installs through `scripts/smoke.py`, npm pack contents, and plugin/skill/MCP
manifest validation. `upstream.yml` builds a real lite index nightly, checks what
lite promises, and runs the auto-update end to end. Plus CodeQL, scorecard, PR title,
dependency review and link checks.

Build needs ~2× the DB size in free space (writes `crowbar.db.tmp`, then swaps).
Do not kill an update mid-write on removable media; `crowbar verify` repairs a hot
journal.
