# TODO - crowbar audit backlog

Snapshot: 2026-10-20 audit, P0 merge applied 2026-10-21. Index: 412,295 CVEs ·
2,059,621 CPE ranges · 412,412 CNA records · 26,324 public PoCs · 2.7 GB.
Corpus tests: 1,200 passing; fixture tests: 108; v3 adapter tests: 17;
selftest: 40/40.
Ordered by impact. Check items off as they land; move fixed items to “Done”.
Execution order and schema details: `docs/PLAN.md`.
Downloaded raw intel: `docs/INTEL.md`.

---

## Done (2026-10-21)

- [x] **CVE List v5 adapter** (`crowbar/intel.py`). 412,412 CNA records in
      `cve_cna` / `cve_cna_ref` / `cve_cna_product`; +3,479 CVEs NVD never
      carried. NVD description/CVSS/severity/status never overwritten.
- [x] **PoC-in-GitHub adapter.** 26,324 repos (metadata only, never executed);
      434 orphans in `poc_orphan`; `cve_meta.has_poc` / `poc_count`.
- [x] **Row-level provenance.** `source_state` records url/license/sha256/
      loaded_at/record_count per source; `crowbar sources` + `cb_sources`.
- [x] **Deprecated-CWE stubs.** Referenced-but-absent weakness IDs get a
      Deprecated stub instead of dangling.
- [x] **Adapter/idempotency tests.** `tests/test_v3.py`, 17 cases: parsing,
      non-clobber, idempotency, provenance, orphan policy, no-code-execution.
- [x] **Duplicate rows.** Unique indexes on `cve_cwe` / `cve_product` /
      `cpe_match` / `cve_ref`; CPE dedupe during migration.
- [x] **`cve.year` split.** `cve_meta.published_year` vs `cve_meta.cve_year`
      (84,672 rows differ).

## P0 - correctness and integrity

- [ ] **Apple `exploited` parsing.** Apple has 8,139 rows but 0 `exploited`;
      MSRC has 197. Parse Apple's "actively exploited" advisory text.
- [ ] **Orphan-link policy.** `poc_orphan` holds 434 PoC CVEs absent from the
      index (CVE-List rejects + pre-2002 IDs). Decide: create stub `cve` rows
      or keep them out of the CVE table.
- [ ] **MSRC metadata not stored.** Raw SUG has `baseScore`, `temporalScore`,
      `vectorString`, `publiclyDisclosed`, `cweList`, `customerActionRequired`,
      `latestSoftwareRelease`, `articles`. Add columns/tables; expose
      “publicly disclosed”, CVSS, CWE and KB/patch info in `crowbar os`.
- [ ] **MSRC blanks are legitimate but unexplained.** 20,311 rows have no
      severity and 16,901 no impact (mostly Mariner + Edge). Decide: backfill
      from the matching `cve` row (NVD severity/CVSS) or label `"Not rated"`.
- [ ] **Manifest coverage is incomplete.** `index/manifest.json` tracks 41 of 58
      registered datasets. Missing: `nuclei`, `metasploit`, `msf-source`,
      `gtfobins`, `lolbas`, `payloads`, `vulnrichment`, all 10 `osv-*`,
      `exploitdb-full`, `debian-tracker`. Two stale keys (`metasploit-index`,
      `nuclei-templates`) remain. `crowbar verify` therefore hashes only part of the
      3.3 GB corpus. Make `sync`/custom handlers record every dataset; fail
      `check.py` when registry ≠ manifest; add `crowbar verify --datasets`.
- [ ] **`crowbar verify` passes with a 0-byte DB** because it trusts the manifest.
      Always `PRAGMA quick_check` + require `schema == SCHEMA_VERSION`.
- [ ] **Debian tracker only has 4 releases** (`sid`, `bookworm`, `trixie`,
      `forky`). Add `bullseye` (11) and `buster` (10); verify why the tracker
      JSON dropped them. Add `--release` filter.
- [ ] **Apple platform lumping.** `os_advisory.platform` has `apple` for 2,347
      rows that are really Safari/watchOS/tvOS/visionOS/Xcode. Split by title;
      keep a release row even when no CVE is extracted (currently 1 such row,
      many releases share CVEs).
- [ ] **OSV severity is unnormalized.** 271,578 of 367,268 advisories have an
      empty `severity`; the rest store a raw CVSS vector. Compute score + band
      (CRITICAL/HIGH/MEDIUM/LOW), keep the vector, and fall back to
      `database_specific.severity` / ecosystem severity when CVSS is absent.
- [ ] **No alias index.** 321,382 OSV advisories have no CVE; `aliases` is a
      comma string. `crowbar search GHSA-…` only works by accident when the CVE
      description mentions it. Add `alias(alias, cve, source)` with an index,
      populate from OSV aliases/CVE fields, Exploit-DB codes, Nuclei CVE ids,
      MSRC ids; add `crowbar alias <id>` and MCP `cb_alias`. (Partially done:
      `cve_alias` exists with 27,113 OSV rows; still no Exploit-DB / Nuclei /
      MSRC aliases and no `crowbar alias` command.)
- [ ] **NVD completeness gaps.** 88,693 CVEs (21.7%) have no `cpe_match`;
      79,417 no CWE; 18,498 no EPSS; 18,493 rejected CVEs are indexed as normal
      rows. Add a `rejected` view/filter (default exclude in search), and
      decide whether to derive CPEs from CVE references/CNA data.
- [ ] **CPE string matching still leaks.** `crowbar product` uses `LIKE` on
      vendor/product; add vendor aliases (e.g. `microsoft` vs `ms`, `apache`
      vs `apache_software_foundation`) or an FTS index over `cpe_match`.
- [ ] **`cve_msf` is only 1,171 links from 5,128 modules (939 with CVEs).**
      Metasploit modules can list multiple CVEs; verify the extractor handles
      `references` arrays, `CVE` constants and auxiliary modules.
- [ ] **Exploit-DB `verified` is always 1/0 but 14,363 rows have no CVE.**
      Keep, but expose “no CVE” in `crowbar exploit`; add language/type filters.

## P1 - missing data sources (biggest coverage gaps)

### OS / distro advisories

Only Windows (MSRC), iOS/macOS (Apple), Debian, Alpine and Debian/Ubuntu via OSV
are covered. Missing:

- [ ] Ubuntu Security Notices + Ubuntu CVE tracker (git) + USN OVAL.
- [ ] Red Hat Security Data API + OVAL (RHEL/CentOS Stream).
- [ ] SUSE / openSUSE security announcements + OVAL.
- [ ] Amazon Linux security advisories (ALAS).
- [ ] Oracle Linux errata.
- [ ] Rocky Linux / AlmaLinux errata (mostly RHEL clones).
- [ ] Alpine secdb (OSV has partial coverage; add native secdb).
- [ ] Android Security Bulletin (monthly, CVE + component).
- [ ] ChromeOS release notes / CVE list.
- [ ] FreeBSD / OpenBSD / NetBSD security advisories.
- [ ] Windows KB / patch mapping (MSRC `articles`/`latestSoftwareRelease`) and
      affected build ranges, not just release month.

### Network / enterprise appliances

High-value for real intrusions; none indexed today:

- [ ] Cisco advisory API (IOS/NX-OS/ASA/FMC/AnyConnect).
- [ ] Fortinet PSIRT.
- [ ] Ivanti (Connect Secure, Policy Secure, Neurons).
- [ ] VMware/Broadcom VMSA (vCenter, ESXi, Workspace ONE).
- [ ] Citrix (NetScaler/ADC, Gateway).
- [ ] Palo Alto Networks security advisories.
- [ ] Juniper SIRT.
- [ ] SonicWall PSIRT.
- [ ] F5 BIG-IP security advisories.
- [ ] Zimbra, Atlassian, SAP, Oracle Critical Patch Update, Adobe.
- [ ] CISA ICS advisories (separate from ATT&CK ICS) + CERT/CC VU + JVN.

### Cloud / container / supply chain

- [ ] Kubernetes CVEs / K8s security releases (some are in NVD, not grouped).
- [ ] AWS / Azure / GCP security bulletins.
- [ ] Container base-image advisories (Chainguard, Wolfi, Distroless).
- [ ] GitHub Actions advisories (GHSA ecosystem `actions`).
- [ ] SBOM/package-lock scanning (`crowbar scan`): map npm/PyPI/Go/Maven lockfiles
      to OSV ranges and output affected packages.
- [ ] OSV ecosystems not downloaded: `Ubuntu`, `Red Hat`, `SUSE`, `openSUSE`,
      `Alpine` (native), `Android`, `CRAN`, `Bioconductor`, `ConanCenter`,
      `vcpkg`, `GitHub Actions`, `Hackage`, `Hex` (only 2 rows today).

### Exploit / PoC / detection

- [ ] Packet Storm, CXSecurity, 0day.today (metadata only).
- [ ] GitHub PoC index (search API or curated `nomi-sec/PoC-in-GitHub`).
- [ ] Sigma rules (converted to ATT&CK technique mapping).
- [ ] YARA rules (signature metadata).
- [ ] Semgrep registry rules.
- [ ] Suricata/ET rules (CVE → SID).
- [ ] Nuclei is covered; add template `verified`/`tags` filters and workflow
      relationships.

### ATT&CK depth

- [ ] Only 935 techniques are indexed (enterprise 706, ICS 104, mobile 125).
      Add `software` (S####), `groups` (G####), `campaigns` (C####),
      `mitigations` (M####), `data sources` and relationship edges
      (group uses software, software uses technique).
- [ ] Add CWE ↔ CAPEC relationships and CVE → CAPEC where available.

### Identity / CPE / aliases

- [ ] Official NVD CPE dictionary (canonical vendor/product names) - currently
      derived from NVD configurations only.
- [ ] MITRE CVE List v5 (`cve.org`) for CNA metadata, affected products and
      references not in NVD.
- [ ] CISA Vulnrichment is indexed for SSVC; add its CPE/KEV enrichments too.

## P2 - schema and index

- [ ] `alias(alias TEXT, cve TEXT, source TEXT)` + indexes; used by search,
      `get_cve`, `crowbar alias`, advisories.
- [ ] `advisory_severity(advisory_id, score, band, vector)` or normalized
      columns on `advisory`; filter `crowbar advisory --severity high`.
- [ ] Advisory FTS (`advisory_fts`: summary, package, aliases) so
      `crowbar advisory log4j` searches text, not only package names.
- [ ] `os_advisory`: add `kb`, `cvss`, `vector`, `cwe`, `publicly_disclosed`,
      `customer_action`, `product_tree`; unique key should include KB/edition.
- [ ] `debian_release` / `debian_source` tables so `release` is not a bare
      string and old releases can be filtered.
- [ ] `attack_software`, `attack_group`, `attack_relationship` tables.
- [ ] `exploit_code(path, language, size, sha256)` metadata table; link to
      `exploit.id`.
- [ ] `model` is fine; add `model_price_history` only if a source exists.
- [ ] `meta` should record per-dataset row counts + build duration for
      observability; `index/stats.json` already has some.
- [ ] Consider FTS over `cwe`/`capec` descriptions (currently LIKE).
- [ ] Partial indexes for `cve(status != 'Rejected')`, `cve(kev=1)`,
      `cve(has_exploit=1)` if query plans regress.

## P3 - CLI / MCP features

- [ ] `crowbar alias <GHSA|PYSEC|EDB|MSRC|CVE>` - resolve across sources.
- [ ] `crowbar search --all` - unified ranked search over CVE, OSV, Exploit-DB,
      Nuclei, toolkit and exploit code (with `--source` filter).
- [ ] `crowbar advisory --cve`, `--severity`, `--fixed`, `--introduced` filters.
- [ ] `crowbar os --product`, `--severity`, `--exploited`, `--kb`, `--since`;
      join `cve` for missing severity/CVSS/EPSS.
- [ ] `crowbar debian --release`, `--cve`, `--status`.
- [ ] `crowbar exploit --language`, `--type`, `--verified-only`, `--no-cve`.
- [ ] `crowbar scan <lockfile|sbom>` - OSV range matching for npm/PyPI/Go/Maven.
- [ ] `crowbar export --format jsonl|csv --query …` for pipelines.
- [ ] `crowbar diff --since <date>` / `crowbar new` - what changed since a timestamp.
- [ ] `crowbar watchlist add/remove/check` - persistent CVE/product watchlist.
- [ ] `crowbar map --json|--mermaid` (already has `--tables`); expose dataset
      freshness + row counts in `crowbar map`.
- [ ] MCP: add resources (dataset map, saved queries), prompts, and tools
      `cb_alias`, `cb_scan`, `cb_diff`; keep tools list in sync with selftest.
- [ ] `crowbar verify --datasets` (hash every registered dataset, fail on missing
      manifest entries).

## P4 - operations / portability

- [ ] `crowbar setup-drive`: atomic DB copy (`tmp` + `os.replace`), `--no-data`
      semantics, prune stale files, and a `--verify` post-check. Refresh
      `manifest/state/stats` always (done) and record what was copied.
- [ ] `crowbar mirror <path> --if-mounted` for the local-index + drive-snapshot model.
- [ ] Nix scheduling: add `launchd.agents.crowbar` (snippet in `docs/NIX.md`),
      remove `install-agent`/`uninstall-agent`, decide TCC strategy (local index
      recommended).
- [ ] `crowbar update` should be crash-safe on removable media: write journal-aware
      checkpoint, warn on `EPERM`/removal, and refuse to run if free space < 2×.
- [ ] Eject flow: `crowbar eject <mount>` - checkpoint WAL, close, `diskutil eject`,
      verify unmount; never eject mid-build.
- [ ] Incremental bulk indexing: manifests of `(path, mtime, size)` for OSV
      zips, Exploit-DB sources, Nuclei and toolkit to avoid full re-parses.
- [ ] Build progress/ETA per loader; `--jobs` for Apple page fetch/OSV parse.
- [ ] Disk budget guard: warn before `sync --bulk` if projected data + 2× index
      exceeds free space (currently ~5 GB corpus + 3.4 GB temp).

## P5 - tests / CI / quality

- [ ] Corpus regression tests for the MSRC `exploited` fix (only Yes), severity
      and impact mappings, and `publiclyDisclosed`.
- [ ] `tests/test_manifest.py`: registry ↔ manifest coverage; every dataset
      has a loader and a destination; no stale manifest keys.
- [ ] `tests/test_setup_drive.py`: copy to a temp dir, interrupt simulation,
      verify atomic DB replacement and metadata refresh.
- [ ] Fixture index published as a CI artifact (or built in CI) so corpus tests
      run on GitHub, not only locally.
- [ ] Add Python 3.14 to the CI matrix once FTS5 wheels are confirmed.
- [ ] `scripts/bench.py`: query latency budget (`search`, `product`, `cve`,
      `code`, `advisory`) on the full corpus; fail on >2× regression.
- [ ] Fuzz the CPE comparator (`vkey`, `version_affected`) with random strings
      and real CPE versions (`1.2.3p1`, `2:1.2`, `~rc1`, `*`).
- [ ] `gitleaks dir` on source dirs in pre-commit (currently `git --staged`
      only); add a full-history scan before the first public push.
- [ ] Golden-output tests for CLI text mode (width, truncation, colors off).

## P6 - research / nice to have

- [ ] EPSS history + trend (`epss_history(cve, date, score)`); “rising” filter.
- [ ] KEV history (added/removed) and ransomware-only view.
- [ ] Prioritization score combining KEV, EPSS, exploit/nuclei/MSF, CVSS,
      exposure and OS applicability.
- [ ] CWE/CAPEC/ATT&CK graph export (DOT/JSON) for agent reasoning.
- [ ] Vendor-normalized CPE mapping (canonical names + aliases).
- [ ] Advisory → patch command extraction (`apt`, `npm`, `pip`, `go get`).
- [ ] `crowbar explain CVE-…` - one-paragraph, evidence-linked triage summary.
- [ ] Local embeddings / semantic search (optional; keep stdlib core).

## Tooling / prior art (evaluate, don't duplicate)

- [ ] **trickest/cve** - check license, repo size, freshness; import only PoC
      URLs not already in `poc-in-github`/Exploit-DB/Nuclei/MSF.
- [ ] **pocindex / 0xMarcio-style indexes** - same dedupe rule; add a
      `poc.source` value only for genuinely unique links.
- [ ] **cve-search/cve-search** - feature-parity checklist (query API, FTS
      ranking, history); do not adopt Redis/Mongo or replace SQLite.
- [ ] **flawz** - reference TUI/UX only; no runtime dependency.
- [ ] **open-vulnerability-cli (vulnz)** - borrow delta/cache ideas for NVD/GHSA;
      no runtime dependency.
- [ ] **vulnerability-intelligence-mcp / cve-mcp-server** - compare MCP tool
      names/schemas for interoperability; keep our MCP native to the index.
- [ ] Positioning check: one query must answer *affected? exploited? PoC?
      fixed?* offline, with provenance - that is the differentiator versus
      cve-search + separate EPSS/KEV/PoC scripts.
- [ ] Competitive scan: closest pure-OSS stack is **cve-search + a PoC layer
      (trickest / PoC-in-GitHub / pocindex-style) + separate EPSS/KEV scripts**.
      Very few ship full CVE List v5 + GHSA + ZDI/Project Zero + OS advisories +
      exploits + prioritization + offline + MCP in one package. Track gaps in
      `docs/PLAN.md`; do not adopt Redis/Mongo or a hosted API.

---

## Done recently (do not redo)

- [x] Bulk loaders: OSV (10 ecosystems), Debian, MSRC, Apple, Exploit-DB source,
      Metasploit source, GTFOBins/LOLBAS/Payloads.
- [x] Schema v2: `advisory`, `package_range`, `debian`, `os_advisory`,
      `toolkit`, `exploit_code_fts`, `ssvc`; `msf` widened.
- [x] `crowbar os|advisory|code|bin|debian|map` + MCP `cb_os|cb_advisory|cb_code|
      cb_binary|cb_debian|cb_tables`.
- [x] 1,200 corpus tests + 90 fixture tests + 34 selftest checks.
- [x] Pre-commit hooks and GitHub Actions workflow (3.11–3.13).
- [x] `docs/MAP.md`, dataset docs, README/TODO refresh.
- [x] MSRC `exploited` truthiness bug fixed (197 true positives).
- [x] `setup-drive` refreshes existing data (rsync) and metadata files.
- [x] Drive corpus rebuilt and verified (re-copy DB after the interrupted
      `setup-drive`; see P0 atomic-copy item).
