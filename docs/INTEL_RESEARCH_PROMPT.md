# Prompt: state-of-the-art vulnerability-intelligence source inventory

Use this with a research model that can browse and cite sources. It is scoped to
data acquisition and defensive research; it deliberately excludes exploit
development, targeting, and criminal marketplaces.

---

You are a vulnerability-intelligence data engineer. I maintain a local, offline,
agent-traversable corpus (SQLite + CLI/MCP) for security research. I need a 2026
state-of-the-art inventory of vulnerability data sources and a concrete ingestion
plan.

**Scope and rules**

- Lawful, public, or commercially licensed sources only.
- No criminal markets, private exploit brokers, or instructions for exploiting
  systems.
- Distinguish four things clearly: a CVE record, a vendor advisory, a public PoC,
  and a working exploit.
- If a source needs authentication, scraping, or has redistribution limits, say so
  instead of guessing.
- Cite URLs and access dates. Prefer primary sources over blog summaries.

**Current stack (do not re-recommend what I already have unless I am missing a
better feed or format)**

- NVD 2.0 yearly feeds (CVSS, CPE, CWE, references)
- CISA KEV
- FIRST EPSS
- CISA Vulnrichment / SSVC
- OSV (npm, PyPI, Go, Maven, NuGet, RubyGems, crates.io, Packagist, Debian, Alpine)
- Debian security tracker
- Microsoft MSRC Security Update Guide
- Apple security releases
- Exploit-DB (including source archive), Metasploit modules, Nuclei templates
- CWE, CAPEC, ATT&CK techniques
- CVE List v5, GitHub Advisory Database, Project Zero, ZDI, CISA advisories,
  CERT/CC, Full Disclosure (being added)

**Deliverable 1 - ranked source inventory**

Return a table with one row per source and these columns:

`name | category | URL | what it provides | access method (bulk/API/RSS/scrape) | auth/key | format | typical size | update cadence | historical depth | coverage | license/ToS | free/paid | caveats | priority (P0/P1/P2)`

Cover at least:

- **Core:** CVE.org/cvelistV5, NVD 2.0, CISA KEV, FIRST EPSS, CISA Vulnrichment,
  CWE, CAPEC, ATT&CK (including software, groups, campaigns, mitigations, data
  sources), NVD CPE dictionary, CVE List v5 CNA metadata.
- **Packages:** OSV, GitHub Advisory, RustSec, Go vulnerability DB, PyPA,
  RubySec, Packagist, Maven, NuGet, Alpine secdb, Ubuntu CVE tracker.
- **OS/vendor:** MSRC, Apple, Ubuntu USN/OVAL, Red Hat Security Data API/OVAL,
  SUSE/openSUSE, Alpine, Amazon Linux, Oracle Linux, Rocky/Alma, Android,
  ChromeOS, Cisco, Fortinet, Ivanti, VMware/Broadcom, Citrix, Palo Alto, Juniper,
  SonicWall, F5, Atlassian, Zimbra, SAP, Adobe, Chrome, Firefox.
- **Exploit/PoC/research:** Exploit-DB, Metasploit, Nuclei, Packet Storm,
  GitHub PoC indexes, Sploitus, Vulners, ZDI, Pwn2Own, Project Zero,
  Full Disclosure, HackerOne/Bugcrowd disclosed reports, seclists archives.
- **Detection/threat:** Sigma, YARA, Semgrep, Suricata/ET, CISA ICS advisories,
  CERT/CC, JVN, Shadowserver, GreyNoise, Censys, Shodan.
- **Commercial:** VulnCheck, Flashpoint, Recorded Future, Mandiant, SecurityScorecard,
  Bitsight, and any comparable feeds. Include rough cost tiers if public.

For every source, state:

1. Does it have a stable machine-readable endpoint?
2. Can I mirror it locally and redistribute derived data?
3. Exact download/API endpoint if known.
4. What unique field or coverage it adds over NVD/OSV/KEV.
5. How it handles aliases (GHSA, OSV, ZDI, EDB, MSRC, KB, purl, CPE).

**Deliverable 2 - gap analysis**

Rank the top 10 gaps in my current stack by impact on answering:

- "What is exploited in the wild right now?"
- "What is internet-facing and remotely exploitable?"
- "Am I affected, by exact product and version?"
- "Is there a public PoC or exploit?"
- "What changed since yesterday?"

**Deliverable 3 - canonical ingestion schema**

Propose tables and keys for:

- identifiers and aliases (`cve`, `ghsa`, `osv`, `zdi`, `edb`, `msrc`, `kb`, `purl`)
- product identity (CPE, CPE match, vendor/product aliases)
- affected version ranges (introduced/fixed/last_affected, ecosystem semantics)
- advisory/source provenance and timestamps
- severity normalization (CVSS v2/v3/v4, vendor severity, SSVC)
- exploit/PoC status and confidence
- deduplication and merge rules
- full-text search fields

Include a short DDL sketch and a JSON example for one CVE and one package advisory.

**Deliverable 4 - update strategy**

- Full vs incremental fetch per source
- Change detection (ETag, Last-Modified, checksum, cursor, release tag)
- Rate limits, retries, backoff, partial-failure handling
- How to detect stale or silently broken sources
- How to keep a removable-drive mirror consistent (atomic swap, journal)

**Deliverable 5 - plan and exclusions**

- 30/60/90-day implementation plan, highest-value source first
- A "do not ingest" list with reasons (legal, quality, duplication, volatility)
- A short list of questions I should answer before adding paid feeds

Return the result as Markdown, plus a CSV-ready header row for the source table.
Cite every URL with an access date.
