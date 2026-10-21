# Intel staging (`data/intel/`)

Raw, free vulnerability-intelligence downloads live here before they are
normalized into the SQLite corpus. `data/` is gitignored; the fetcher and this
document are tracked.

```bash
python scripts/fetch_intel.py --list
python scripts/fetch_intel.py
python scripts/fetch_intel.py --only cveorg-cvelist,project-zero
python scripts/fetch_intel.py --force
```

Every download is resumable and recorded in `data/intel/manifest.json` with URL,
size, SHA-256, and fetch timestamp. Current staging: **22 sources, ~354 MB**.

Archive contents verified by `tar -tzf`:

| Archive | JSON records | Notes |
|---|---:|---|
| CVE List v5 | 410,579 | includes reserved/rejected; not the same count as NVD |
| GHSA | 391,434 | 36,910 reviewed + 354,524 unreviewed |
| PoC-in-GitHub | 11,265 | one JSON array of repos per CVE |

Load reviewed GHSA by default; unreviewed entries are noisy and should be a
separate `--unreviewed` opt-in flag.

## Fetched

| Source | Path | What it adds |
|---|---|---|
| CVE List v5 (`cvelistV5`) | `cveorg/` | CNA metadata, affected products, references |
| GitHub Advisory DB | `ghsa/` | GHSA advisories, OSV-format, package ranges |
| PoC-in-GitHub | `poc-in-github/` | CVE → public GitHub PoC references |
| Project Zero | `project-zero/blog.rss` | 0-day research and root-cause writeups |
| ZDI published | `zdi/published.rss`, `zdi/published.html` | Published advisories |
| ZDI upcoming | `zdi/upcoming.html` | Not-yet-published 0-day pipeline |
| CISA advisories | `cisa/all-advisories.xml` | Alerts and ICS advisories |
| CERT/CC | `certcc/vuls.html` | Multi-vendor coordination notes |
| Full Disclosure | `seclists/fulldisclosure.rss` | Public 0-day/exploit disclosures |
| Cisco | `cisco/advisories.xml`, `cisco/csaf.xml` | Cisco PSIRT, CSAF |
| Fortinet | `fortinet/psirt.html` | Fortinet PSIRT |
| Palo Alto | `paloalto/advisories.html` | PAN-OS and product advisories |
| Citrix | `citrix/bulletins.html` | Citrix/NetScaler bulletins |
| VMware | `vmware/advisories.html` | VMSA index |
| Zimbra | `zimbra/security.html` | Zimbra Security Center |
| SAP | `sap/security-notes.html` | SAP Security Notes / Patch Day |
| F5 | `f5/advisories.html` | F5 security advisories |
| SonicWall | `sonicwall/psirt.html` | SonicWall PSIRT |
| Oracle CPU | `oracle/cpu.html` | Oracle Critical Patch Update index |

## Deliberately not bulk-downloaded

| Source | Why |
|---|---|
| HackerOne Hacktivity | Requires authenticated GraphQL; no public bulk endpoint |
| Bugcrowd disclosures | No stable public bulk API |
| Packet Storm | Feed URLs redirect through a terms-of-service gate |
| Sploitus | Aggregator with rate limits and unclear redistribution terms |
| Vulners / Flashpoint / Recorded Future / Mandiant / VulnCheck | Paid or contract-gated |
| Shodan / Censys / GreyNoise | API keys, quota, and terms restrict mirroring |
| Vendor portals behind login (some F5/SAP/Oracle pages) | Auth or bot protection |

## Candidate staging (2026-10-20, not approved)

These are downloaded for evaluation only; they are **not** in the main manifest
and are **not** indexed. Manifest with URL/license/SHA-256:
`data/intel/candidates/manifest.json`.

| Candidate | Bytes | Why staged |
|---|---:|---|
| `trickest-github.txt` | 17.4 MB | 89,602 unique CVEs, but 226,880 duplicate URLs and invalid `CVE-0000-0000` rows |
| `trickest-references.txt` | 13.6 MB | broad references, not PoC-specific |
| `pocindex-github.txt` | 1.8 MB | derived PoC index; validation only |
| `pocindex-nuclei.json` | 1.4 MB | Nuclei mapping cross-check |
| `pocindex-reference_poc_verified.json` | 16 KB | verified reference subset |
| `pocindex-kev.json` | 59 KB | KEV cross-check |
| `exploitdb-files_exploits.csv` | 9.8 MB | current CSV; hash matches staged copy, 47,170 rows |

## Next normalization steps

1. Parse RSS/Atom feeds into an `intel(source, id, title, url, published,
   summary, cve)` table with FTS; add `crowbar intel <query>`.
2. Extract `CVE-YYYY-NNNN` from every feed and insert into the alias table.
3. Parse PoC-in-GitHub JSON into `poc(cve, repo, url, stars, created_at)`.
4. Load GHSA's OSV JSON through the existing advisory/package-range path.
5. Diff CVE List v5 against NVD to find CNA-only records and missing references.
6. Add source freshness checks: fail `crowbar doctor` when a feed is older than its
   expected cadence.
