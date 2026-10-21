# Datasets - sources, shapes, licenses

Everything is downloaded unmodified into `data/` and recorded in
`index/manifest.json` (url, bytes, sha256, fetched_at, http_last_modified,
tier). Re-syncs use sha256 plus `If-Modified-Since`; an unchanged feed costs a
304, not a download.

## Core (default)

| dataset | source | file | shape | cadence |
|---|---|---|---|---|
| NVD CVE 2.0, per year | nvd.nist.gov (US NIST, public domain) | `data/nvd/nvdcve-2.0-<year>.json.gz` | JSON, 2002–2026 | daily |
| NVD recent / modified | nvd.nist.gov | `data/nvd/nvdcve-2.0-{recent,modified}.json.gz` | last 8 days of changes | ~2 h |
| CISA KEV | cisa.gov (public domain) | `data/kev/known_exploited_vulnerabilities.json` | JSON | daily |
| EPSS | FIRST / Empirical Security | `data/epss/epss_scores-current.csv.gz` | `cve,epss,percentile` | daily |
| Exploit-DB | exploit-db.com | `data/exploitdb/files_exploits.csv` | CSV index, ~47k | daily |
| Exploit-DB shellcodes | exploit-db.com | `data/exploitdb/files_shellcodes.csv` | CSV index | daily |
| Nuclei templates | projectdiscovery/nuclei-templates (MIT) | `data/nuclei/templates/` | git, YAML | daily |
| Metasploit modules | rapid7/metasploit-framework (BSD-3) | `data/metasploit/source/` | sparse git clone | on demand |
| MSRC Security Update Guide | api.msrc.microsoft.com | `data/msrc/sug.json` | JSON, 30.7k rows | daily |
| Apple security releases | support.apple.com | `data/apple/index.html` + pages | HTML, 319 pages | daily |
| ATT&CK Enterprise | attack.mitre.org | `data/attack/enterprise-attack.json` | STIX 2.1 | 2×/year |
| CWE | cwe.mitre.org | `data/cwe/cwec_latest.xml.zip` | XML | quarterly |
| CAPEC | capec.mitre.org | `data/capec/capec_latest.xml` | XML | quarterly |
| LLM catalog | models.dev | `data/models/models.dev.json` | providers → models | daily |

## Extra (`crowbar sync --extra`, `crowbar build --extra`)

| dataset | source | file | shape | value |
|---|---|---|---|---|
| ATT&CK Mobile | attack.mitre.org | `data/attack/mobile-attack.json` | STIX | mobile techniques |
| ATT&CK ICS | attack.mitre.org | `data/attack/ics-attack.json` | STIX | OT/ICS techniques |
| CISA Vulnrichment | cisagov/vulnrichment | `data/vulnrichment/` | per-CVE JSON | SSVC decision points, ADP enrichments |

Vulnrichment populates `ssvc(cve_id, exploitation, automatable, technical_impact)`
and enables `crowbar search --ssvc active`. It is a large clone (~40k JSON files);
enable it only if you want SSVC.

## Bulk (`crowbar sync --bulk`)

Bulk feeds are opt-in for download, but `crowbar build` indexes them automatically
whenever their directory already exists. Nothing here is required for core
queries.

| dataset | source | file | shape | value |
|---|---|---|---|---|
| OSV npm | osv.dev | `data/osv/npm.zip` | 230k JSON records | npm advisories + ranges |
| OSV PyPI | osv.dev | `data/osv/PyPI.zip` | JSON records | Python advisories |
| OSV Go / crates.io / RubyGems / Maven / NuGet / Packagist / Pub / Hex | osv.dev | `data/osv/<eco>.zip` | JSON records | 10 ecosystems total |
| Debian tracker | security-tracker.debian.org | `data/debian/` | git checkout | package × release × CVE |
| Exploit-DB full | gitlab.com/exploit-database/exploitdb | `data/exploitdb/full/` | git checkout | 46k exploit sources |
| Metasploit source | rapid7/metasploit-framework | `data/metasploit/source/` | sparse checkout | module `.rb` metadata |
| GTFOBins | gtfobins/gtfobins.github.io | `data/toolkit/gtfobins/` | Jekyll collection | 478 binaries |
| LOLBAS | LOLBAS-Project/LOLBAS | `data/toolkit/lolbas/` | YAML | 385 Windows binaries |
| PayloadsAllTheThings | swisskyrepo/PayloadsAllTheThings | `data/toolkit/payloads/` | markdown | 148 payload notes |

Downloading all of it is ~3 GB compressed; unzipping OSV + NVD would add another
3.2 GB. The loaders parse zips in place, so no extraction is performed.

## Index mapping

| table | built from | notes |
|---|---|---|
| `cve` | NVD feeds | CVSS v4 > v3.1 > v3.0 > v2; `year` precomputed |
| `cve_cwe` | NVD `weaknesses[]` | `CWE-NNNN` |
| `cpe_match` | NVD `configurations[].nodes[].cpeMatch[]` | only `vulnerable=true`; keeps version bounds |
| `cve_product` | derived from `cpe_match` | deduped vendor/product, capped 120/CVE |
| `cve_ref` | NVD `references[]` | capped 60/CVE |
| `kev` | CISA KEV | due date, ransomware flag |
| `exploit` / `cve_exploit` | Exploit-DB `codes` column | CVE ids extracted by regex |
| `nuclei` / `cve_nuclei` | template `info.classification.cve-id` | template path kept for reading YAML |
| `msf` / `cve_msf` | module `.rb` files | name, platform, description, CVE ids |
| `attack` | STIX `attack-pattern` objects | `domain` distinguishes enterprise/mobile/ics |
| `cwe`, `capec` | MITRE XML | definitions + related weaknesses |
| `model` | models.dev | context/output limits, $/M tokens, capability flags |
| `ssvc` | Vulnrichment | optional (present when `data/vulnrichment/` exists) |
| `advisory` / `package_range` | OSV zips | id, ecosystem, package, severity, aliases, affected ranges |
| `debian` | Debian tracker | package × release × CVE, status, fixed version |
| `os_advisory` | MSRC SUG + Apple releases | platform, product, version, title, severity, impact |
| `toolkit` / `toolkit_fts` | GTFOBins/LOLBAS/Payloads | source, name, path, description, tags |
| `exploit_code_fts` | Exploit-DB full sources | full-text search inside exploit code |

## Notes and caveats

**NVD feeds.** Year files are full snapshots; `recent`/`modified` are the
incremental delta. `crowbar build` uses year files (complete, stable), `crowbar update`
applies the delta in place. Rejected CVEs appear with `status = 'Rejected'` and
usually an empty description.

**CPE extraction.** `cpe_match` keeps `part, vendor, product, version` plus the
four bound fields. Wildcard vendors/products (`*`, `-`) are dropped, and each
row is deduped per CVE, capped at 400. Version comparison is segment-wise
(`1.2.3p1`), with alpha segments sorting after numeric ones at the same
position. This is deliberately simple; for exotic version schemes read the raw
NVD record.

**EPSS.** A calibrated probability (0–1) that a CVE is exploited in the next 30
days, plus its percentile. Model output, not a verdict. The CSV carries a
`#model_version` comment line that the reader skips.

**KEV.** `date_added` is when CISA added it; `due` is the federal remediation
deadline; `ransomware` is `Known`/`Unknown`. Membership means observed
exploitation somewhere, not that your host is affected.

**Exploit-DB.** `codes` is a semicolon-separated string of CVE/OSVDB/EDB ids.
`crowbar exploit <id>` downloads the file from GitLab raw into
`data/exploitdb/files/<file>` on demand; the full corpus is not mirrored.

**Nuclei.** Metadata is parsed with a line-oriented extractor (no YAML
dependency): `id`, `info.name`, `info.severity`, `info.tags`,
`info.description`, `info.classification.cve-id`. Workflows/helpers/profiles are
excluded. The YAML stays on disk for exact matchers.

**Metasploit.** `load_msf_source` reads module `.rb` files (not just paths) and
extracts name, platform, description and CVE ids from `references`. This
populates `cve_msf` (1,171 links) and replaces the sparse GitHub tree mapping.

**OSV.** One zip per ecosystem, parsed in place. `package_range` keeps
introduced/fixed/last_affected bounds so `crowbar advisory --package lodash` can show
which versions are affected without reading the zip at query time.

**Debian.** The tracker checkout is parsed into package × release × CVE rows
with status and fixed version. `crowbar debian openssl` answers "what is fixed in
bookworm?" directly.

**MSRC.** The Security Update Guide API is paginated 500 rows at a time into
`data/msrc/sug.json` (30,700 rows). `severityId` maps to
Critical/Important/Moderate/Low; `impactId` maps to RCE/EoP/DoS/InfoDisclosure/
Spoofing/Tampering/Bypass. Rows without a severity/impact keep empty strings.

**Apple.** The security-releases index is fetched, then each advisory page is
fetched (6 workers) and CVE ids are extracted. Platform is inferred from the
release title (`macos`, `ios`, else `apple` for Safari/watchOS/tvOS/visionOS).

**Toolkit.** GTFOBins files are extensionless Jekyll collection entries under
`_gtfobins/`; LOLBAS uses YAML; PayloadsAllTheThings uses Markdown. `functions:`
keys become tags for GTFOBins.

**Exploit code.** The full Exploit-DB checkout is indexed into
`exploit_code_fts` (46,454 files) so `crowbar code jndi` searches source, not just
metadata.

**models.dev.** Upstream-reported pricing and limits; may lag vendor changes.

**Licensing.** NVD/KEV are US government works. MITRE content (CWE, CAPEC,
ATT&CK) requires attribution. Exploit-DB, Nuclei and Metasploit have their own
licenses. Keep `data/` out of public repos.
