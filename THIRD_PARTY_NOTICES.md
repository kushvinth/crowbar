# Third-party notices

crowbar-authored code is MIT ([LICENSE](LICENSE)) and ships **zero runtime
dependencies** (Python standard library only) - no third-party code is vendored
or bundled into the package.

Two kinds of third-party material are involved, neither redistributed by this
repository:

## 1. Indexed data (downloaded locally at build time, never committed)

crowbar builds its index from public sources. Each keeps its own license and
terms; `data/` and `index/*.db` are git-ignored and never shipped. Per-source
shape, URLs and caveats are in [docs/DATASETS.md](docs/DATASETS.md).

| Source | Content | License / terms |
|---|---|---|
| NVD (NIST) | CVE records, CPE ranges | U.S. Government public domain |
| CISA KEV | Known Exploited Vulnerabilities | U.S. Government public domain |
| CISA Vulnrichment | SSVC decision points | U.S. Government public domain |
| FIRST EPSS | exploit-prediction scores | free use, attribution to FIRST |
| MITRE CWE / CAPEC / ATT&CK | taxonomies, techniques | free use with attribution to MITRE |
| CVE List (cve.org) | CNA records | CVE Program terms |
| Exploit-DB | exploit index + sources | OffSec Exploit-DB terms (no redistribution) |
| Nuclei templates | detection templates | MIT (ProjectDiscovery) |
| Metasploit modules | module metadata + sources | BSD-3-Clause (Rapid7) |
| OSV | ecosystem advisories (incl. GHSA) | CC-BY / per-ecosystem |
| Debian security tracker | per-package fixed versions | Debian terms |
| Microsoft MSRC | Windows/Edge advisories | Microsoft terms |
| Apple security releases | iOS/macOS advisories | Apple terms |
| GTFOBins / LOLBAS / PayloadsAllTheThings | LOLBin/payload references | respective repo licenses (MIT / GPL) |
| models.dev | LLM catalog | models.dev terms |

Treat exploit and PoC content as untrusted, hostile code. crowbar never clones,
compiles, or executes it.

## 2. Documentation build (docs-only, not in the tool)

The `website/` docs site builds with [Docusaurus](https://docusaurus.io/) and
[asciinema-player](https://github.com/asciinema/asciinema-player) (both MIT).
These are development dependencies for the docs site only; they are not part of
the `crowbar-cli` package or its runtime.
