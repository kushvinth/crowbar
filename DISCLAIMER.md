# Disclaimer

crowbar is a defensive vulnerability-intelligence tool for security
engineers, incident responders, and their coding agents. It aggregates public
data (NVD, CISA KEV, EPSS, MITRE CWE/CAPEC/ATT&CK, OSV, vendor advisories) and
public exploit/PoC **metadata and source as data** into a local, read-only
index.

## Authorized use only

Use crowbar only against systems you own or are explicitly permitted to
assess. You are responsible for complying with all applicable laws and with the
terms of every engagement.

## Dual-use data

crowbar can surface exploit source and PoC references. This is intended for
defenders triaging and reproducing issues under authorization. crowbar never
executes, compiles, or clones that code. Fetching exploit source with
`hv exploit <id>` downloads a file for you to inspect in isolation; running it
is your decision and your responsibility. Detonate untrusted code only in a
disposable, isolated environment.

## No warranty, not a verdict

Data is provided as-is from upstream sources and may be incomplete, stale, or
wrong. KEV and SSVC describe exploitation observed elsewhere; EPSS is a model
estimate. None of it is a statement about your specific environment. Verify
before you act. See [LICENSE](LICENSE) for the full warranty disclaimer and
[docs/DATASETS.md](docs/DATASETS.md) for per-source licensing and caveats.
