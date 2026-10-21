# Security Policy

## Supported versions

Security fixes are provided for the latest published version of crowbar.
Upgrade to the latest release before reporting a problem that may already be
resolved.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting:
<https://github.com/kushvinth/crowbar/security/advisories/new>
(**Security** tab > **Report a vulnerability**). Do not open a public issue to request a private contact
channel, and do not include working exploit payloads, credentials, or private
target data in the report.

Include the affected crowbar version, your OS, how you installed it
(`uvx`, `pip`, `git`), the dataset tier in use, impact, and reproduction steps.

The maintainer acknowledges reports within 7 days, assesses scope, and
coordinates a fix and disclosure timing with the reporter. Fixed issues are
published as GitHub security advisories.

## Security boundary

crowbar is a **read-only, offline index**. The CLI and MCP server open the
SQLite database read-only (`PRAGMA query_only`), and `crowbar sql` rejects writes and
DDL. No tool clones, compiles, or executes exploit code.

What crowbar indexes is untrusted upstream content: CVE text, advisory pages,
Exploit-DB and Metasploit **source** (as data), and PoC repository **metadata**
(never the repositories themselves). Treat every exploit or PoC it surfaces as
hostile code. Run anything you fetch in a disposable VM or container, never on
your host.

This is not a sandbox. The index reflects observed exploitation reported
elsewhere (KEV, SSVC) and model output (EPSS); neither is a statement about your
own hosts. Absence of a row is not proof that something is "not affected";
upstream coverage is advisory-driven, not exhaustive.

Only test systems you own or are explicitly authorized to test.
