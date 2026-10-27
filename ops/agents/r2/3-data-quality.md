# Agent 3 – data quality in the bulk loaders

## Goal

Fix the P0 data-quality items in `TODO.md` that live in `crowbar/loaders.py`, so the vendor/ecosystem
answers are usable without changing the CLI surface more than one flag.

## Steps

1. **OSV severity normalization** (TODO P0). `advisory.severity` holds either '' or a raw CVSS vector.
   Add two columns to `advisory` in `indexer.SCHEMA` (the only `indexer.py` lines you may touch):
   `cvss REAL` and `severity_band TEXT` (CRITICAL/HIGH/MEDIUM/LOW/''). In `loaders.load_osv_zip` compute
   the CVSS base score from the vector with a small pure stdlib function (CVSS 3.x and 4.0 vectors
   appear; implement 3.0/3.1 exactly per the spec formula, and for 4.0 vectors store the band from
   `database_specific.severity` when present, else ''). Keep the raw vector in `severity`. Fall back to
   `database_specific.severity` / ecosystem severity when no vector exists. Add `--severity` to
   `crowbar advisory` (argparse in `cli.py`, filter in `query.advisory_search` on `severity_band`), and
   expose `cvss`/`severity_band` in `cb_advisory` results (they come through `SELECT *`). Update
   `AGENTS.md` §2 (`advisory(...)` columns) and `docs/DATASETS.md`.
   Schema change means `paths.SCHEMA_VERSION` is already 4 on your base; do NOT bump it again - the
   coordinator rebuilds the index after this round. Add the two columns to the `CREATE TABLE advisory`
   in `SCHEMA` only.
2. **Apple platform split** (TODO P0). `loaders.load_apple` lumps Safari/watchOS/tvOS/visionOS/Xcode
   into `platform='apple'`. Derive `platform` from the title: `macos`, `ios` (iOS/iPadOS), `watchos`,
   `tvos`, `visionos`, `safari`, `xcode`, else `apple`. Update the `cb_os`/`crowbar os` platform enum in
   `mcp.py` (that one line) and `cli.py` (argparse choices, those lines only), `AGENTS.md` §2
   (`os_advisory.platform` values) and `docs/DATASETS.md`.
3. **MSRC blanks are unexplained** (TODO P0). When MSRC gives no severity and no score, label
   `severity='Not rated'` instead of ''; when `impact` is empty and the title gives no keyword, label
   `impact='Unrated'`. Keep `exploited` as is.
4. **Debian `--release` filter** (TODO P0, the flag part only): `crowbar debian <pkg> --release bookworm`
   → `query.debian_lookup(..., release=...)`. One argparse line + one WHERE clause. The "why did the
   tracker drop bullseye/buster" question is a data question; note what the tracker JSON contains in
   your report, do not fix it.
5. **Tests** in `tests/test_unit.py` (loader tests only): CVSS 3.1 score for three known vectors
   (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8, a medium, a low), Apple platform
   derivation for five titles, MSRC "Not rated"/"Unrated" labels, Debian release filter on the fixture.
   Make `tests/support.py` fixture rows carry the new advisory columns if its INSERTs list columns
   explicitly (it is shared with agent 1: edit only the advisory INSERT if needed and say so).
6. `TODO.md`: move the four items to "Done (2026-10-27)" with one line each. Note in the report that the
   "Apple exploited parsing" item is already implemented in `load_apple` (`exploited_map`) and should be
   moved to Done as well if a real page shows non-empty `exploited` rows - verify with one page under
   `data/apple/pages/` if present (read-only).

## Report

`ops/agents/REPORT-r2-3.md`. Status file `ops/agents/status/r2-3.md`, last line `ALL DONE` when finished.
