# Agent 4 - CVE List v5: apply hourly/end-of-day delta zips instead of the 643 MB tarball

## Owns
`crowbar/intel.py` (the CVE List loader and delta code; keep `FTS_INSERT` as it is),
the CVE List parts of `crowbar/datasets.py` (a new fetch function; do not touch
`http_get`/`http_text`/`sync`/`index_status`), the `_update()` function in
`crowbar/cli.py` (only the CVE List wiring), docs lines about CVE List cadence in
`AGENTS.md`/`docs/DATASETS.md`, `tests/test_r2_cvelist.py`.

## Background
Every `crowbar update` re-downloads `codeload.github.com/CVEProject/cvelistV5`
(hundreds of MB) and `intel.load_cveorg` deletes + reloads ~400k CNA records
(minutes). CVEProject publishes hourly GitHub releases:
- tag `cve_<YYYY-MM-DD>_<HH>00Z`, asset `<YYYY-MM-DD>_delta_CVEs_at_<HH>00Z.zip`:
  CUMULATIVE changes since that day's midnight UTC (e.g. 2099 records at 1800Z),
  files `deltaCves/CVE-*.json` (same CVE JSON 5 format as the repo).
- tag `cve_<YYYY-MM-DD>_at_end_of_day`, asset `<YYYY-MM-DD>_delta_CVEs_at_end_of_day.zip`.
- direct URL: `https://github.com/CVEProject/cvelistV5/releases/download/<tag>/<asset>`;
  the latest tag: `https://api.github.com/repos/CVEProject/cvelistV5/releases/latest`
  (unauthenticated, 60 req/h - one call per update is fine).
Download one real delta into $TMPDIR to confirm the layout before coding.

## Goals
1. Refactor `load_cveorg` so the per-record logic takes an iterator of
   `(name, doc)`; the tarball keeps the full (delete-all + reload) behaviour; a new
   `apply_cveorg_deltas(con, zips, epss, kev_ids)` upserts only the records in the
   given zips: replace that CVE's `cve_cna` row and its `cve_cna_ref` /
   `cve_cna_product` rows, add `cve_meta`, promote PUBLISHED CVEs that `cve` lacks
   exactly like the full load. CNA data must never overwrite NVD's
   `cve.description`/`cvss` (existing invariant - test it).
2. Track progress in the DB: a `meta` key (e.g. `cveorg_delta`) holding the last
   applied tag; record a `source_state` row for the deltas.
3. `datasets`: a function that, given the last applied tag (or the tarball's
   `fetched_at` when no delta was ever applied), downloads the needed zips into
   `data/intel/cveorg/delta/`: end-of-day zips for each full day missed, then the
   latest hourly zip. More than 14 days behind -> return None (caller falls back
   to the full tarball). Reuse `http_get`.
4. `cli._update`: when the index already has a CVE List load and deltas are
   available, sync deltas instead of the `cveorg-cvelist` tarball and have
   `intel.load_all` (or update) apply them in chronological order; otherwise the
   current behaviour. A failed delta download must not fail the update (it is
   retried next run; the marker does not advance). `--deep` and `build` keep the
   full tarball.
5. Keep `crowbar sources` / `cb_sources` truthful about which mode loaded the data.

## Verify
- `tests/test_r2_cvelist.py`: build a tiny zip with 2-3 CVE JSON 5 records
  (one new PUBLISHED CVE absent from `cve`, one update to an existing CNA record,
  one REJECTED) and apply it to a fixture copy; assert rows; apply twice ->
  idempotent; NVD description untouched; tag marker advances; the date-walk logic
  (which zips are needed for a given marker and "now") with the network mocked,
  including the >14-day fallback and the midnight edge.
- One live run against GitHub in $TMPDIR (download the latest delta, apply to a
  fixture copy) and report the timing and record count.
