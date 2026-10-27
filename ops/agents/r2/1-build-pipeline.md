# Agent 1 – build and update pipeline speed

## Goal

Make `crowbar build` and `crowbar update` faster without changing what they produce.

## Context (measured)

- `indexer.load_nvd()` is the long pole of `build`: for each NVD year file it gunzips + `json.load`s the
  whole feed, then runs `parse_cve()` per item on one core. `parse_cve()` is pure (dict in, tuples out).
- (fixed in r1) `indexer.finish()` used to run `INSERT INTO <fts>(<fts>) VALUES('optimize')` on four FTS tables on **every**
  update; `optimize` rewrites the whole FTS index into one segment, so a 10 s update spends most of its
  time there once the index is big.
- `summarize()` after every build/update does `count(*)` on every table (fine, once).
- `cve_fts` rowid is `indexer.fts_rowid(id)` (year*1e8+seq); `delete_cves()` deletes FTS rows by rowid. Keep that invariant in anything you change.

## Steps

1. **Parallel NVD parse.** In `load_nvd()`, parse items with `multiprocessing.Pool` (`imap`, chunksize
   ~500, `processes=max(1, os.cpu_count() - 1)`), keeping the single writer connection and the existing
   `_flush()` batching. `parse_cve(item, epss, kev_ids)` needs `epss` (dict of ~300k entries) and
   `kev_ids`; pass them once via the pool initializer (module globals in the worker), not per item.
   Keep the sequential path when the file has fewer than ~2000 items or `os.cpu_count() == 1`, and on
   any `OSError` from starting the pool (sandboxed or restricted environments) fall back to sequential.
   Output must be byte-identical: same rows, same order in each table as today (order within a batch may
   follow the input order; `imap` preserves order).
2. **(done in r1: optimize runs only on build; skip)** FTS merge instead of optimize on update. Give `finish()` a `full: bool = True` parameter;
   `build()` keeps `optimize`; `update()` calls `finish(con, full=False)`, which runs
   `INSERT INTO <fts>(<fts>, rank) VALUES('merge', 200)` per FTS table instead (bounded incremental
   merge). Keep ANALYZE in both.
3. **`update()`: skip work whose input did not change.** `load_cwe`, `load_capec`, `load_models`,
   `chatter.load`, `load_ssvc` run on every update even when their files are unchanged. Add a tiny
   mtime+size check against `source_state` (reuse `intel.record_source` / `already_loaded` style: store
   the file's `st_mtime_ns` and size in `source_state.sha256`'s neighbour fields or `note`) and skip the
   loader when unchanged. Do not change what the loaders write when they do run.
4. **Measure** with your own `CROWBAR_HOME` (see common rules): time `build` before and after (git stash
   is forbidden; use a second worktree checkout of the base commit, or just run the old code from
   `git show integrate/perf:crowbar/indexer.py > /tmp/...`? No: simplest is to time `build` once on your
   branch before step 1 and once after). Then time `update` twice (the second run has unchanged inputs).
   Put all numbers in the report. Also report `stats.json` → `db_bytes` and the `cve` count before and
   after to prove the output is unchanged, plus `SELECT count(*) FROM cve_fts` == `SELECT count(*) FROM cve`.
5. **Tests.** Add to a new `tests/test_r2_build.py`: (a) the parallel path produces the same `cve`, `cve_cwe`,
   `cve_product`, `cpe_match`, `cve_ref`, `cve_fts` rows as the sequential path on the fixture feed
   (force both paths via a parameter or a module flag; do not duplicate parse logic); (b) `finish(con,
   full=False)` leaves the FTS tables queryable and `tests` still pass.
6. Update `TODO.md`: add one line under "Done (2026-10-27)" per item that landed. Update `docs/MAP.md`
   or `AGENTS.md` §7 only if the `update` behaviour description changes.

## Report

`ops/agents/REPORT-r2-1.md`. Status file `ops/agents/status/r2-1.md`, last line `ALL DONE` when finished.
