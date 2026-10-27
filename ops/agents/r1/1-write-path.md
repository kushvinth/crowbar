# Agent 1 - index write path: FTS rowids, optimize in build only, in-place update

## Owns
`crowbar/indexer.py`; `tests/test_r1_write.py`; status/report files for r1-1.
(`crowbar/intel.py` belongs to agent 2: the one-line FTS insert in `load_cveorg`'s
`flush()` is the exception - you may change that single statement to use the
shared rowid helper. Nothing else in intel.py.)

## Goals
1. **cve_fts fixed rowids.** `cve_fts.id` is UNINDEXED, so `delete_cves()`'s
   `DELETE FROM cve_fts WHERE id IN (...)` scans the whole FTS table per 800-id chunk.
   - Add `fts_rowid(cid) -> int` = `year * 100_000_000 + seq` (CVE-YYYY-N...) and the
     equivalent SQL expression; insert every cve_fts row with that rowid
     (`_flush`, and the CNA insert in intel.py `load_cveorg`), using a conflict mode
     that cannot raise on a duplicate id (verify FTS5 REPLACE behaviour with a test).
   - `delete_cves` deletes cve_fts by rowid.
   - Existing indexes: in `update()`, if `meta.fts_rowid` != '1', renumber once
     (copy id/description/products to a temp table grouped by id, clear, reinsert
     with the computed rowid), then set `meta.fts_rowid='1'`. `build()` sets it too.
     The fixture (`tests/support.py`) inserts without rowids - your migration must
     handle that, and your test should prove a fixture copy migrates and that FTS
     row count == cve row count afterwards.
2. **FTS optimize only in build.** `finish()` currently runs `INSERT INTO x(x)
   VALUES('optimize')` on every update, which rewrites whole FTS indexes. Keep
   indexes + ANALYZE in both; optimize only in build.
3. **In-place update on non-CoW filesystems.** `update()` copies the 2.7 GB DB
   (`_clone` falls back to `shutil.copy2` on exFAT/USB). When the CoW clone is not
   possible, update the live DB in place inside ONE transaction instead (rollback
   journal = same crash atomicity, no 2x disk). Loaders call `con.commit()` and
   `con.executescript()` (which implicitly COMMITs) all over, and Python 3.11 has no
   `autocommit` attribute, so wrap the connection in a small proxy whose
   `commit()` is a no-op and whose `executescript()` runs statements one by one
   (`sqlite3.complete_statement`) - then do the real COMMIT (or ROLLBACK on any
   exception) once at the end. Do not set `synchronous=OFF` on the live DB.
   Keep the CoW/copy path when clone works. `_clone` should report whether it
   cloned. Document the trade-off (readers may wait during the commit) in a
   one-line comment.
   Note: agent 3 owns `crowbar/db.py` and is adding hot-journal recovery for
   read-only opens; do not edit db.py.
4. **apply_epss writes only changed rows** (`WHERE ... AND (cve.epss IS NOT t.epss
   OR cve.epss_pct IS NOT t.pct)`), so an update does not rewrite every cve page.

## Verify
- tests in `tests/test_r1_write.py`: rowid helper; duplicate insert does not raise;
  delete_cves removes exactly the FTS rows for those ids; migration of a fixture
  copy; optimize not called by update (mock or inspect); in-place path commits
  everything or nothing (force an exception mid-update with a patched loader and
  assert the DB is unchanged and has no hot journal left); apply_epss skips equal rows.
- Measure on a synthetic 300k-row cve + cve_fts DB in $TMPDIR: delete of 5k ids
  before vs after (seconds), and report it.
- Run `indexer.update()` end-to-end on a fixture home (CROWBAR_HOME) both with clone
  and with `_clone` forced to the non-CoW path.
