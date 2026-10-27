# REPORT r1-1 - index write path

## What changed (`crowbar/indexer.py`, one statement in `crowbar/intel.py`, `tests/test_r1_write.py`)

1. **cve_fts fixed rowids.** `fts_rowid(cid)` / `FTS_ROWID_SQL` (`year*1e8 + seq`). `_flush`
   and intel `load_cveorg.flush()` insert with `INSERT OR REPLACE INTO cve_fts(rowid, ...)`
   (FTS5 raises `IntegrityError` on a plain duplicate rowid; `OR REPLACE` swaps the row and
   its tokens - covered by a test). `delete_cves` deletes cve_fts by rowid; on an index that
   has not been renumbered it still uses `id IN (...)` so a stale index never keeps orphan rows.
2. **Migration.** `migrate_fts_rowids(con)` runs once from `update()` (after the schema
   migration, before the NVD reload): copies `id, description, products` to a temp table
   grouped by id (newest rowid wins), drops and recreates `cve_fts` from its own DDL in
   `sqlite_master` (FTS5 has no fast truncate for a content-bearing table), reinserts with the
   computed rowid, sets `meta.fts_rowid='1'`. `build()` sets the flag directly.
3. **optimize only in build.** `finish(con, optimize=False)`; `build()` passes `True`.
4. **In-place update without CoW.** `_clone()` now returns whether a clone happened. On macOS
   `cp -c` silently falls back to a full copy (man cp), so it calls `clonefile(2)` through
   ctypes; Linux uses `cp --reflink=always`. When it returns False, `update()` opens the live
   DB with `isolation_level=None`, runs `BEGIN IMMEDIATE`, wraps the connection in `_OneTxn`
   (no-op `commit()`, `executescript()` split by `sqlite3.complete_statement` and run
   statement by statement) and issues one `COMMIT` at the end, `ROLLBACK` + close on any
   exception. The live DB keeps its default `synchronous` and rollback journal. The old
   `shutil.copy2` fallback is gone (it was the 2x-disk path).
5. **apply_epss** only updates rows whose `epss` or `epss_pct` differ (`IS NOT`, NULL-safe).

## Measurements (synthetic 300k cve + cve_fts rows, 1.3 GB, warm cache, APFS SSD)

| step | before | after |
|---|---|---|
| delete 5 000 ids from cve_fts (7 chunks of 800) | 1.91 s (7 full scans, plan `INDEX 0:`) | 0.32 s (rowid lookups, plan `INDEX 0:=`) |
| one-off renumber (`migrate_fts_rowids`) | - | 12.75 s (expect ~20 s on the real 400k index) |
| `update()` FTS optimize | 4 tables rewritten every run | build only |
| `apply_epss` on an unchanged score file | every cve row rewritten | 0 cve rows written |

The numbers come from a warm page cache: the old path's cost is a full read of the FTS
content table per chunk, so on a USB/exFAT index the difference is disk-bandwidth bound.

## Verification

`python3 -m tests.test_r1_write` (12 tests), `tests.test_unit`, `tests.test_v3`,
`scripts/check.py`, `ruff check` - all green on Python 3.14.7 and 3.11.8. `update()` ran end
to end on a fixture home through both the APFS clone path and the forced in-place path,
including a forced failure (DB byte-for-byte identical via `iterdump()`, no hot journal, no
tmp file, next run succeeds) and a schema-2 fixture (intel.migrate's executescript through
the proxy).

## Left undone / risks

- The renumber copies the FTS content into a temp table with `temp_store=MEMORY`: on the real
  index that is roughly the size of the descriptions (hundreds of MB) for the one migration
  run. If that is too much for small hosts, switch `update()` to `temp_store=FILE` before the
  migration.
- In-place path: the final COMMIT needs an EXCLUSIVE lock, so a long-running reader can make
  it wait up to the 90 s busy timeout and then fail (the transaction rolls back, the DB is
  unchanged). The clone path has no such interaction.
- A malformed CVE id (not `CVE-YYYY-N`) makes `fts_rowid` raise `ValueError` and the SQL form
  cast to 0; NVD and CVE List ids are canonical, so this never triggered, but it is a louder
  failure than before.
- `ruff format` is not the house style for existing files; the new test module is
  ruff-formatted because the editor hook formats on write.

## Changes needed from other agents

- **Agent 2 (`crowbar/intel.py`)**: the cve_fts insert in `load_cveorg.flush()` inlines the
  rowid formula in SQL (`CAST(substr(?1,5,4) AS INTEGER)*100000000+CAST(substr(?1,10) AS
  INTEGER)`) because I was limited to that single statement and intel.py does not import
  indexer. If you add an import, `indexer.fts_rowid(cid)` is the shared helper.
- **Agent 3 (`crowbar/db.py`)**: the in-place path means a crash mid-COMMIT can leave a hot
  `crowbar.db-journal` next to the live DB; your read-only hot-journal recovery covers that.
