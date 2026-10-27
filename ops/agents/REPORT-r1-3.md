# REPORT r1-3 - read path

## What changed

- `crowbar/db.py`
  - `connect(readonly=True)` sets `mmap_size=268435456` and `cache_size=-65536`
    beside `query_only=ON`. `temp_store=MEMORY` was tried and dropped (no effect).
  - new `recover_journal(path)`: when `<db>-journal` exists, open read-write once
    and read `sqlite_master`; SQLite rolls back a journal only when it is really
    hot (no live writer lock), and any `sqlite3.Error` (read-only media, locked)
    is ignored. Called before every read-only open.
- `crowbar/mcp.py`
  - `connection()` / `close_connection()`: one read-only connection for the
    server lifetime, keyed on `(inode, mtime_ns)` of `paths.DB`; reopened when the
    key changes (os.replace swap or in-place rewrite) or after a
    `sqlite3.DatabaseError`. `handle()` no longer opens/closes per `tools/call`.
- `crowbar/query.py` - `search()`: with a query, `sort="relevance"` and no other
  filter, the candidates are ranked inside FTS first
  (`SELECT id, rank FROM cve_fts WHERE cve_fts MATCH ? ORDER BY rank LIMIT ?` as a
  co-routine) and `cve` plus the three correlated subqueries are joined on that
  pool only. Every other path (filters, other sorts, no query) is unchanged.
- `tests/test_r1_read.py` (10 tests): PRAGMAs, real hot-journal recovery
  (SIGKILLed child writer with spilled pages), MCP connection across a swap, an
  in-place rewrite and a damaged file (running server), in-process
  DatabaseError recovery, FTS top-N equivalence (fixture + 30k synthetic corpus,
  9 queries x 4 limit/offset pairs) and the query plan.

## Measurements

See `ops/agents/status/r1-3.md` for the full table. On a 300k-row synthetic
index: relevance search 40-45% faster (137.7 -> 81.7 ms for "kernel",
83.2 -> 51.8 ms for "nginx overflow"), MCP `cb_cve` round-trip 0.73 -> 0.46 ms,
`get_cve` unchanged (0.18 ms, already PK lookups). The remaining search cost is
bm25 over every FTS match, which is inherent to ranking.

## Left undone / risks

- `mtime_ns` granularity: an in-place rewrite that finishes within the same
  timestamp tick on a coarse filesystem (FAT: 2 s) would not trigger a reopen.
  Harmless in practice: the persistent connection has no open read transaction
  between tool calls, so each statement already sees committed in-place changes;
  the reopen only matters for a swapped inode, which is always detected.
- `recover_journal` adds one `stat()` per read-only open (CLI) - sub-millisecond.
- cache_size could not be shown to help on a 309 MB index that fits in the mmap
  window; it is kept for the real 2.7 GB index where pages fall outside it.

## Changes needed from other agents

None. `cli.py` `verify` (agent 1's area) has its own hot-journal rollback
(`cmd_verify`, `PRAGMA quick_check`); it could call `db.recover_journal()` to
drop the duplicate, but that is optional.
