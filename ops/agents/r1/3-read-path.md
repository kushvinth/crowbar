# Agent 3 - read path: persistent MCP connection, connection PRAGMAs, FTS top-N

## Owns
`crowbar/db.py`, `crowbar/mcp.py`, `crowbar/query.py` (`search()` and helpers it
uses only), `tests/test_r1_read.py`.

## Goals
1. **db.connect PRAGMAs** for read-only connections: `mmap_size` (e.g. 256 MB),
   a larger `cache_size`, `temp_store=MEMORY`. Measure on a synthetic 300k-row DB
   that a warm `search` / `get_cve` gets faster or at least not slower; keep what helps.
2. **Hot-journal recovery.** Agent 1 is making `update` run in place inside one
   transaction on non-CoW drives. If that process is killed, a hot `-journal`
   stays behind and a `mode=ro` open fails until a writer opens the DB. In
   `db.connect(readonly=True)`: when `<db>-journal` exists, briefly open a normal
   read-write connection and read one row (SQLite itself only rolls back a journal
   that is really hot, i.e. no writer holds a lock), ignore errors (read-only
   media), then open the ro connection as now. Test it by creating a real hot
   journal (child process that begins a write transaction, writes, then is killed
   with SIGKILL) and asserting a ro connect works and the data is the pre-write state.
3. **Persistent MCP connection.** `mcp.handle` opens a new connection per
   `tools/call`. Keep one read-only connection; reopen it when the DB file changed
   underneath (inode or mtime of `paths.DB` differs - `update` swaps the file with
   `os.replace`, and the in-place mode keeps the inode but changes mtime) or after a
   `sqlite3.DatabaseError`. Must stay correct across a swap: test by swapping the
   DB file between two tool calls in a running server and asserting the second call
   sees the new data.
4. **FTS top-N for relevance search.** In `query.search`, when `sort='relevance'`,
   a query is given and NO other filter is set, take the top candidates inside FTS
   first (`SELECT id, rank FROM cve_fts WHERE cve_fts MATCH ? ORDER BY rank LIMIT ?`)
   and join `cve` on that small set, instead of computing bm25 + 3 correlated
   subqueries for every match. Results (ids and order) must equal the current
   implementation on the fixture and on a synthetic corpus for a set of queries;
   write that equivalence test. Measure before/after on 300k rows.

## Verify
- `tests/test_r1_read.py` for all four; existing `tests/test_unit.py` MCP tests pass.
- Report measured latencies (median of 5) before/after for search, get_cve and an
  MCP round-trip.
