# Round r2 – common rules

## The system

crowbar: a zero-dependency Python 3.11+ CLI (`bin/crowbar`, `crowbar/cli.py`) and MCP stdio server
(`crowbar/mcp.py`) over one SQLite + FTS5 index. Read `AGENTS.md` and `CONTRIBUTING.md` first.
`crowbar/query.py` is the read layer, `crowbar/indexer.py` + `crowbar/intel.py` + `crowbar/loaders.py` +
`crowbar/chatter.py` build the index, `crowbar/datasets.py` downloads the corpora.

You are on a git worktree branched from the integration branch `integrate/perf`, which already contains
schema v4 (FTS prefix index, WITHOUT ROWID link tables) and round r1 (cve_fts rowid =
year*1e8+seq via `indexer.fts_rowid`, FTS optimize only on build, in-place update without
CoW, hot-journal recovery, persistent MCP connection) and the query-layer
rewrites (FTS top-N before join, IN filters, cached MCP connection), plus commit `57cc5a2`
(offline `exploit` lookup, `doctor --json`, filter-only browse, one `norm()`/`CVE_RE` in `loaders.py`).
Build on them; do not revert them.

Tests and checks (all must pass before every commit):

```sh
python3 -m tests.test_unit          # fixture tests, no corpus needed
python3 -m tests.test_v3            # schema v3/v4 adapter tests
python3 -m tests.test_r1_read && python3 -m tests.test_r1_write
python3 -m tests.test_r2_<area>     # your own new module, if your brief names one
python3 scripts/check.py            # schema / catalog / docs consistency
ruff check crowbar scripts tests
gitleaks git --no-banner .          # or: gitleaks dir .   (must be clean)
```

Real corpus for measurements (read-only unless your brief says otherwise): the lite data set is at
`/Users/MacbookPro/LocalStorage/Developer/personal/security/hacking/harness/_publish/hackvault/data`
(328 MB). To build or update against it without touching anything live, make your own home:

```sh
export CROWBAR_HOME="$TMPDIR/cb-$USER-r2-<n>"; mkdir -p "$CROWBAR_HOME"
ln -s /Users/MacbookPro/LocalStorage/Developer/personal/security/hacking/harness/_publish/hackvault/data "$CROWBAR_HOME/data"
export CROWBAR_NO_AUTO_UPDATE=1
python3 -m crowbar.cli build        # writes $CROWBAR_HOME/index/crowbar.db
```

Never write to `/Users/MacbookPro/LocalStorage/Developer/personal/security/hacking/harness/_publish/hackvault/index`
or to `~/.crowbar`. Never run `crowbar sync` (network) unless your brief says so.

## Hard rules

- Nothing is sent externally. No network calls except what `crowbar sync` already does, and only if your brief allows it.
- Never print, log or commit secrets. Run `gitleaks git --no-banner .` before each commit.
- No CAPTCHA bypass. No global installs (`brew`, `npm -g`, `pip install --user`, `sudo`). Stdlib only: the
  project has zero runtime dependencies and keeps it that way.
- Don't touch other containers, other worktrees, or the user's live index.
- No `Co-Authored-By` or "Generated with" trailers in commit messages. Plain conventional commits
  (`perf(indexer): ...`, `fix(cli): ...`, `test: ...`).
- Never push. Never merge. Never rebase onto anything. The coordinator merges your branch.
- Smallest change that fully works. No new abstractions, options or config nobody asked for. Reuse what the
  repo has. Comment only the why. Keep AGENTS.md / README.md / docs accurate for anything you change
  (`scripts/check.py` verifies some of it).

## Ownership (so merges don't conflict)

| agent | owns | must not edit |
|---|---|---|
| 1 build-pipeline | `crowbar/indexer.py`, `tests/test_r2_build.py` | `intel.py`, `cli.py`, `datasets.py`, `loaders.py`, `query.py` |
| 2 cli-hardening | `crowbar/cli.py` (except `_update`'s CVE List wiring), `crowbar/datasets.py` (except a new CVE List delta fetch function), `crowbar/catalog.py`, `README.md`, `docs/*.md` | `indexer.py`, `intel.py`, `loaders.py`, `query.py` |
| 3 data-quality | `crowbar/loaders.py`, `crowbar/query.py` (only `advisory_search`, `os_search`, `debian_lookup`), `tests/test_unit.py` (loader tests only), `AGENTS.md` §2/§4 for any column you add | `indexer.py` except the `SCHEMA` string for a new column, `cli.py` except the argparse lines for a flag your brief names, `datasets.py` |
| 4 cvelist-deltas | `crowbar/intel.py`, a new CVE List delta fetch function in `crowbar/datasets.py`, the CVE List wiring in `cli._update`, `tests/test_r2_cvelist.py`, CVE List cadence lines in `AGENTS.md`/`docs/DATASETS.md` | `indexer.py`, `loaders.py`, `query.py`, the rest of `cli.py`/`datasets.py` |

If you must touch a file outside your ownership, keep it to the exact lines your brief names and say so in your report.

## Working loop

1. Keep `ops/agents/status/r2-<n>.md` as a checklist with evidence (command + result) for each step. Update it
   every iteration; commit it with your code.
2. Commit small working steps; every commit passes the checks above.
3. Measure before and after for any perf claim; put the numbers in your report.
4. Write `ops/agents/REPORT-r2-<n>.md`: what changed per file, measurements, what you skipped and why,
   risks the coordinator must know.
5. When everything in your brief is done and verified, make the exact last line of your status file `ALL DONE`.
