# Round r1 - crowbar audit follow-ups (shared rules)

## The system
crowbar is a local, read-only vulnerability-intelligence index: one SQLite+FTS5 DB
(`index/crowbar.db`, ~2.7 GB in real use: 400k CVEs, 2M cpe_match rows), a CLI
(`crowbar/cli.py`, shim `bin/crowbar`) and a zero-dependency MCP stdio server
(`crowbar/mcp.py`). Python stdlib only - never add a dependency. Read `AGENTS.md`
and `CONTRIBUTING.md` first. Your worktree is branched from `perf/audit-followups`.

There is NO real corpus on this machine. Use the fixture:
`python3 scripts/make_fixture.py $TMPDIR/fx --force` then
`CROWBAR_HOME=$TMPDIR/fx CROWBAR_NO_AUTO_UPDATE=1 ./bin/crowbar ...`.
For scale questions, build a synthetic DB in `$TMPDIR` (e.g. 300k fake CVE rows)
and measure; `EXPLAIN QUERY PLAN` everything you change.

## Checks (all must pass before every commit)
```
python3 -m tests.test_unit
python3 -m tests.test_v3
python3 -m tests.test_r1_<yourarea>      # your new test module (see your brief)
python3 scripts/check.py
ruff check crowbar tests scripts mcp bin
```
Python 3.11 must work: no f-strings that reuse the outer quote inside `{}`, no
3.12-only APIs (e.g. `sqlite3.Connection.autocommit`). SQLite >= 3.35 features are ok.

## Hard rules
- Nothing sent externally: no `git push`, no PRs, no issues, no package publishing.
  Downloads from public upstreams for verification are fine.
- Never print, log or commit secrets. Run `gitleaks git --staged --no-banner`
  (or `, gitleaks ...`) before each commit if it is available.
- No global installs (`brew`, `npm -g`, `pip install` outside a venv in $TMPDIR, `sudo`).
- Do NOT add `Co-Authored-By` trailers or "Generated with Claude Code" lines to
  commits. Conventional commit messages (`perf(update): ...`, `fix(mcp): ...`).
- Keep diffs minimal and in the house style (see the surrounding code; one-line
  "why" comments only). A PostToolUse formatter may rewrite whole files when you
  use the Edit tool: if `git diff --stat` shows lines you did not mean to change,
  restore them (`git checkout -p` or re-apply your edit with a small script) so
  the diff contains only your change.
- Stay inside the files you own (your brief). If you truly need a change in a
  file another agent owns, write it down in your report instead of making it.
- Tests go in your own new module `tests/test_r1_<yourarea>.py` (unittest,
  runnable with `python3 -m tests.test_r1_<yourarea>`, reuse `tests/support.py`
  without editing it). Do not edit `tests/test_unit.py` except to fix a test your
  change legitimately breaks.

## Working loop
1. Keep `ops/agents/status/r1-<n>.md` as a checklist: each item `- [ ]`/`- [x]`
   with evidence (test name, measured numbers, query plan line).
2. Commit small, working steps (code + tests + status file together).
3. Write `ops/agents/REPORT-r1-<n>.md`: what changed, measurements before/after,
   anything left undone, risks, and any change you need from another agent.
4. When everything in your brief is done and verified, make the last line of your
   status file exactly `ALL DONE` and commit it. That is the stop condition.
