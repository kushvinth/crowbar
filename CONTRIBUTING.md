# Contributing to crowbar

Thanks for helping. crowbar is one SQLite+FTS5 index, one CLI, one MCP
server, standard library only. Keep it that way: no runtime dependencies.

## Development

```bash
git clone https://github.com/kushvinth/crowbar && cd crowbar
python3 scripts/check.py        # schema/catalog/docs consistency (fast, no corpus)
python3 -m tests.test_unit      # 96 fixture tests (no corpus needed)
uvx crowbar-cli sync --tier lite && uvx crowbar-cli build --tier lite   # a small real index
python3 -m tests.test_corpus    # generated tests against index/crowbar.db
pre-commit run --all-files      # check + unit + gitleaks
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `perf:`, `docs:`, `refactor:`, `test:`, `ci:`): the changelog
and version are generated from them by release-please.

## Contribution scope

- **Agent-token cost comes first.** A new MCP tool or field must return the
  smallest sufficient answer. Cap unbounded arrays and report a `*_total` count
  so callers know what was elided (see `query.CVE_ARRAY_CAP`). Measure a real
  response before and after.
- The index is read-only. `crowbar sql` is `PRAGMA query_only`; never add a write path.
- No tool clones, compiles, or executes exploit or PoC code. Fetching source for
  inspection is fine; running it is not.

## Adding a dataset

A new source touches five places (kept consistent by `scripts/check.py`):

1. a `Dataset(...)` entry in `crowbar/datasets.py` (with its tier)
2. a loader in `crowbar/loaders.py` or `crowbar/indexer.py`
3. a call in both `indexer.build` and `indexer.update`
4. a group in `crowbar/catalog.py`
5. the table in `indexer.SCHEMA`

Document the source URL, shape, **and license** in `docs/DATASETS.md`. Never
commit `data/` or any `*.db` - the corpus is built locally, not redistributed.
