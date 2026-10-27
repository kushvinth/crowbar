# Agent 2 – verify, manifest coverage, sync hardening

## Goal

Close the verify/manifest P0 items in `TODO.md` without touching the indexer or query layer. The
"exploit offline / doctor --json / filter-only browse / shared helpers" items were already done in
commit `57cc5a2` on your base: do not redo them; move their `TODO.md` lines to Done if still listed.

## Steps

1. **`crowbar verify` trusts the manifest too much** (TODO P0, `cli.py` `_verify` / `_db_ok`): it
   must always run `PRAGMA quick_check` on `index/crowbar.db`, require `meta.schema ==
   paths.SCHEMA_VERSION`, and fail on a 0-byte or schema-less DB even when the manifest is fine. Keep the
   hash checks. Add `--datasets` to hash every dataset in the registry that exists on disk (not only the
   ones in the manifest), reporting the ones the manifest does not track. `verify --json` prints the
   findings as a list of `{name, problem}`.
2. **Manifest coverage** (TODO P0, `datasets.py`): `index/manifest.json` tracks only datasets fetched
   through the generic downloader; custom handlers (nuclei, metasploit, msf-source, gtfobins, lolbas,
   payloads, vulnrichment, osv-*, exploitdb-full, debian-tracker, apple, msrc, chatter) never record an
   entry. Make every `sync` handler record `{url, path, bytes, fetched_at, sha256 (one file) or null,
   tier}` in the manifest through the same helper the generic path uses. Remove the stale keys
   (`metasploit-index`, `nuclei-templates`) on save. Add a unit test in `tests/test_unit.py` that
   monkeypatches the network functions (`http_text`, `download`, `git_clone`, ...) with fakes writing a
   small file, runs `sync_one` for one dataset of each handler kind, and asserts the manifest entry
   exists with `path` and `fetched_at`. Do not hit the network.
3. **`scripts/check.py`**: fail when a registered dataset's handler has no manifest write (simplest
   real check: after step 2, every handler goes through the one helper; assert by grepping that no
   handler function in `datasets.py` returns without calling it, or assert the registry names equal the
   names the fake-sync test produced - pick the smaller honest check).
4. **`crowbar sync --json`** (if not already there): per-dataset `{name, status, bytes, error}` so an
   agent can read the result. Keep the text output unchanged.
5. **`datasets.refresh_in_background` on a v3 index**: schema v4 (on your base) cannot be migrated in
   place; `update()` raises "needs a rebuild". Make sure the background auto-update records that error
   through `datasets.note_update` once and does not respawn every hour forever: when `update.err` says
   the index needs a rebuild, `refresh_in_background` must return False until the schema changes. Add a
   fixture test for that gate. (If the Tier 2 agent already did this on your base, verify it with a test
   and move on.)
6. Docs: `README.md`, `AGENTS.md` §7 (maintenance commands) and `docs/*.md` for `verify --datasets`,
   `verify --json`, `sync --json`. `TODO.md` lines moved to "Done (2026-10-27)".

## Report

`ops/agents/REPORT-r2-2.md`. Status file `ops/agents/status/r2-2.md`, last line `ALL DONE` when finished.
