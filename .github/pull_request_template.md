## What and why

<!-- What this changes and the problem it solves. Link the issue. -->

## Checklist

- [ ] `python3 scripts/check.py` passes (schema/catalog/docs consistency)
- [ ] `python3 -m tests.test_unit` passes
- [ ] New non-trivial logic has a test
- [ ] Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, …) for the changelog
- [ ] A new dataset documents its source and license in `docs/DATASETS.md` and does not commit `data/` or any `*.db`
- [ ] No owner-specific paths, secrets, or exploit payloads added (`gitleaks dir .` clean)
