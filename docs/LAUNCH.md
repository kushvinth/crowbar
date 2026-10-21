# Publishing & launch runbook

crowbar ships at **0.1.0 (public beta)** - `0.x` = pre-stable, API may move.
One canonical repo (`kushvinth/crowbar`), one version, distributed to every
channel below. Most publishing is automated by GitHub Actions on release; a few
steps need a one-time account/secret setup you do once.

Positioning on every surface: **"Retrieve CVEs and index them inside your
codebase. Offline, reproducible CVE + exploit intelligence - one MCP server."**
Lead with that verb.

## How releases work (release-please)

Commits use [Conventional Commits](https://www.conventionalcommits.org/). On push
to `main`, `release-please` opens/updates a release PR; merging it tags
`v0.1.0`, writes the CHANGELOG, and **triggers every publish job** in
`.github/workflows/release.yml`:

| Channel | Job | One-time setup you do |
|---|---|---|
| **GitHub Release** | `release-please` | none |
| **PyPI** `crowbar-cli` | `pypi` | add a [Trusted Publisher](https://docs.pypi.org/trusted-publishers/) for the repo (no token) |
| **npm** `crowbar-cli` | `npm` | `npm login`, add `NPM_TOKEN` repo secret |
| **Docker** `ghcr.io/kushvinth/crowbar` | `docker` | none (uses `GITHUB_TOKEN`); make the package public after first push |
| **MCP registry** `io.github.kushvinth/crowbar` | `mcp-registry` | none (GitHub OIDC); the `io.github.kushvinth/*` namespace authorizes from your repo |
| **Website** | Vercel (Git) | done: `crowbar` project, root dir `website`, domain `crowbar.kushvinth.com` |

So after the one-time setup, **publishing = merge the release PR**.

v0.1.0 was cut with a temporary `release-as: 0.1.0` pin in `release-please-config.json`, removed once tagged; versions now follow the Conventional Commits since the last release.

Registries publish only once switched on: set the repo variables `PUBLISH_NPM` / `PUBLISH_PYPI` to `true` (Settings > Secrets and variables > Actions > Variables). npm needs `NPM_TOKEN` to be a granular token with "bypass 2FA" enabled; PyPI needs the trusted publisher (owner `kushvinth`, repo `crowbar`, workflow `release.yml`, environment `pypi`). To publish an existing release to a registry switched on later, run the `release` workflow by hand with that tag (e.g. `gh workflow run release -f tag=v0.1.0`); versions already on a registry are skipped.

## One-time setup (do these once, before the first release)

1. **GitHub** - already pushed to `kushvinth/crowbar` (private). Flip to public when ready.
2. **PyPI**: create the project's Trusted Publisher: project `crowbar-cli`, owner
   `kushvinth`, repo `crowbar`, workflow `release.yml`, environment `pypi`.
3. **npm**: `npm login`; create an automation token; add it as the `NPM_TOKEN`
   Actions secret.
4. **Website (Vercel)**: live. The `crowbar` Vercel project is linked to
   `kushvinth/crowbar` with the root directory set to `website`, so every push
   to `main` redeploys. `crowbar.kushvinth.com` is attached and verified. The
   site is static, so there is no build step.
5. **asciinema** (optional): `asciinema upload website/static/demo.cast` for a
   hosted player link; or `vhs assets/demo.tape` to render `demo.gif` for the README.

## Channels not wired to CI (manual, but cheap)

- **Homebrew**: create a `homebrew-tap` repo, copy `packaging/homebrew/crowbar.rb`,
  fill `url`+`sha256` from the published PyPI sdist → `brew install kushvinth/tap/crowbar`.
- **Nix**: already shippable - `nix run github:kushvinth/crowbar`. Submit to
  nixpkgs later if you want `nix-env -iA`.
- **Claude Code plugin marketplace** (`claude.com/plugins`): submit the repo (it
  ships `.claude-plugin/{plugin,marketplace}.json`, validated by `claude plugin validate`).
- **skills.sh**: connect the GitHub repo (ships `skills/crowbar/SKILL.md`).

## Discovery channels (submit after the packages are live)

Highest ROI first - these are where the exact audience browses:

1. **MCP indexes** (one PR/submission each): the MCP registry (auto from CI),
   [glama.ai/mcp](https://glama.ai/mcp), [smithery.ai](https://smithery.ai/),
   [mcp.so](https://mcp.so/), [pulsemcp.com](https://pulsemcp.com/),
   [mcpservers.org](https://mcpservers.org/), [mcp-get.com](https://mcp-get.com/),
   [cursor.directory](https://cursor.directory/).
2. **Awesome-lists** (one-line PRs): `punkpeye/awesome-mcp-servers`,
   `sbilly/awesome-security`, `hslatman/awesome-threat-intelligence`,
   `agarrharr/awesome-cli-apps`.
3. **Show HN**: *"Show HN: crowbar – offline CVE/exploit intel as an MCP server so your agent stops hallucinating."* Lead with the demo GIF.
4. **Reddit**: r/LocalLLaMA + r/ClaudeAI (agent-grounding angle), then r/netsec +
   r/blueteamsec (triage angle), r/commandline + r/selfhosted (one-file, no-daemon).
5. **Product Hunt**, **lobste.rs** (needs invite), **dev.to**/**hashnode** writeup,
   **X**/**Bluesky**/**LinkedIn** with the GIF. Security newsletters (tldr sec)
   pick up a good HN run on their own.

## Pre-launch checklist (don't overclaim)

- [ ] One real `lite` build is green (`crowbar doctor` ready) on a clean machine.
- [ ] CI green on the public repo, plus a green nightly `upstream` run.
- [ ] README numbers labeled full/extreme; nothing a fresh user can't reproduce.
- [ ] DISCLAIMER + SECURITY linked above the fold.
- [ ] Beta is stated plainly (0.1.0) - set expectations, invite issues.
