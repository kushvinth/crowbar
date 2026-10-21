#!/usr/bin/env python3
"""Smoke-test an *installed* crowbar (wheel, sdist, nix, docker), not the checkout.

    python3 scripts/smoke.py <crowbar-bin> <crowbar-mcp-bin> [expected-home]

Checks --version, that the index root is ~/.crowbar (an installed package must
never write into site-packages or the nix store), and an MCP handshake:
initialize, tools/list, and cb_stats answering "no index" on an empty home.
Stdlib only; run it with a different interpreter than the one under test.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys


def main() -> int:
    cli, mcp = sys.argv[1], sys.argv[2]
    want_home = pathlib.Path(
        sys.argv[3] if len(sys.argv) > 3 else pathlib.Path.home() / ".crowbar"
    )
    env = dict(os.environ, CROWBAR_NO_AUTO_UPDATE="1")
    env.pop("CROWBAR_HOME", None)

    ver = subprocess.run(
        [cli, "--version"], capture_output=True, text=True, env=env, check=True
    )
    assert ver.stdout.startswith("crowbar "), ver.stdout
    where = json.loads(
        subprocess.run(
            [cli, "where", "--json"],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        ).stdout
    )
    assert pathlib.Path(where["home"]) == want_home, (
        f"home {where['home']} != {want_home}"
    )

    msgs = "".join(
        json.dumps(m) + "\n"
        for m in (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "cb_stats", "arguments": {}},
            },
        )
    )
    res = subprocess.run(
        [mcp], input=msgs, capture_output=True, text=True, env=env, timeout=60
    )
    out = {r["id"]: r for r in map(json.loads, res.stdout.splitlines()) if r.get("id")}
    assert out[1]["result"]["serverInfo"]["name"] == "crowbar", out.get(1)
    tools = {t["name"] for t in out[2]["result"]["tools"]}
    assert {"cb_stats", "cb_cve", "cb_product", "cb_search"} <= tools, tools
    # an empty home has no index; the server must say so instead of crashing
    assert "no index" in json.dumps(out[3]), out[3]
    print(
        f"smoke ok: {ver.stdout.strip()} · home {where['home']} · {len(tools)} MCP tools"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
