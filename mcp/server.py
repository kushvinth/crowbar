#!/usr/bin/env python3
"""crowbar MCP server (stdio). Kept at this path for existing opencode configs."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from crowbar.mcp import serve  # noqa: E402

if __name__ == "__main__":
    serve()
