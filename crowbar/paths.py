"""Path resolution for a relocatable harness (local disk, symlink, or USB drive)."""
from __future__ import annotations

import os
import pathlib
from datetime import date

# Resolve through symlinks so `.crowbar/bin/crowbar` still finds the real corpus root.
_REAL = pathlib.Path(__file__).resolve().parents[1]
# A source checkout keeps its corpus beside the code. An installed package (pip,
# uvx, nix) sits in site-packages or a read-only store, so it uses ~/.crowbar.
_DEFAULT = _REAL if (_REAL / "bin" / "crowbar").exists() else pathlib.Path.home() / ".crowbar"
ROOT = pathlib.Path(os.environ.get("CROWBAR_HOME") or _DEFAULT).expanduser()

DATA = ROOT / "data"
INDEX = ROOT / "index"
DB = INDEX / "crowbar.db"
MANIFEST = INDEX / "manifest.json"
STATE = INDEX / "state.json"
SKILL = ROOT / "skills" / "crowbar"
HOME_LINK = pathlib.Path.home() / ".crowbar"
DRIVE_MARKER = ".crowbar-drive"

SCHEMA_VERSION = 4
FIRST_YEAR = 2002
YEARS = list(range(FIRST_YEAR, date.today().year + 1))


def ensure_dirs() -> None:
    INDEX.mkdir(parents=True, exist_ok=True)


def is_drive_root() -> bool:
    return (ROOT / DRIVE_MARKER).exists()


def state() -> dict:
    import json

    if STATE.exists():
        try:
            return json.loads(STATE.read_text())
        except json.JSONDecodeError:
            pass
    return {}


def save_state(**kw) -> None:
    import json

    cur = state()
    cur.update(kw)
    ensure_dirs()
    STATE.write_text(json.dumps(cur, indent=2, sort_keys=True) + "\n")
