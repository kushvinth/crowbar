"""SQLite helpers: read-only connections, metadata, schema version."""
from __future__ import annotations

import sqlite3

from . import paths


class NotIndexed(RuntimeError):
    pass


def connect(readonly: bool = True) -> sqlite3.Connection:
    if not paths.DB.exists():
        raise NotIndexed("no index yet - run: crowbar build")
    if readonly:
        con = sqlite3.connect(ro_uri(paths.DB), uri=True, timeout=30)
        con.execute("PRAGMA query_only=ON")
    else:
        con = sqlite3.connect(paths.DB, timeout=60)
    con.row_factory = sqlite3.Row
    return con


def ro_uri(path) -> str:
    """Read-only SQLite URI. as_uri() percent-encodes ?/#/%/spaces (e.g. USB mounts),
    which a bare f-string would misparse as the URI query."""
    return f"{path.resolve().as_uri()}?mode=ro"


def schema_version(con: sqlite3.Connection) -> int:
    try:
        row = con.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
        return int(row[0]) if row else 0
    except sqlite3.DatabaseError:
        return 0


def meta(con: sqlite3.Connection) -> dict:
    try:
        return {r[0]: r[1] for r in con.execute("SELECT key, value FROM meta")}
    except sqlite3.DatabaseError:
        return {}


def counts(con: sqlite3.Connection) -> dict:
    tables = [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE '%_fts%' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    return {t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in tables}
