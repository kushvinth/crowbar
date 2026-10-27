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
        recover_journal(paths.DB)
        con = sqlite3.connect(ro_uri(paths.DB), uri=True, timeout=30)
        con.execute("PRAGMA query_only=ON")
        con.execute("PRAGMA mmap_size=268435456")   # per-connection read speedups, safe read-only
        con.execute("PRAGMA cache_size=-65536")
    else:
        con = sqlite3.connect(paths.DB, timeout=60)
    con.row_factory = sqlite3.Row
    return con


def recover_journal(path) -> None:
    """A writer killed mid-transaction leaves a hot `-journal`, which a mode=ro open
    cannot roll back. One read-write open does; SQLite only rolls back a journal
    nobody still holds a lock on. Errors (read-only media, locked) are ignored."""
    if not path.with_name(path.name + "-journal").exists():
        return
    try:
        w = sqlite3.connect(path, timeout=5)
        w.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
        w.close()
    except sqlite3.Error:
        pass


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


def schema_error(con: sqlite3.Connection) -> str | None:
    """Why this crowbar cannot read the index, or None. No schema migrates in place since v4."""
    v = schema_version(con)
    if v == paths.SCHEMA_VERSION:
        return None
    return f"index schema v{v} != v{paths.SCHEMA_VERSION} - run: crowbar build"


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


CVE_FLAGS = ("cve_with_epss", "cve_kev", "cve_with_exploit", "cve_with_nuclei", "cve_with_msf")


def flag_counts(con: sqlite3.Connection) -> dict:
    """The cve coverage counts: written to stats.json by build/update, live fallback in stats()."""
    row = con.execute("SELECT count(epss), coalesce(sum(kev=1),0), coalesce(sum(has_exploit=1),0),"
                      " coalesce(sum(has_nuclei=1),0), coalesce(sum(has_msf=1),0) FROM cve").fetchone()
    return dict(zip(CVE_FLAGS, row))
