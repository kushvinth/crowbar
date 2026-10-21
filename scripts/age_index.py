"""Make the index look DAYS old, for the auto-update e2e in upstream.yml.

Index age lives in the meta rows a build/update writes with the data
(datasets.index_status), so that is what this rewinds.
"""
from __future__ import annotations

import sqlite3
import sys
import time

sys.path.insert(0, ".")
from crowbar import paths  # noqa: E402

ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - float(sys.argv[1]) * 86400))
con = sqlite3.connect(paths.DB)
con.executemany("INSERT OR REPLACE INTO meta VALUES (?,?)", [("built_at", ts), ("updated_at", ts)])
con.commit()
con.close()
print("aged to", ts)
