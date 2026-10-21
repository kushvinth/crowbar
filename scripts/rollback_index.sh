#!/bin/sh
# Restore the pre-merge crowbar index snapshot.
#
# Usage:
#   scripts/rollback_index.sh [snapshot-path]
#
# Default snapshot: index/crowbar.db.snapshot-20261020
# The snapshot was created with an APFS clone (cp -c), so restoring is cheap.
# This script only replaces the DB; code/docs are reverted with git.
set -eu

case "${1:-}" in
    -h|--help)
        sed -n '2,10p' "$0"
        exit 0
        ;;
esac

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SNAP=${1:-"$ROOT/index/crowbar.db.snapshot-20261020"}
DB="$ROOT/index/crowbar.db"

if [ ! -f "$SNAP" ]; then
    echo "rollback: snapshot not found: $SNAP" >&2
    exit 1
fi

TMP="$ROOT/index/crowbar.db.rollback.$$"
trap 'rm -f "$TMP"' EXIT HUP INT TERM

if cp -c "$SNAP" "$TMP" 2>/dev/null; then
    :
else
    cp "$SNAP" "$TMP"
fi

mv "$TMP" "$DB"
trap - EXIT HUP INT TERM

echo "restored: $DB"
shasum -a 256 "$DB"
