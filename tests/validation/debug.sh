#!/usr/bin/env bash
set -x
ROOT=/d/anpu
PORT=18234
REPORTS=/tmp/valdbg
rm -rf "$REPORTS"; mkdir -p "$REPORTS/safe" "$REPORTS/safe2"
ANPU_ALLOW_LOCAL_NETWORK=1 "$ROOT/anpu" scan "http://127.0.0.1:$PORT/" --profile safe --json --output "$REPORTS/safe" >/dev/null
find "$REPORTS/safe" -type f
J1=$(find "$REPORTS/safe" -name '*.json' | head -n1)
echo "J1=$J1"
ls -l "$J1"