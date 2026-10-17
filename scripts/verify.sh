#!/usr/bin/env bash
# verify.sh — cross-platform live verification for ANPU.
#
# Builds the binary, serves a local fixture over loopback (ANPU's
# local-network guard is lifted only for this operator-controlled target),
# runs a safe-profile scan, and confirms the documented outputs and
# commands actually work: HTML/JSON/SARIF files, history storage, diff,
# and the --fail-on CI gate. Exit non-zero on any failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY=python3; command -v python3 >/dev/null 2>&1 || PY=python
GOOS_GO="$(go env GOOS)"
if [ "$GOOS_GO" = "windows" ]; then BIN="$ROOT/anpu.exe"; else BIN="$ROOT/anpu"; fi
PORT="${PORT:-18120}"
FIX="$(mktemp -d)"
REPORTS="$FIX/reports"
mkdir -p "$REPORTS"

cleanup() { [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true; rm -rf "$FIX"; }
trap cleanup EXIT

echo "== build =="
CGO_ENABLED=0 go build -o "$BIN" ./cmd/anpu

echo "== fixture server =="
printf '<html><head><title>t</title></head><body>home <a href="/requirements.txt">reqs</a></body></html>' > "$FIX/index.html"
printf 'Django==3.2.0\n' > "$FIX/requirements.txt"
ANPU_ALLOW_LOCAL_NETWORK=1 "$PY" -m http.server "$PORT" --bind 127.0.0.1 --directory "$FIX" >/dev/null 2>&1 &
SRV_PID=$!
sleep 2

export ANPU_ALLOW_LOCAL_NETWORK=1
TARGET="http://127.0.0.1:$PORT/"
fail() { echo "FAIL: $1"; exit 1; }
newest_id() { "$BIN" history | awk 'NR==2 {print $1}'; }

echo "== safe scan: HTML/JSON/SARIF =="
"$BIN" scan "$TARGET" --profile safe --json --sarif --html --output "$REPORTS" >/dev/null
ls "$REPORTS"/*.html >/dev/null 2>&1 || fail "no HTML report"
ls "$REPORTS"/*.json >/dev/null 2>&1 || fail "no JSON report"
ls "$REPORTS"/*.sarif >/dev/null 2>&1 || fail "no SARIF report"
echo "  html/json/sarif written"

echo "== history =="
"$BIN" history | grep -q "$TARGET" || fail "scan not listed in history"
OLD="$(newest_id)"
echo "  history lists the scan ($OLD)"

echo "== diff =="
"$BIN" scan "$TARGET" --profile safe --json --output "$REPORTS" >/dev/null
NEW="$(newest_id)"
"$BIN" diff "$OLD" "$NEW" >/dev/null || fail "diff failed"
echo "  diff $OLD -> $NEW OK"

echo "== --fail-on gate =="
set +e
"$BIN" scan "$TARGET" --profile safe --json --fail-on low --output "$REPORTS" >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "--fail-on low should exit non-zero"
echo "  --fail-on low exits $code (non-zero)"

echo "VERIFY OK"
