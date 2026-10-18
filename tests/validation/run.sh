#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PORT="${PORT:-18234}"
PY=python3; command -v python3 >/dev/null 2>&1 || PY=python
FIX="$ROOT/tests/validation"
REPORTS="$(mktemp -d)"
trap 'kill ${SRV_PID:-} 2>/dev/null || true; rm -rf "$REPORTS"' EXIT
ANPU_ALLOW_LOCAL_NETWORK=1 "$PY" "$FIX/fixture.py" "$PORT" >/dev/null 2>&1 &
SRV_PID=$!
sleep 2
BIN="$ROOT/anpu"
CGO_ENABLED=0 go build -o "$BIN" ./cmd/anpu
export ANPU_ALLOW_LOCAL_NETWORK=1
# default must be off: scanning loopback without opt-in must fail
set +e
env -u ANPU_ALLOW_LOCAL_NETWORK "$BIN" scan "http://127.0.0.1:$PORT/" --profile safe --json --output "$REPORTS/noopt" >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then echo "FAIL: local-network guard is off by default"; exit 1; fi
echo "local-network guard: off by default (exit $rc)"
# safe scan
"$BIN" scan "http://127.0.0.1:$PORT/" --profile safe --json --output "$REPORTS/safe" >/dev/null
JSON=$(ls "$REPORTS/safe"/*.json | head -1)
$PY - "$JSON" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
titles=[f.get("title","") for f in d.get("findings",[])]
need=["Security headers posture","Cookie \"session\" missing HttpOnly","robots.txt found"]
for n in need:
    if not any(n in t for t in titles):
        print("MISSING:", n); sys.exit(1)
print("safe findings:", len(titles))
PY
# determinism: run again and compare score
"$BIN" scan "http://127.0.0.1:$PORT/" --profile safe --json --output "$REPORTS/safe2" >/dev/null
J1=$(find "$REPORTS/safe" -name '*.json' | head -n1)
J2=$(find "$REPORTS/safe2" -name '*.json' | head -n1)
S1=$($PY - "$J1" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['risk_score'])
PY
)
S2=$($PY - "$J2" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['risk_score'])
PY
)
if [ "$S1" != "$S2" ]; then echo "FAIL: non-deterministic score $S1 vs $S2"; exit 1; fi
echo "deterministic score: $S1"
echo "VALIDATION OK"
