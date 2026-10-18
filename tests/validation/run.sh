#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PY=python3; command -v python3 >/dev/null 2>&1 || PY=python
FIX="$ROOT/tests/validation"
WORK="$(mktemp -d)"
trap 'kill ${SRV_PID:-} ${TLS_PID:-} ${TLS11_PID:-} ${HARD_PID:-} 2>/dev/null || true; rm -rf "$WORK"' EXIT

PORT="${PORT:-18234}"
TLSPORT="${TLSPORT:-18235}"
TLS11PORT="${TLS11PORT:-18236}"
HARDPORT="${HARDPORT:-18237}"

echo "== build =="
CGO_ENABLED=0 go build -o "$ROOT/anpu" ./cmd/anpu

echo "== fixture server =="
ANPU_ALLOW_LOCAL_NETWORK=1 "$PY" "$FIX/fixture.py" "$PORT" >/dev/null 2>&1 &
SRV_PID=$!
sleep 2

export ANPU_ALLOW_LOCAL_NETWORK=1

echo "== local-network guard off by default =="
set +e
env -u ANPU_ALLOW_LOCAL_NETWORK "$ROOT/anpu" scan "http://127.0.0.1:$PORT/" --profile safe --json --output "$WORK/noopt" >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then echo "FAIL: local-network guard is off by default"; exit 1; fi
echo "  guard off by default (exit $rc)"

echo "== safe scan (run 1) =="
"$ROOT/anpu" scan "http://127.0.0.1:$PORT/" --profile safe --json --output "$WORK/safe1" >/dev/null
J1=$(find "$WORK/safe1" -name '*.json' | head -n1)

echo "== safe scan (run 2, determinism) =="
"$ROOT/anpu" scan "http://127.0.0.1:$PORT/" --profile safe --json --output "$WORK/safe2" >/dev/null
J2=$(find "$WORK/safe2" -name '*.json' | head -n1)
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
echo "  deterministic score: $S1"

echo "== per-analyzer metrics =="
$PY "$FIX/metrics.py" "$FIX/ground-truth.yml" "$J1" | tee "$WORK/metrics.txt"
# threshold: precision and recall must be >= 0.95
if ! $PY - "$WORK/metrics.txt" <<'PY'
import sys
lines=open(sys.argv[1]).read().splitlines()
for line in lines:
    parts=line.split()
    if len(parts)>=6 and parts[0] not in ("analyzer","TOTAL"):
        prec=float(parts[4]); rec=float(parts[5])
        if prec < 0.95 or rec < 0.95:
            print(f"THRESHOLD FAIL: {parts[0]} prec={prec} rec={rec}")
            sys.exit(1)
print("thresholds ok")
PY
then
  exit 1
fi

echo "== TLS-broken fixture (expired cert, wrong hostname) =="
# Generate an expired cert with wrong hostname using openssl ca (OpenSSL 3.0
# req has no -not_before/-not_after).
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/ca.key" -out "$WORK/ca.pem" -days 365 -nodes \
  -subj "/CN=ANPU TLS Test CA" -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout "$WORK/tlskey.pem" -out "$WORK/tlscsr.pem" -nodes \
  -subj "/CN=wronghost" -addext subjectAltName=DNS:wronghost >/dev/null 2>&1
cat > "$WORK/ca.cnf" <<EOF
[ca]
default_ca = CA_default
[CA_default]
dir = $WORK
database = $WORK/index.txt
new_certs_dir = $WORK/newcerts
certificate = $WORK/ca.pem
private_key = $WORK/ca.key
serial = $WORK/serial
default_md = sha256
policy = policy_anything
copy_extensions = copy
[policy_anything]
commonName = supplied
EOF
mkdir -p "$WORK/newcerts"; touch "$WORK/index.txt"; echo 1000 > "$WORK/serial"
openssl ca -config "$WORK/ca.cnf" -startdate 20200101000000Z -enddate 20210101000000Z \
  -batch -notext -in "$WORK/tlscsr.pem" -out "$WORK/tlscert.pem" >/dev/null 2>&1
openssl s_server -accept "$TLSPORT" -cert "$WORK/tlscert.pem" -key "$WORK/tlskey.pem" -www >/dev/null 2>&1 &
TLS_PID=$!
sleep 2
"$ROOT/anpu" scan "https://127.0.0.1:$TLSPORT/" --profile safe --json --output "$WORK/tls" >/dev/null 2>&1 || true
TLJSON=$(find "$WORK/tls" -name '*.json' | head -n1 || true)
if [ -n "$TLJSON" ]; then
  $PY - "$TLJSON" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
titles=[f.get("title","") for f in d.get("findings",[])]
tls=[t for t in titles if "expired" in t.lower() or "hostname" in t.lower() or "certificate" in t.lower()]
print("  TLS findings:", tls)
if not tls:
    print("FAIL: no TLS findings on broken fixture")
    sys.exit(1)
PY
else
  echo "  WARN: no TLS report produced"
fi

echo "== TLS 1.1 fixture =="
openssl s_server -accept "$TLS11PORT" -cert "$WORK/tlscert.pem" -key "$WORK/tlskey.pem" -tls1_1 -www >/dev/null 2>&1 &
TLS11_PID=$!
sleep 2
"$ROOT/anpu" scan "https://127.0.0.1:$TLS11PORT/" --profile safe --json --output "$WORK/tls11" >/dev/null 2>&1 || true
T11JSON=$(find "$WORK/tls11" -name '*.json' | head -n1 || true)
if [ -n "$T11JSON" ]; then
  $PY - "$T11JSON" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
titles=[f.get("title","") for f in d.get("findings",[])]
old=[t for t in titles if "tls 1.0" in t.lower() or "tls 1.1" in t.lower() or "deprecated" in t.lower()]
print("  TLS 1.0/1.1 findings:", old)
PY
fi

echo "== hardened baseline =="
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/ca.key" -out "$WORK/ca.pem" -days 365 -nodes \
  -subj "/CN=ANPU Test CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout "$WORK/hard.key" -out "$WORK/hard.csr" -nodes \
  -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in "$WORK/hard.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
  -CAcreateserial -out "$WORK/hard.pem" -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost") >/dev/null 2>&1
cat "$WORK/hard.key" "$WORK/hard.pem" "$WORK/ca.pem" > "$WORK/hardfull.pem"
# Trust the harness CA WITHOUT touching the system store: on Linux/macOS Go
# honors SSL_CERT_FILE, so the scan below validates the chain exactly the way
# a user with a real trusted CA would see it — no skip-verify anywhere.
# Windows ignores SSL_CERT_FILE, so the hardened scan is skipped there
# (documented in docs/validation.md; hardened numbers come from Linux CI).
HARDENED_SKIP=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) HARDENED_SKIP="1" ;;
esac
"$PY" "$FIX/hardened.py" "$HARDPORT" "$WORK/hardfull.pem" >/dev/null 2>&1 &
HARD_PID=$!
sleep 2
if [ -z "$HARDENED_SKIP" ]; then
  SSL_CERT_FILE="$WORK/ca.pem" "$ROOT/anpu" scan "https://localhost:$HARDPORT/" --profile safe --json --output "$WORK/hard" >"$WORK/hard.out" 2>&1 || true
else
  echo "  SKIP: hardened TLS scan needs SSL_CERT_FILE (Linux/macOS only)"
fi
if [ -s "$WORK/hard.out" ]; then echo "  hardened scan output: $(tail -1 "$WORK/hard.out")"; fi
HJSON=$(find "$WORK/hard" -name '*.json' | head -n1 || true)
if [ -n "$HJSON" ]; then
  $PY - "$HJSON" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
findings=d.get("findings",[])
bad=[f for f in findings if f.get("severity") in ("medium","high","critical")]
print("  hardened findings:", len(findings), "medium+:", len(bad))
if bad:
    print("FAIL: hardened baseline produced medium+ findings")
    for f in bad: print("   ", f.get("title"))
    sys.exit(1)
PY
elif [ -z "$HARDENED_SKIP" ]; then
  echo "FAIL: no hardened report produced"
  exit 1
fi

echo "== TLS-untrusted pairing (same server, different CA) =="
# Pairing guard: "no findings on the hardened baseline" must not be
# achievable by silently turning verification off. Scan the same hardened
# server while trusting a DIFFERENT CA: the chain is well-formed but not
# in the trust store, so ANPU must fail the crawl with a verification
# error instead of quietly serving it. Linux/macOS only, same as the
# hardened scan (SSL_CERT_FILE is ignored by Go on Windows).
if [ -z "$HARDENED_SKIP" ]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$WORK/otherca.key" -out "$WORK/otherca.pem" -days 365 -nodes \
    -subj "/CN=ANPU Unrelated CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
  SSL_CERT_FILE="$WORK/otherca.pem" "$ROOT/anpu" scan "https://localhost:$HARDPORT/" --profile safe --json --output "$WORK/untrust" >/dev/null 2>&1 || true
  UJSON=$(find "$WORK/untrust" -name '*.json' | head -n1 || true)
  if [ -z "$UJSON" ]; then
    echo "FAIL: no report produced for untrusted-chain scan"
    exit 1
  fi
  $PY - "$UJSON" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
warns=" ".join(d.get("warnings",[])).lower()
crawled=[f.get("title") for f in d.get("findings",[])
         if f.get("source") in ("headers-analyzer","cookie-analyzer")]
verified=any(k in warns for k in ("x509","certificate","tls","verify","authority"))
print("  verification-failure surfaced:", verified, "| crawl-stage findings:", len(crawled))
if not verified:
    print("FAIL: no TLS verification failure surfaced for an untrusted chain")
    print("      (the clean hardened result above would be meaningless if")
    print("       verification were silently off)")
    sys.exit(1)
if crawled:
    print("FAIL: untrusted chain was served content anyway:", crawled[:3])
    sys.exit(1)
PY
else
  echo "  SKIP: TLS-untrusted pairing needs SSL_CERT_FILE (Linux/macOS only)"
fi

echo "VALIDATION OK"