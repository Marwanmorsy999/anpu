#!/bin/sh
# SH tamper proof: control + zip-tamper + sums-tamper, each with fired-guards.
# Portable: SUT_SRC defaults to the repo checkout (override with ANPU_SUT_SRC).
set -eu
WORK=/tmp/shproof
rm -rf "$WORK"
mkdir -p "$WORK"
: "${ANPU_SUT_SRC:=$(cd "$(dirname "$0")/../.." && pwd)/install.sh}"
SUT_SRC=$ANPU_SUT_SRC
SUT="$WORK/install.sh"
cp "$SUT_SRC" "$SUT"
chmod +x "$SUT"
echo "SH-SUT=$SUT sha256=$(sha256sum "$SUT" | awk '{print $1}')"
echo "SH-SUT-SRC=$SUT_SRC sha256=$(sha256sum "$SUT_SRC" | awk '{print $1}')"
echo '--- C0 control: clean archive installs ---'
CTRL="$WORK/ctrl-bin"
rm -rf "$CTRL" && mkdir -p "$CTRL"
ANPU_VERSION=v0.5.2 ANPU_INSTALL_DIR="$CTRL" sh "$SUT"
echo "C0-RC=$?"
test -x "$CTRL/anpu"
"$CTRL/anpu" version | grep -q '0\.5\.2'
"$CTRL/anpu" version | grep -q '88d80a5'
echo 'C0 RESULT=PASS (clean install, version proved)'
echo '--- fixtures: download + non-empty guards ---'
TAMPER="$WORK/tamper"
SUMS="$WORK/sums"
rm -rf "$TAMPER" "$SUMS"
mkdir -p "$TAMPER/v0.5.2" "$SUMS/v0.5.2"
curl -fsSL https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz -o "$TAMPER/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz"
curl -fsSL https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.2/checksums.txt -o "$TAMPER/v0.5.2/checksums.txt"
cp "$TAMPER/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz" "$SUMS/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz"
cp "$TAMPER/v0.5.2/checksums.txt" "$SUMS/v0.5.2/checksums.txt"
test -s "$TAMPER/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz" || { echo 'HARNESS-MISFIRE: tarball empty'; exit 99; }
test -s "$TAMPER/v0.5.2/checksums.txt" || { echo 'HARNESS-MISFIRE: sums empty'; exit 99; }
echo 'FIXTURES-NONEMPTY-OK'
echo '--- Case A: corrupt archive (append 1 byte) ---'
B=$(sha256sum "$TAMPER/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz" | awk '{print $1}')
printf x >> "$TAMPER/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz"
A=$(sha256sum "$TAMPER/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz" | awk '{print $1}')
echo "ZIP-TAMPER-FIRED sha-before=$B sha-after=$A"
test "$B" != "$A" || { echo 'HARNESS-MISFIRE: tamper inert'; exit 99; }
echo '--- Case B: mutate 1 hex char of the tarball hash in checksums.txt ---'
W0=$(awk '$2 == "anpu_0.5.2_linux_amd64.tar.gz" {print $1}' "$SUMS/v0.5.2/checksums.txt")
G0=$(sha256sum "$SUMS/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz" | awk '{print $1}')
echo "SUMS-BASELINE published=$W0 clean=$G0"
test "$W0" = "$G0" || { echo 'HARNESS-MISFIRE: clean fixture mismatch'; exit 99; }
echo 'BASELINE-RIGHT-HASH-OK (compares against the right hash)'
# Generic mutation: flip the first hex char of the tarball's hash line (no hardcoded prefix).
python3 - "$SUMS/v0.5.2/checksums.txt" <<'PYEOF'
import re, sys
p = sys.argv[1]
data = open(p, "r", encoding="utf-8").read()
out, changed = [], False
for line in data.splitlines(keepends=True):
    m = re.match(r"^([0-9a-fA-F]{64})(\s+.*)$", line)
    if m and not changed and "anpu_0.5.2_linux_amd64.tar.gz" in line:
        h = m.group(1)
        new = ("0" if h[0] != "0" else "1") + h[1:]
        line = new + m.group(2) + ("\n" if line.endswith("\n") else "")
        changed = True
    out.append(line)
assert changed, "no checksum line matched"
open(p, "w", encoding="utf-8").write("".join(out))
print("SUMS-TAMPER-FIRED first-char-flipped")
PYEOF
W1=$(awk '$2 == "anpu_0.5.2_linux_amd64.tar.gz" {print $1}' "$SUMS/v0.5.2/checksums.txt")
echo "SUMS published-before=$W0 published-after=$W1"
test "$W0" != "$W1" || { echo 'HARNESS-MISFIRE: sums mutation inert'; exit 99; }
echo '--- serve both (access log = proof the installer hit OUR server) ---'
python3 -m http.server 8123 --directory "$TAMPER" >"$WORK/tamper.log" 2>&1 &
PID1=$!
python3 -m http.server 8124 --directory "$SUMS" >"$WORK/sums.log" 2>&1 &
PID2=$!
sleep 2
echo "--- T1: zip-tamper must abort ---"
set +e
TBIN="$WORK/tamper-bin"
rm -rf "$TBIN" && mkdir -p "$TBIN"
OUT1=$(ANPU_VERSION=v0.5.2 ANPU_BASE_URL=http://127.0.0.1:8123 ANPU_INSTALL_DIR="$TBIN" sh "$SUT" 2>&1)
RC1=$?
set -e
echo "$OUT1"
echo "T1-RC=$RC1"
grep -q 'GET /v0.5.2/anpu_0.5.2_linux_amd64.tar.gz' "$WORK/tamper.log" || { echo 'T1 FAIL: installer never fetched our tampered tarball'; exit 1; }
echo 'T1-EVIDENCE installer fetched tampered tarball from local server'
echo "$OUT1" | grep -qi 'FAILED\|mismatch\|did NOT match' || { echo 'T1 FAIL: no mismatch text'; exit 1; }
test "$RC1" -ne 0 || { echo 'T1 FAIL: exit 0'; exit 1; }
test ! -e "$TBIN/anpu" || { echo 'T1 FAIL: binary installed'; exit 1; }
echo "T1 RESULT=PASS (zip tamper exercised, abort pre-install)"
echo '--- T2: sums-tamper must abort ---'
set +e
SBIN="$WORK/sums-bin"
rm -rf "$SBIN" && mkdir -p "$SBIN"
OUT2=$(ANPU_VERSION=v0.5.2 ANPU_BASE_URL=http://127.0.0.1:8124 ANPU_INSTALL_DIR="$SBIN" sh "$SUT" 2>&1)
RC2=$?
set -e
echo "$OUT2"
echo "T2-RC=$RC2"
grep -q 'GET /v0.5.2/checksums.txt' "$WORK/sums.log" || { echo 'T2 FAIL: installer never fetched our tampered checksums.txt'; exit 1; }
echo 'T2-EVIDENCE installer fetched tampered checksums.txt from local server'
echo "$OUT2" | grep -qi 'FAILED\|mismatch\|did NOT match' || { echo 'T2 FAIL: no mismatch text'; exit 1; }
test "$RC2" -ne 0 || { echo 'T2 FAIL: exit 0'; exit 1; }
test ! -e "$SBIN/anpu" || { echo 'T2 FAIL: binary installed'; exit 1; }
kill $PID1 $PID2 2>/dev/null || true
echo "T2 RESULT=PASS (sums tamper exercised, abort pre-install)"
echo '--- server access logs ---'
cat "$WORK/tamper.log" "$WORK/sums.log"
echo 'SH ALL-PASS'
