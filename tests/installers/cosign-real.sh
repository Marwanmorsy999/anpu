#!/bin/sh
# Real-cosign matrix: verified (>=2.5), warning (2.4.x), negatives. Isolated dirs.
# Portable: REPO defaults to the checkout root (override with ANPU_REPO).
set -u
: "${ANPU_REPO:=$(cd "$(dirname "$0")/../.." && pwd)}"
REPO=$ANPU_REPO
echo "===== SETUP: download real cosign binaries (same run: WSL /tmp is wiped between calls) ====="
mkdir -p /tmp/rcbin-new /tmp/rcbin-old
curl -fsSL -o /tmp/rcbin-new/cosign https://github.com/sigstore/cosign/releases/download/v2.6.1/cosign-linux-amd64
curl -fsSL -o /tmp/rcbin-old/cosign https://github.com/sigstore/cosign/releases/download/v2.4.3/cosign-linux-amd64
chmod +x /tmp/rcbin-new/cosign /tmp/rcbin-old/cosign
test -s /tmp/rcbin-new/cosign || { echo SETUP-FAIL: new cosign empty; exit 99; }
test -s /tmp/rcbin-old/cosign || { echo SETUP-FAIL: old cosign empty; exit 99; }

echo "===== A. which -a + version (new on PATH) ====="
PATH=/tmp/rcbin-new:$PATH which -a cosign
echo "--- cosign version ---"
PATH=/tmp/rcbin-new:$PATH cosign version 2>&1 | grep -E 'GitVersion|GitCommit'

echo
echo "===== B. VERIFIED PATH: real cosign 2.6.1, real v0.5.2 release, isolated dir ====="
rm -rf /tmp/cosign-verified-bin; mkdir -p /tmp/cosign-verified-bin
set +e
PATH=/tmp/rcbin-new:$PATH ANPU_VERSION=v0.5.2 ANPU_INSTALL_DIR=/tmp/cosign-verified-bin sh "$REPO/install.sh" 2>&1
echo "VERIFIED-RC=$?"
set -e
ls -la /tmp/cosign-verified-bin/ 2>/dev/null || echo "(dir listing failed)"

echo
echo "===== C. WARNING PATH: real cosign 2.4.3, isolated dir ====="
rm -rf /tmp/cosign-warn-bin; mkdir -p /tmp/cosign-warn-bin
set +e
PATH=/tmp/rcbin-old:$PATH ANPU_VERSION=v0.5.2 ANPU_INSTALL_DIR=/tmp/cosign-warn-bin sh "$REPO/install.sh" 2>&1
echo "WARNING-RC=$?"
set -e
ls -la /tmp/cosign-warn-bin/

echo
echo "===== D. NEGATIVE: new cosign + TAMPERED checksums.txt (must abort) ====="
rm -rf /tmp/neg-tamper /tmp/neg-tamper-bin; mkdir -p /tmp/neg-tamper/v0.5.2 /tmp/neg-tamper-bin
curl -fsSL https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz -o /tmp/neg-tamper/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz
curl -fsSL https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.2/checksums.txt -o /tmp/neg-tamper/v0.5.2/checksums.txt
curl -fsSL https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.2/checksums.txt.sigstore.json -o /tmp/neg-tamper/v0.5.2/checksums.txt.sigstore.json
test -s /tmp/neg-tamper/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz || { echo NEG-SETUP-FAIL: tarball empty; exit 99; }
test -s /tmp/neg-tamper/v0.5.2/checksums.txt || { echo NEG-SETUP-FAIL: sums empty; exit 99; }
W0=$(awk '$2 == "anpu_0.5.2_linux_amd64.tar.gz" {print $1}' /tmp/neg-tamper/v0.5.2/checksums.txt)
G0=$(sha256sum /tmp/neg-tamper/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz | awk '{print $1}')
echo "NEG-BASELINE published=$W0 clean=$G0 match=$([ "$W0" = "$G0" ] && echo yes || echo NO)"
python3 - /tmp/neg-tamper/v0.5.2/checksums.txt <<'PYEOF'
import re, sys
p = sys.argv[1]
data = open(p, encoding="utf-8").read()
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
print("NEG-TAMPER-FIRED first-hex-char-flipped")
PYEOF
python3 -m http.server 8131 --directory /tmp/neg-tamper >/tmp/neg-tamper.log 2>&1 &
NEGPID=$!
sleep 2
set +e
PATH=/tmp/rcbin-new:$PATH ANPU_VERSION=v0.5.2 ANPU_BASE_URL=http://127.0.0.1:8131 ANPU_INSTALL_DIR=/tmp/neg-tamper-bin sh "$REPO/install.sh" 2>&1
echo "NEG-TAMPER-RC=$?"
set -e
grep -q 'GET /v0.5.2/checksums.txt' /tmp/neg-tamper.log && echo "NEG-EVIDENCE installer fetched tampered checksums.txt from local server" || echo "NEG-FAIL: never fetched tampered file"
test ! -e /tmp/neg-tamper-bin/anpu && echo "NEG-OK nothing installed" || echo "NEG-FAIL: binary installed despite tamper"
kill $NEGPID 2>/dev/null || true

echo
echo "===== E. NEGATIVE: new cosign + WRONG identity (must abort, not skip) ====="
rm -rf /tmp/neg-id /tmp/neg-id-bin; mkdir -p /tmp/neg-id /tmp/neg-id-bin
curl -fsSL https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.2/anpu_0.5.2_linux_amd64.tar.gz -o /tmp/neg-id/anpu_0.5.2_linux_amd64.tar.gz
curl -fsSL https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.2/checksums.txt -o /tmp/neg-id/checksums.txt
curl -fsSL https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.2/checksums.txt.sigstore.json -o /tmp/neg-id/checksums.txt.sigstore.json
/tmp/rcbin-new/cosign verify-blob --bundle /tmp/neg-id/checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Marwanmorsy999/anpu/\.github/workflows/WRONG-WORKFLOW\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  /tmp/neg-id/checksums.txt 2>&1
echo "WRONG-IDENTITY-RC=$? (expect non-zero: real cosign rejects the forged identity)"
