#!/bin/sh
# Guard tests for the ANPU_BASE_URL knob in install.sh.
#
#   sh tests/installers/base-url-guard.sh [VERSION]
#
# Every check prints
#   GUARD-CHECK case=<case> check=<name> verdict=<success|failure> <detail>
# and the script exits 0 only when every check passed.
#
#   custom-no-allow  a non-official base URL without a usable cosign and
#                    without ANPU_ALLOW_CUSTOM_BASE_URL=1 must be REFUSED:
#                    non-zero exit, nothing installed, no download started.
#   custom-allowed   the same base URL with ANPU_ALLOW_CUSTOM_BASE_URL=1
#                    must print the non-official-source warning and proceed.
#   default-base     the default (unset) base URL must behave exactly as
#                    before and must NOT print the warning.
#   official-base    the official base URL set explicitly is not "custom"
#                    either: no warning, no refusal.
set -u

VERSION=${1:-v0.5.5}
INSTALL_SH=${INSTALL_SH:-install.sh}
WORK=$(mktemp -d)
PORT=${PORT:-18771}
FAILURES=0

say() { printf '%s\n' "$*"; }

# shellcheck disable=SC2317  # invoked through the EXIT/INT/TERM trap, not called directly
cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM HUP

# A PATH without any cosign, so the "no usable cosign" case is
# deterministic even on a machine that has cosign installed.
CLEAN_PATH=$(printf '%s' "$PATH" | tr ':' '\n' | while IFS= read -r d; do
  [ -n "$d" ] || continue
  if [ -x "$d/cosign" ]; then continue; fi
  printf '%s\n' "$d"
done | tr '\n' ':' | sed 's/:$//')

# --- the hostile source: a fake archive plus a matching checksums.txt ------
mkdir -p "$WORK/www/$VERSION" "$WORK/fake"
printf '#!/bin/sh\necho "anpu version 9.9.9 (FAKE BINARY FROM A NON-OFFICIAL SOURCE)"\n' > "$WORK/fake/anpu"
chmod +x "$WORK/fake/anpu"
TARBALL="anpu_${VERSION#v}_linux_amd64.tar.gz"
tar -czf "$WORK/www/$VERSION/$TARBALL" -C "$WORK/fake" anpu
(cd "$WORK/www/$VERSION" && sha256sum "$TARBALL" > checksums.txt)
say "hostile source serves $TARBALL plus a checksums.txt that matches it:"
sed 's/^/    /' "$WORK/www/$VERSION/checksums.txt"

python3 -m http.server "$PORT" --directory "$WORK/www" >"$WORK/http.log" 2>&1 &
SERVER_PID=$!
i=0
while [ "$i" -lt 30 ]; do
  if curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then break; fi
  i=$((i + 1))
  sleep 1
done
if [ "$i" -ge 30 ]; then
  say "GUARD-ERROR the fixture server never became reachable"
  exit 1
fi

OUT=""
RC=0
INSTALL_DIR=""

run_installer() {
  # run_installer <case-name> [ENV=VALUE ...]
  name=$1
  shift
  INSTALL_DIR="$WORK/install-$name"
  rm -rf "$INSTALL_DIR"
  set +e
  OUT=$(env PATH="$CLEAN_PATH" ANPU_VERSION="$VERSION" ANPU_INSTALL_DIR="$INSTALL_DIR" "$@" sh "$INSTALL_SH" 2>&1)
  RC=$?
  set -e
  printf '%s\n' "$OUT" > "$WORK/$name.out"
  say "--- case $name (exit $RC) ---"
  printf '%s\n' "$OUT" | sed 's/^/    /'
}

check() {
  # check <case> <check-name> <ok|fail> <detail>
  if [ "$3" = "ok" ]; then
    say "GUARD-CHECK case=$1 check=$2 verdict=success $4"
  else
    say "GUARD-CHECK case=$1 check=$2 verdict=failure $4"
    FAILURES=$((FAILURES + 1))
  fi
}

# --- case 1: custom base URL, no allow variable, no cosign ------------------
run_installer custom-no-allow "ANPU_BASE_URL=http://127.0.0.1:$PORT"
if [ "$RC" -ne 0 ]; then
  check custom-no-allow non-zero-exit ok "exit=$RC"
else
  check custom-no-allow non-zero-exit fail "exit=0"
fi
if printf '%s' "$OUT" | grep -q "refusing to install from a non-official source"; then
  check custom-no-allow refusal-message ok "the refusal message was printed"
else
  check custom-no-allow refusal-message fail "no refusal message"
fi
if printf '%s' "$OUT" | grep -q "ANPU_ALLOW_CUSTOM_BASE_URL=1"; then
  check custom-no-allow names-escape-hatch ok "the escape hatch is named"
else
  check custom-no-allow names-escape-hatch fail "the escape hatch is not named"
fi
if printf '%s' "$OUT" | grep -q "anpu installer: downloading "; then
  check custom-no-allow no-download-started fail "a download was started"
else
  check custom-no-allow no-download-started ok "no download was started"
fi
if [ -e "$INSTALL_DIR/anpu" ]; then
  check custom-no-allow nothing-installed fail "a binary was installed"
else
  check custom-no-allow nothing-installed ok "no binary was installed"
fi

# --- case 2: custom base URL with the allow variable -----------------------
run_installer custom-allowed "ANPU_BASE_URL=http://127.0.0.1:$PORT" "ANPU_ALLOW_CUSTOM_BASE_URL=1"
if printf '%s' "$OUT" | grep -q "WARNING: DOWNLOADING FROM A NON-OFFICIAL SOURCE"; then
  check custom-allowed warning-printed ok "the non-official-source warning was printed"
else
  check custom-allowed warning-printed fail "no non-official-source warning"
fi
if printf '%s' "$OUT" | grep -q "do NOT prove the archive"; then
  check custom-allowed warning-explains-risk ok "the warning explains that checksums do not prove authenticity"
else
  check custom-allowed warning-explains-risk fail "the warning does not explain the risk"
fi
if printf '%s' "$OUT" | grep -q "refusing to install from a non-official source"; then
  check custom-allowed not-refused fail "still refused despite the allow variable"
else
  check custom-allowed not-refused ok "not refused"
fi
if [ "$RC" -eq 0 ] && [ -x "$INSTALL_DIR/anpu" ]; then
  check custom-allowed install-proceeds ok "the install proceeded (accepted risk)"
else
  check custom-allowed install-proceeds fail "exit=$RC, the install did not proceed"
fi

# --- case 3: the default base URL is unchanged and prints no warning -------
run_installer default-base
if [ "$RC" -eq 0 ] && [ -x "$INSTALL_DIR/anpu" ]; then
  check default-base install-ok ok "exit=0, the binary was installed"
else
  check default-base install-ok fail "exit=$RC, no binary"
fi
if printf '%s' "$OUT" | grep -q "WARNING: DOWNLOADING FROM A NON-OFFICIAL SOURCE"; then
  check default-base no-warning fail "the warning was printed for the default base URL"
else
  check default-base no-warning ok "no warning"
fi
if printf '%s' "$OUT" | grep -q "verifying checksum"; then
  check default-base checksum-step-present ok "the normal checksum step ran"
else
  check default-base checksum-step-present fail "the checksum step is missing"
fi

# --- case 4: the official base URL set explicitly is not "custom" ----------
run_installer official-base "ANPU_BASE_URL=https://github.com/Marwanmorsy999/anpu/releases/download"
if [ "$RC" -eq 0 ]; then
  check official-base install-ok ok "exit=0"
else
  check official-base install-ok fail "exit=$RC"
fi
if printf '%s' "$OUT" | grep -q "WARNING: DOWNLOADING FROM A NON-OFFICIAL SOURCE"; then
  check official-base no-warning fail "the warning was printed for the official base URL"
else
  check official-base no-warning ok "no warning"
fi

if [ "$FAILURES" -gt 0 ]; then
  say "GUARD-RESULT failures=$FAILURES"
  exit 1
fi
say "GUARD-RESULT failures=0"
exit 0
