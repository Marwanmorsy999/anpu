#!/bin/sh
# Build a PATH directory that mirrors the current PATH but excludes curl.
#
# Usage: sh scripts/ci/nocurl-path.sh [DIR]
#
# Prints the directory on stdout. The directory holds one symlink per
# executable found on PATH (except curl), so an installer run can be
# exercised on a wget-only system without touching system binaries.
#
# Exits non-zero if curl leaked into the directory or if wget is missing:
# a "wget-only" test that still has curl on PATH would prove nothing.
set -u

DIR=${1:-/tmp/anpu-nocurl-path}

rm -rf "$DIR"
mkdir -p "$DIR"

printf '%s' "$PATH" | tr ':' '\n' | while IFS= read -r d; do
  [ -n "$d" ] || d=.
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    [ -x "$f" ] || continue
    b=${f##*/}
    if [ "$b" = "curl" ]; then
      continue
    fi
    if [ -e "$DIR/$b" ]; then
      continue
    fi
    ln -s "$f" "$DIR/$b" 2>/dev/null || true
  done
done

if [ -e "$DIR/curl" ]; then
  echo "nocurl-path: curl leaked into $DIR" >&2
  exit 1
fi
if [ ! -e "$DIR/wget" ]; then
  echo "nocurl-path: wget missing from $DIR" >&2
  exit 1
fi

printf '%s\n' "$DIR"
