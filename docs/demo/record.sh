#!/bin/sh
# Exact recipe used to record docs/demo/scan.cast (see that file's header).
# Re-run inside the same container setup to reproduce the recording:
#
#   docker run --rm \
#     -v "$PWD/docs/demo/record.sh:/demo/run.sh:ro" \
#     -v "$PWD/tests/bench/server.py:/demo/server.py:ro" \
#     -v "$PWD/dist-anpu-linux:/demo/anpu:ro" \
#     -v "$PWD/docs/demo:/demo/out" \
#     python:3.13-slim bash -c \
#       "pip install -q asciinema && asciinema rec --overwrite \
#         --cols 100 --rows 30 --idle-time-limit 5 \
#         --title 'ANPU advanced scan vs fixture' \
#         -c 'sh /demo/run.sh' /demo/out/scan.cast"
#
# Idle gaps are compressed to 5s max (asciinema --idle-time-limit);
# every byte of terminal output is from the real scan.
set -eu
cd /demo
./anpu --version
python server.py 8901 &
SRV=$!
sleep 2
ANPU_ALLOW_LOCAL_NETWORK=1 ./anpu scan http://127.0.0.1:8901 \
  --profile advanced --json --html=false --sarif=false \
  --output ./demo-reports
kill $SRV || true
