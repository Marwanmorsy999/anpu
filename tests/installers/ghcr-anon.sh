#!/bin/sh
# Anonymous ghcr.io pull proof: no credentials anywhere in this script.
set -u
TOKEN=$(curl -fsS "https://ghcr.io/token?scope=repository:marwanmorsy999/anpu:pull" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "token-len=${#TOKEN} (empty means anonymous token fetch failed)"
for TAG in v0.5.2 latest; do
  CODE=$(curl -s -o /tmp/ghcr-manifest.json -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.oci.image.index.v1+json" "https://ghcr.io/v2/marwanmorsy999/anpu/manifests/$TAG")
  echo "manifest-$TAG-http=$CODE"
done
head -c 300 /tmp/ghcr-manifest.json; echo
