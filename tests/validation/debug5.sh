#!/usr/bin/env bash
J=$(find /tmp/valdbg/safe -name '*.json' | head -n1)
echo "J=$J"
python - "$J" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['risk_score'])
PY