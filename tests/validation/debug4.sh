#!/usr/bin/env bash
J=$(find /tmp/valdbg/safe -name '*.json' | head -n1)
echo "J=$J"
python -c "import json; print(json.load(open('$J'))['risk_score'])"