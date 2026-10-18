p="D:/anpu/tests/validation/run.sh"
s=open(p).read()
idx=s.index("# determinism")
head=s[:idx].rstrip()+"\n"
tail='''# determinism: run again and compare score
"$BIN" scan "http://127.0.0.1:$PORT/" --profile safe --json --output "$REPORTS/safe2" >/dev/null
J1=$(find "$REPORTS/safe" -name '*.json' | head -n1)
J2=$(find "$REPORTS/safe2" -name '*.json' | head -n1)
S1=$($PY -c "import json; print(json.load(open('$J1'))['risk_score'])")
S2=$($PY -c "import json; print(json.load(open('$J2'))['risk_score'])")
if [ "$S1" != "$S2" ]; then echo "FAIL: non-deterministic score $S1 vs $S2"; exit 1; fi
echo "deterministic score: $S1"
echo "VALIDATION OK"
'''
open(p,"w").write(head+tail)
print("done")
