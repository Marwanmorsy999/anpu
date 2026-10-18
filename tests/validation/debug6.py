p="D:/anpu/tests/validation/run.sh"
s=open(p).read()
old='''S1=$($PY -c "import json; print(json.load(open('$J1'))['risk_score'])")
S2=$($PY -c "import json; print(json.load(open('$J2'))['risk_score'])")'''
new='''S1=$($PY - "$J1" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['risk_score'])
PY
)
S2=$($PY - "$J2" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['risk_score'])
PY
)'''
s=s.replace(old,new)
open(p,"w").write(s)
print("done")'''
open("D:/anpu/tests/validation/fixrun2.py","w").write(s) # no
PY