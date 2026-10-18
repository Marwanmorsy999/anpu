p="D:/anpu/tests/validation/run.sh"
s=open(p).read()
s=s.replace('S1=$($PY -c', 'ls -l "$J1" >&2\nS1=$($PY -c')
open(p,"w").write(s)
print("done")