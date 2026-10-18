p="D:/anpu/tests/validation/run.sh"
s=open(p).read()
s=s.replace('S1=$($PY -c', 'echo "J1=$J1" >&2\nS1=$($PY -c')
open(p,"w").write(s)
print("done")