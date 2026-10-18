import json,re,sys

text=open(sys.argv[1]).read()
def section(name):
    m=re.search(r"(?ms)^"+name+r":\s*\n(.*?)(?=^\w|\Z)", text)
    if not m: return []
    vals=[]
    for line in m.group(1).splitlines():
        line=line.strip()
        if line.startswith("-"):
            vals.append(line.lstrip("-").strip().strip('"').strip("'"))
    return [v for v in vals if v]

expected=section("expected")
unexpected=section("unexpected")
actual=json.load(open(sys.argv[2]))
titles=[f.get("title","") for f in actual.get("findings",[])]

tp=sum(1 for exp in expected if any(exp.lower() in t.lower() for t in titles))
fn=len(expected)-tp
fp=sum(1 for t in titles if not any(exp.lower() in t.lower() for exp in expected))
prec=tp/(tp+fp) if (tp+fp) else 1.0
rec=tp/(tp+fn) if (tp+fn) else 1.0
print(f"TP={tp} FP={fp} FN={fn} precision={prec:.2f} recall={rec:.2f}")