import json,re
text=open('D:/anpu/tests/validation/ground-truth.yml').read()
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
actual=json.load(open('D:/DevCache/Temp/opencode/valreports/127.0.0.1-2026-10-18-042830.json'))
titles=[f.get("title","") for f in actual.get("findings",[])]
for exp in expected:
    hit = any(exp.lower() in t.lower() for t in titles)
    print(repr(exp), hit)
print("titles:")
for t in titles: print(" -", t)