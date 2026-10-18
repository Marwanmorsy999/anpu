import json,re,sys

gt_path, actual_path = sys.argv[1], sys.argv[2]
text = open(gt_path).read()

def section(name):
    m = re.search(r"(?ms)^" + name + r":\s*\n(.*?)(?=^\w|\Z)", text)
    if not m:
        return []
    vals = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if line.startswith("-"):
            vals.append(line.lstrip("-").strip().strip('"').strip("'"))
    return [v for v in vals if v]

analyzers = {}
for m in re.finditer(r"(?ms)^  (\w[\w-]*):\s*\n    expected:\s*\n(.*?)\n    unexpected:\s*\n(.*?)\n", text):
    name = m.group(1)
    exp = [v for v in re.findall(r"-\s+(.+)", m.group(2)) if v]
    exp = [v.strip('"').strip("'") for v in exp]
    analyzers[name] = exp

def analyzer_for(dm, src):
    s = ((src or "") + " " + (dm or "")).lower()
    if "headers" in s or "custom" in s:
        return "headers"
    if "cookie" in s:
        return "cookies"
    if "tls" in s:
        return "tls"
    if "recon" in s:
        return "recon"
    if "endpoint" in s:
        return "endpoints"
    if "tech" in s:
        return "tech"
    if "nuclei" in s or "nuclei" in (src or "").lower():
        return "nuclei"
    if "zap" in s or "zap" in (src or "").lower():
        return "zap"
    return "other"

actual = json.load(open(actual_path))
findings = actual.get("findings", [])

by_analyzer = {}
for f in findings:
    a = analyzer_for(f.get("detectionMethod", ""), f.get("source", ""))
    by_analyzer.setdefault(a, []).append(f.get("title", ""))

rows = []
tp_all = fp_all = fn_all = 0
for a in ["headers", "cookies", "tls", "recon", "endpoints", "tech", "nuclei", "zap"]:
    expected = analyzers.get(a, [])
    titles = by_analyzer.get(a, [])
    tp = sum(1 for e in expected if any(e.lower() in t.lower() for t in titles))
    fn = len(expected) - tp
    fp = sum(1 for t in titles if not any(e.lower() in t.lower() for e in expected))
    prec = tp / (tp + fp) if (tp + fp) else (1.0 if not expected and not titles else 0.0)
    rec = tp / (tp + fn) if (tp + fn) else (1.0 if not expected else 0.0)
    tp_all += tp; fp_all += fp; fn_all += fn
    rows.append((a, tp, fp, fn, prec, rec, len(titles), len(expected)))

print(f"{'analyzer':<10} {'TP':>3} {'FP':>3} {'FN':>3} {'prec':>6} {'rec':>6} {'actual':>7} {'expected':>8}")
for a, tp, fp, fn, prec, rec, nact, nexp in rows:
    print(f"{a:<10} {tp:>3} {fp:>3} {fn:>3} {prec:>6.2f} {rec:>6.2f} {nact:>7} {nexp:>8}")
prec_all = tp_all / (tp_all + fp_all) if (tp_all + fp_all) else 1.0
rec_all = tp_all / (tp_all + fn_all) if (tp_all + fn_all) else 1.0
print(f"{'TOTAL':<10} {tp_all:>3} {fp_all:>3} {fn_all:>3} {prec_all:>6.2f} {rec_all:>6.2f}")
