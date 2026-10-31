"""Merge many public datasets into one training file.
Usage: python build_dataset.py --data a.csv --data b.tsv ... [--synthetic 5000] -> all_data.tsv
Handles headers (label/class/category + text/message/sms) or headerless 'label,text' / UCI tab files.
spam/smishing/scam -> scam; ham/normal/legit -> safe; other labels (e.g. 'promotional') are skipped."""
import argparse, csv, random, re
LAB = {"spam": 1, "smishing": 1, "smish": 1, "scam": 1, "1": 1, "ham": 0, "normal": 0, "legit": 0, "legitimate": 0, "benign": 0, "0": 0}

def rows_from(path):
    raw = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    if not raw: return
    rd = list(csv.reader(raw, delimiter="\t" if "\t" in raw[0] else ","))
    hdr = [h.strip().lower() for h in rd[0]]
    li = next((i for i, h in enumerate(hdr) if h in ("label", "class", "category", "v1")), None)
    ti = next((i for i, h in enumerate(hdr) if h in ("text", "message", "sms", "v2")), None)
    body = rd[1:]
    if li is None or ti is None: li, ti, body = 0, 1, rd
    for r in body:
        if len(r) > max(li, ti):
            l = LAB.get(r[li].strip().lower()); t = re.sub(r"\s+", " ", r[ti]).strip()
            if l is not None and t: yield t, l

ap = argparse.ArgumentParser(); ap.add_argument("--data", action="append", required=True)
ap.add_argument("--synthetic", type=int, default=0, help="extra generated Indian-style messages (augmentation only!)")
a = ap.parse_args(); seen, out, dup = set(), [], 0
for p in a.data:
    for t, l in rows_from(p):
        k = t.lower()
        if k in seen: dup += 1; continue
        seen.add(k); out.append((t, l))
real = len(out)
if a.synthetic:
    import quiz_gen as QG
    n = 0
    while n < a.synthetic:
        for q in QG.generate(8):
            if q["text"].lower() not in seen and n < a.synthetic:
                seen.add(q["text"].lower()); out.append((q["text"], int(q["scam"]))); n += 1
random.Random(1).shuffle(out)
with open("all_data.tsv", "w", encoding="utf-8") as f:
    for t, l in out: f.write(f"{'scam' if l else 'ham'}\t{t.replace(chr(9), ' ')}\n")
print(f"real={real}  synthetic={len(out) - real}  duplicates removed={dup}  scam={sum(l for _, l in out)}  safe={sum(1 - l for _, l in out)}")
print("Wrote all_data.tsv -> python train.py --data all_data.tsv")
