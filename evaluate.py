"""Evaluation + ablation: rules-only vs ML-only vs hybrid.
Usage: python evaluate.py --data SMSSpamCollection   (tab or comma separated: label,text)
Best: also run on YOUR OWN labelled Indian-message CSV (anonymised) - that is your original dataset."""
import argparse, random
import engine as E

def load(p):
    rows = []
    for line in open(p, encoding="utf-8", errors="ignore"):
        sep = "\t" if "\t" in line else ","
        if sep not in line: continue
        l, t = line.rstrip("\n").split(sep, 1)
        l = l.strip().lower().strip('"')
        if l in ("spam", "scam", "1"): rows.append((t.strip('" '), 1))
        elif l in ("ham", "legit", "0"): rows.append((t.strip('" '), 0))
    return rows

def metrics(y, p):
    tp = sum(a and b for a, b in zip(y, p)); fp = sum((not a) and b for a, b in zip(y, p))
    fn = sum(a and (not b) for a, b in zip(y, p)); tn = len(y) - tp - fp - fn
    pr = tp / (tp + fp) if tp + fp else 0; rc = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0
    return dict(acc=(tp + tn) / len(y), prec=pr, rec=rc, f1=f1, tp=tp, fp=fp, fn=fn, tn=tn)

ap = argparse.ArgumentParser(); ap.add_argument("--data", required=True); ap.add_argument("--seed", type=int, default=42)
a = ap.parse_args()
rows = load(a.data); random.Random(a.seed).shuffle(rows)
cut = int(0.8 * len(rows)); train, test = rows[:cut], rows[cut:]
model = E.PureNB().fit([t for t, _ in train], [l for _, l in train])
y = [l for _, l in test]; res = [E.analyze(t, model) for t, _ in test]
systems = {"Rules only": [r["rule_score"] >= 30 for r in res],
           "ML only (Naive Bayes)": [r["ml_score"] >= 50 for r in res],
           "Hybrid (ScamShield)": [r["score"] >= 30 for r in res]}
print(f"train={len(train)} test={len(test)}\n{'System':24}{'Acc':>7}{'Prec':>7}{'Rec':>7}{'F1':>7}   TP/FP/FN/TN")
for n, p in systems.items():
    m = metrics(y, p); print(f"{n:24}{m['acc']:7.3f}{m['prec']:7.3f}{m['rec']:7.3f}{m['f1']:7.3f}   {m['tp']}/{m['fp']}/{m['fn']}/{m['tn']}")
