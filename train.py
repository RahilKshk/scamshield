# pyright: reportMissingImports=false  (scikit-learn is only needed where you TRAIN, e.g. Colab)
"""Train the ScamShield 'brain' -> model.json  (run in Google Colab, or locally if sklearn works).
Usage: python train.py --data SMSSpamCollection --data my_indian_messages.csv
Each file: one message per line, 'label<TAB or comma>text', label = spam/scam/1 or ham/0."""
import argparse, json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

def load(p):
    rows = []
    for line in open(p, encoding="utf-8", errors="ignore"):
        sep = "\t" if "\t" in line else ","
        if sep not in line: continue
        l, t = line.rstrip("\n").split(sep, 1); l = l.strip().lower().strip('"')
        if l in ("spam", "scam", "1"): rows.append((t.strip('" '), 1))
        elif l in ("ham", "legit", "0"): rows.append((t.strip('" '), 0))
    return rows

ap = argparse.ArgumentParser(); ap.add_argument("--data", action="append", required=True)
ap.add_argument("--min_df", type=int, default=2); a = ap.parse_args()
rows = [r for p in a.data for r in load(p)]; X = [t for t, _ in rows]; y = [l for _, l in rows]
print(f"{len(rows)} messages, {sum(y)} scam / {len(y) - sum(y)} safe")
mk = lambda: (TfidfVectorizer(ngram_range=(1, 2), min_df=a.min_df, sublinear_tf=True, token_pattern=r"[\w\u0900-\u097F]{2,}", max_features=30000),
              LogisticRegression(C=5, max_iter=1000, class_weight="balanced"))
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
v, c = mk(); c.fit(v.fit_transform(Xtr), ytr)
print(classification_report(yte, c.predict(v.transform(Xte)), target_names=["safe", "scam"], digits=3))
v, c = mk(); c.fit(v.fit_transform(X), y)          # ship the model trained on ALL data
json.dump({"vocab": {k: int(i) for k, i in v.vocabulary_.items()}, "idf": [float(x) for x in v.idf_],
           "coef": [float(x) for x in c.coef_[0]], "b": float(c.intercept_[0])}, open("model.json", "w"), ensure_ascii=False)
print("Saved model.json - put it next to app.py")
