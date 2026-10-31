# 🛡️ ScamShield
Explainable scam-message detection for everyday users (rules + URL analysis + Naive Bayes, Hindi/Marathi explanations, manipulation profile, OCR, quiz).

## Run locally (VS Code terminal)
```
python -m venv .venv
.venv\Scripts\activate        # Windows  (Mac/Linux: source .venv/bin/activate)
pip install -r requirements.txt
python -m streamlit run app.py
```
Screenshot OCR runs in the browser (Tesseract.js), so nothing extra to install; it needs internet.

## Deploy free (from GitHub)
1. Push this folder to a GitHub repo.
2. Go to share.streamlit.io, sign in with GitHub, click **New app**, pick the repo and `app.py`.
3. In *Advanced settings* choose Python 3.12, then Deploy.
4. Open the app URL on your phone and use "Add to Home Screen".

## Evaluate
`python evaluate.py --data yourdata.csv`  (rows: `label,text`, label = scam/ham) → rules vs ML vs hybrid.
