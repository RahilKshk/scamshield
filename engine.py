"""ScamShield engine: rules + URL analysis + ML + SQLite history."""
import re, html, sqlite3, time
from urllib.parse import urlparse
import math, json
from collections import Counter

class PureNB:
    """Pure-Python Naive Bayes fallback (no compiled libraries needed)."""
    def _tok(self, t):
        w = re.findall(r"[a-z0-9₹']+", t.lower())
        return w + [a + "_" + b for a, b in zip(w, w[1:])]

    def fit(self, X, y):
        self.c = {0: Counter(), 1: Counter()}
        self.n = Counter(y)
        for t, l in zip(X, y):
            self.c[l].update(self._tok(t))
        self.v = len(set(self.c[0]) | set(self.c[1])) + 1
        self.tot = {k: sum(self.c[k].values()) for k in (0, 1)}
        return self

    def predict_proba(self, X):
        out = []
        for t in X:
            s = {}
            for k in (0, 1):
                lp = math.log(self.n[k] / sum(self.n.values()))
                for w in self._tok(t):
                    lp += math.log((self.c[k][w] + 1) / (self.tot[k] + self.v))
                s[k] = lp
            m = max(s.values())
            e = {k: math.exp(v - m) for k, v in s.items()}
            z = e[0] + e[1]
            out.append([e[0] / z, e[1] / z])
        return out

# ---------- Rule indicators: name -> (regex, weight) ----------
INDICATORS = {
    "Urgency": (r"\b(urgent(ly)?|immediately|right now|within \d+ ?(hours?|hrs?|minutes?|mins?)|last chance|expires? (today|soon)|act now|final notice|turant|jaldi)\b", 20),
    "Prize / reward claim": (r"\b(congratulations|you(?:'ve| have)? won|winner|lottery|prize|cashback|gift card|free (gift|iphone|recharge)|lucky draw|jackpot)\b", 22),
    "Personal info request": (r"\b(otp|password|pin|cvv|card number|aadhaar|aadhar|pan (card|number)|net ?banking|account number|verify your (identity|account|details)|kyc)\b", 25),
    "Impersonation": (r"\b(sbi|hdfc|icici|axis bank|paytm|phonepe|google pay|amazon|flipkart|fedex|dhl|india post|irctc|income tax|rbi|customs|police|cbi|trai|microsoft|apple support)\b", 10),
    "Threat / penalty": (r"\b(suspend(ed)?|blocked|deactivat\w+|legal action|penalty|arrest(ed)?|frozen|terminated|disconnect\w*|will be closed)\b", 20),
    "Payment request": (r"\b(processing|registration|customs|delivery|clearance) (fee|charges?)\b|\b(pay|transfer|send)\b.{0,40}(₹|rs\.?|inr|upi|deposit)|\bcollect request\b", 22),
    "Foreign currency": (r"(?:[$€£]\s?\d|\d\s?[$€£]|\b(?:usd|gbp|eur)\b|\b(?:us )?dollars?\b|\bpounds?\b|\beuros?\b|\busdt\b|\bbitcoin\b|\bbtc\b|\bcrypto(?:currency)?\b)", 18),
    "International phone number": (r"\+(?!91)\d{1,3}[\s-]?\d{5,}", 15),
    "Call to action": (r"\b(click|tap|open|visit|login|log in|download|install|call|whatsapp|reply)\b.{0,30}(link|here|below|now|number|app)", 12),
}

SCAM_TYPES = {
    "Fake KYC / Bank alert": r"kyc|bank|account.{0,20}(block|suspend|freeze)|pan|aadhaar|net ?banking",
    "Lottery / Prize scam": r"lottery|won|winner|prize|lucky draw|jackpot|congratulations",
    "Parcel / Delivery scam": r"parcel|package|courier|delivery|customs|fedex|dhl|india post",
    "Job / Work-from-home fraud": r"job|work from home|part.?time|earn.{0,15}(per day|daily)|telegram|hiring",
    "UPI / Refund scam": r"upi|refund|cashback|collect request|paytm|phonepe|google pay",
    "Authority threat ('digital arrest')": r"police|cbi|arrest|narcotics|trai|cyber ?crime|court|warrant",
}

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy|is\.gd)/[^\s]*"
    r"|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:xyz|top|click|link|info|tk|ml|ga|cf|gq|icu|buzz|live|site|online|vip|cc)\b(?:/[^\s]*)?",
    re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd"}
RISKY_TLDS = {"xyz", "top", "click", "link", "info", "tk", "ml", "ga", "cf", "gq", "icu", "buzz", "live", "site", "online", "vip", "cc"}
BRANDS = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "amazon", "flipkart", "irctc", "fedex", "dhl", "indiapost", "incometax", "google", "apple", "microsoft"]


def clean(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\u200b", "")).strip()


def analyze_url(raw: str) -> dict:
    u = raw if raw.lower().startswith("http") else "http://" + raw
    p = urlparse(u)
    host = (p.hostname or "").lower()
    reasons, score = [], 0
    labels = host.split(".")
    tld = labels[-1] if labels else ""
    base = ".".join(labels[-2:]) if len(labels) >= 2 else host

    def add(pts, msg):
        nonlocal score
        score += pts; reasons.append(msg)

    if host in SHORTENERS or base in SHORTENERS: add(25, "URL shortener hides the real destination")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): add(35, "Uses a raw IP address instead of a domain")
    if tld in RISKY_TLDS: add(20, f"Risky domain ending '.{tld}'")
    if "@" in p.netloc: add(30, "Contains '@' to disguise the real host")
    if host.startswith("xn--") or "xn--" in host: add(30, "Punycode (look-alike characters) domain")
    if raw.lower().startswith("http://"): add(10, "Not using HTTPS")
    if len(labels) > 4: add(15, "Too many subdomains")
    if host.count("-") >= 2: add(15, "Many hyphens in domain")
    for b in BRANDS:
        if b in host and not (base.startswith(b + ".") and tld in ("com", "in", "co")):
            add(30, f"Mentions '{b}' but is not the official domain"); break
    if len(u) > 75: add(8, "Unusually long URL")
    score = min(100, score)
    level = "High" if score >= 50 else "Medium" if score >= 20 else "Low"
    return {"url": raw, "defanged": raw.replace("http", "hxxp").replace(".", "[.]"),
            "score": score, "level": level, "reasons": reasons or ["No obvious red flags"]}


# ---------- ML model (swap TRAIN data for a bigger dataset e.g. SMS Spam Collection) ----------
SCAM = [
    "Congratulations! You won Rs 25,00,000 in KBC lottery. Claim now at http://kbc-win.xyz",
    "URGENT: Your SBI account will be blocked today. Update KYC at bit.ly/sbi-kyc",
    "Your parcel is held at customs. Pay Rs 49 delivery fee at http://india-post-track.top",
    "Dear customer your HDFC netbanking is suspended. Verify PAN and OTP immediately",
    "Earn Rs 5000 per day working from home. Join our Telegram group now",
    "You have a pending refund. Share your UPI PIN to receive money",
    "This is CBI. A case is registered against your Aadhaar. Pay fine or face arrest",
    "Free recharge offer! Click here to claim your cashback before it expires",
    "Your electricity will be disconnected tonight. Call this number and pay immediately",
    "Final notice: income tax refund pending. Login at http://incometax-refund.info with card details",
    "Lucky draw winner! Send processing fee to collect your iPhone prize",
    "Your Amazon account is deactivated. Confirm password at www.amazon-secure-login.top",
    "Part time job offer, earn daily, no experience needed. WhatsApp us now",
    "Paytm KYC expired. Account frozen. Click link to update within 2 hours",
]
HAM = [
    "Hey, are we still meeting for lunch tomorrow at 1?",
    "Your OTP is 482913. Do not share it with anyone. Valid for 10 minutes.",
    "Rs 1,200 debited from A/c XX4521 at Zomato on 12-Sep. Avl bal Rs 8,340.",
    "Your Amazon order has been delivered. Rate your experience in the app.",
    "Meeting rescheduled to 4pm. Please update your calendar.",
    "Happy birthday! Wishing you a great year ahead.",
    "Your train PNR 2145678901 is confirmed. Have a safe journey.",
    "Please find the assignment notes attached. Submit by Friday.",
    "Mom called, please call her back when you're free.",
    "Your appointment with Dr. Mehta is confirmed for Monday 10:30 AM.",
    "Thanks for your payment of Rs 499. Your invoice is available in the app.",
    "Dinner at 8? I'll book the table.",
    "Your monthly statement is ready. Log in to the official app to view it.",
    "Class tomorrow is cancelled due to rain.",
]


class JsonLR:
    """Loads the trained 'brain' (model.json) and predicts in pure Python (no sklearn needed)."""
    def __init__(self, path):
        d = json.load(open(path, encoding="utf-8"))
        self.v, self.idf, self.w, self.b = d["vocab"], d["idf"], d["coef"], d["b"]

    def _x(self, text):
        w = re.findall(r"[\w\u0900-\u097F]{2,}", text.lower())
        tf = Counter(g for g in w + [a + " " + b for a, b in zip(w, w[1:])] if g in self.v)
        x = {g: (1 + math.log(c)) * self.idf[self.v[g]] for g, c in tf.items()}
        n = math.sqrt(sum(s * s for s in x.values())) or 1.0
        return {g: s / n for g, s in x.items()}

    def predict_proba(self, X):
        out = []
        for t in X:
            z = self.b + sum(self.w[self.v[g]] * s for g, s in self._x(t).items())
            p = 1 / (1 + math.exp(-z)); out.append([1 - p, p])
        return out

    def explain(self, text, n=5):
        c = [(g, round(self.w[self.v[g]] * s, 2)) for g, s in self._x(text).items()]
        return sorted([x for x in c if x[1] > 0.02], key=lambda x: -x[1])[:n]


def build_model():
    import os
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.json")
    if os.path.exists(p):
        return JsonLR(p)
    return PureNB().fit(SCAM + HAM, [1] * len(SCAM) + [0] * len(HAM))


# ---------- Main analysis ----------
def _sev(hits, weight):
    return "High" if (hits >= 2 or weight >= 22) else "Medium"


def analyze(text: str, model) -> dict:
    t = clean(text)
    found, spans = {}, []
    rule_score = 0
    for name, (rx, w) in INDICATORS.items():
        ms = list(re.finditer(rx, t, re.I))
        if ms:
            found[name] = {"hits": len(ms), "severity": _sev(len(ms), w), "examples": sorted({m.group(0) for m in ms})[:3]}
            rule_score += w + 4 * (len(ms) - 1)
            spans += [(m.start(), m.end()) for m in ms]

    urls = [analyze_url(u.rstrip(".,)")) for u in dict.fromkeys(URL_RE.findall(t))]
    if urls:
        top = max(u["score"] for u in urls)
        found["Suspicious link"] = {"hits": len(urls), "severity": "High" if top >= 50 else "Medium" if top >= 20 else "Low",
                                    "examples": [u["url"] for u in urls][:3]}
        rule_score += top * 0.6
        for m in URL_RE.finditer(t): spans.append((m.start(), m.end()))

    ml = float(model.predict_proba([t])[0][1]) * 100 if t else 0.0
    score = int(round(min(100, 0.7 * min(100, rule_score) + 0.3 * ml)))
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

    types = {k: len(re.findall(rx, t, re.I)) for k, rx in SCAM_TYPES.items()}
    stype = max(types, key=types.get) if max(types.values()) > 0 and score >= 30 else "No clear scam pattern"

    # highlight
    spans.sort(); merged = []
    for s, e in spans:
        if merged and s <= merged[-1][1]: merged[-1] = (merged[-1][0], max(e, merged[-1][1]))
        else: merged.append((s, e))
    segs, q = [], 0
    for s, e in merged:
        if s > q: segs.append((t[q:s], False))
        segs.append((t[s:e], True)); q = e
    if q < len(t): segs.append((t[q:], False))
    out, pos = [], 0
    for s, e in merged:
        out.append(html.escape(t[pos:s])); out.append(f"<mark style='background:#ffd6d6;border-radius:4px;padding:0 3px'>{html.escape(t[s:e])}</mark>"); pos = e
    out.append(html.escape(t[pos:]))

    bits = [n.lower() for n in found if n not in ("Impersonation",)]
    reason = ("The message shows: " + ", ".join(bits) + ".") if bits else "No strong scam signals were found."
    if level == "LOW": action = "Looks low-risk, but never share OTPs or passwords, and verify via the official app/website if unsure."
    elif level == "MEDIUM": action = "Be careful. Don't click links; confirm with the organization through its official number or app."
    else: action = "Do NOT click any link, reply, or share OTP/PIN/card details. Block the sender and report it."
    return {"score": score, "level": level, "rule_score": int(min(100, rule_score)), "ml_score": int(ml), "indicators": found,
            "urls": urls, "scam_type": stype, "highlighted": "".join(out), "segs": segs, "reason": reason, "action": action}


def report_text(text, r):
    lines = ["SCAMSHIELD REPORT", f"Risk: {r['level']} ({r['score']}%)", f"Type: {r['scam_type']}", "", "Message:", text, "",
             "Indicators: " + (", ".join(r["indicators"]) or "none"), "Reason: " + r["reason"], "Action: " + r["action"], "",
             "Report at: cybercrime.gov.in | Helpline 1930 | Forward scam SMS to 1909"]
    return "\n".join(lines)


# ---------- SQLite history ----------
DB = "scamshield.db"

def _c():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS scans(ts TEXT, snippet TEXT, score INT, level TEXT, stype TEXT)")
    return c

def save_scan(text, r):
    with _c() as c:
        c.execute("INSERT INTO scans VALUES(?,?,?,?,?)", (time.strftime("%Y-%m-%d %H:%M"), text[:80], r["score"], r["level"], r["scam_type"]))

def load_history():
    with _c() as c:
        return c.execute("SELECT ts,snippet,score,level,stype FROM scans ORDER BY rowid DESC LIMIT 200").fetchall()

def clear_history():
    with _c() as c: c.execute("DELETE FROM scans")
