"""Endless quiz: builds new scam / genuine messages from random templates + slots."""
import random

BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Bank", "PNB", "Bank of Baroda"]
MERCH = ["Swiggy", "Zomato", "Amazon", "Flipkart", "BigBasket", "Uber", "Myntra", "Ola"]
COUR = ["India Post", "FedEx", "DHL", "BlueDart", "Delhivery"]
AGENCY = ["CBI", "Mumbai Cyber Police", "TRAI", "Customs Department", "Narcotics Bureau"]
TLD = ["xyz", "top", "click", "info", "live", "icu"]
WORD = ["kyc", "verify", "secure", "update", "reward", "claim"]
BILLERS = ["Adani Electricity", "Jio", "Airtel", "Tata Power", "MTNL"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
MEALS = ["lunch", "dinner", "coffee", "the movie", "the match"]


def _fake(r, brand): return f"http://{brand.lower().replace(' ', '')}-{r.choice(WORD)}.{r.choice(TLD)}"
def _amt(r, lo, hi): return f"{r.randrange(lo, hi, 50):,}"
def _time(r): return f"{r.randint(1, 12)}:{r.choice(['00', '30'])} {r.choice(['AM', 'PM'])}"


def _scam(r):
    b, c, m = r.choice(BANKS), r.choice(COUR), r.choice(MERCH)
    T = [
        lambda: (f"{b} ALERT: Your account will be blocked in {r.choice([2, 4, 6, 24])} hours. Update KYC now: {_fake(r, b)}",
                 "Banks never fix KYC through links. Urgency + threat + a risky look-alike domain.", "Fake KYC"),
        lambda: (f"Congratulations! You won Rs {_amt(r, 50000, 5000000)} in the {m} lucky draw. Pay Rs {_amt(r, 99, 2000)} fee via UPI to claim.",
                 "You can't win a draw you never entered, and real prizes never need a fee.", "Lottery"),
        lambda: (f"{c}: your parcel is held at customs. Pay Rs {_amt(r, 49, 500)} clearance fee at {_fake(r, c)}",
                 "Couriers don't collect fees through random links. Check the official app.", "Parcel scam"),
        lambda: (f"This is {r.choice(AGENCY)}. Your Aadhaar is linked to a crime. Join the video call now or face arrest.",
                 "No agency arrests anyone over video call. Authority + fear is the 'digital arrest' scam.", "Digital arrest"),
        lambda: (f"Earn Rs {_amt(r, 2000, 9000)} per day working from home. Join our Telegram group: {_fake(r, 'jobs')}",
                 "Easy money for no skills is bait. Real jobs don't recruit through Telegram links.", "Job fraud"),
        lambda: (f"You have a pending refund of Rs {_amt(r, 300, 9000)}. Enter your UPI PIN to receive it.",
                 "You never need your PIN to RECEIVE money. Entering it sends money out.", "UPI scam"),
        lambda: (f"Your {b} reward points worth Rs {_amt(r, 500, 5000)} expire today. Install the rewards app: {_fake(r, b)}.apk",
                 "Reward 'apps' from links carry malware. Urgency + greed + an unofficial download.", "Malicious app"),
        lambda: (f"Hi Mum, I lost my phone, this is my new number. Please send Rs {_amt(r, 2000, 20000)} urgently, I'll explain later.",
                 "Impersonating a family member plus urgency. Call the old number to verify.", "Fake relative"),
        lambda: (f"Your {r.choice(BILLERS)} electricity will be disconnected tonight. Call {r.randint(7, 9)}{r.randint(10**8, 10**9 - 1)} immediately.",
                 "Utilities don't cut power over an SMS 'call now'. Fear + urgency.", "Utility scam"),
        lambda: (f"Congratulations! You won ${r.randrange(1000, 50000, 500):,} in the {m} global draw. Send a small fee to claim.",
                 "A dollar prize on an Indian number? Domestic offers use ₹, and real prizes never need a fee.", "Foreign currency"),
    ]
    return r.choice(T)()


def _legit(r):
    b, m = r.choice(BANKS), r.choice(MERCH)
    T = [
        lambda: (f"Rs {_amt(r, 100, 4000)} debited from A/c XX{r.randint(1000, 9999)} at {m}. Avl bal Rs {_amt(r, 1000, 40000)}. -{b}",
                 "A plain transaction alert: no link, no request, no pressure.", "Genuine"),
        lambda: (f"{r.randint(1000, 9999)}{r.randint(10, 99)} is your OTP for {m}. Do not share it with anyone.",
                 "A genuine OTP. The scam is when someone ASKS you for it.", "Genuine (OTP)"),
        lambda: (f"Your {m} order #{r.randint(10000, 99999)} is out for delivery today.",
                 "Informational, with no link or payment request.", "Genuine"),
        lambda: (f"Reminder: your appointment with Dr. {r.choice(['Mehta', 'Shah', 'Iyer', 'Khan'])} is on {r.choice(DAYS)} at {_time(r)}.",
                 "A routine reminder with nothing to click or pay.", "Genuine"),
        lambda: (f"Class on {r.choice(DAYS)} is shifted to Lab {r.randint(1, 6)}.", "Ordinary message with no scam levers.", "Genuine"),
        lambda: (f"Hey, are we still on for {r.choice(MEALS)} at {_time(r)}?", "A normal chat between friends.", "Genuine"),
        lambda: (f"Your {r.choice(BILLERS)} bill of Rs {_amt(r, 200, 3000)} is due on {r.randint(1, 28)} Nov. Pay in the official app.",
                 "Mentions a due date, but points to the official app, not a link. Tricky, but genuine.", "Genuine (tricky)"),
        lambda: (f"{b} will never ask for your OTP, PIN or CVV. Beware of fraud calls.",
                 "A bank's awareness message. It warns about scams, not performs one.", "Genuine (tricky)"),
    ]
    return r.choice(T)()


def generate(n=8, seed=None):
    r = random.Random(seed)
    scams = n // 2 + r.choice([0, 1]); seen, out = set(), []
    for i in range(n * 6):
        if len(out) == n: break
        is_scam = sum(q["scam"] for q in out) < scams if len(out) - sum(q["scam"] for q in out) >= n - scams else True
        if len(out) - sum(q["scam"] for q in out) < n - scams and sum(q["scam"] for q in out) >= scams: is_scam = False
        text, why, tag = (_scam if is_scam else _legit)(r)
        if text not in seen:
            seen.add(text); out.append({"text": text, "scam": is_scam, "why": why, "tag": tag})
    r.shuffle(out)
    return out
