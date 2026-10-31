"""ScamShield v2 insight layer: manipulation profile, attacker goal, XAI words, Hindi/Marathi."""
import re, math

MANIP = {
    "Urgency / scarcity": r"urgent|immediately|\bnow\b|today|within \d+|last chance|expires?|final|limited|turant|jaldi",
    "Authority": r"police|cbi|rbi|sbi|hdfc|icici|bank|income tax|customs|court|government|official|trai",
    "Fear / threat": r"block|suspend|arrest|legal|penalty|freez|frozen|terminat|disconnect|\bfine\b",
    "Greed / reward": r"\bwon\b|prize|lottery|cashback|reward|free|bonus|gift|refund|earn|jackpot",
    "False trust": r"dear (customer|user|sir|madam)|congratulations|dear winner|valued",
}
GOALS = [
    ("Steal your OTP / PIN / card details", r"otp|\bpin\b|cvv|card|password|kyc|verify|aadhaar|pan"),
    ("Make you send money", r"\bpay\b|fee|upi|transfer|deposit|rs\.?\s?\d|₹"),
    ("Push you to a fake site or malicious app", r"install|apk|download|click|http|www|bit\.ly"),
    ("Move you to WhatsApp/Telegram/phone to build trust", r"whatsapp|telegram|call|reply|join"),
]
HM = {  # indicator: (Hindi, Marathi)
    "Urgency": ("जल्दबाज़ी का दबाव — ठग सोचने का समय नहीं देते।", "घाई करायला लावले जात आहे — ठग विचार करायला वेळ देत नाहीत."),
    "Prize / reward claim": ("इनाम का लालच — जो इनाम आपने जीता ही नहीं, वह नकली है।", "बक्षिसाचे आमिष — न लावलेली स्पर्धा जिंकणे अशक्य आहे."),
    "Personal info request": ("OTP/पासवर्ड माँगा जा रहा है — बैंक कभी नहीं माँगता।", "OTP/पासवर्ड मागितला जात आहे — बँक कधीही मागत नाही."),
    "Impersonation": ("किसी बैंक/संस्था का नाम इस्तेमाल किया गया है।", "बँक/संस्थेचे नाव वापरले आहे."),
    "Threat / penalty": ("डराया जा रहा है (खाता बंद, गिरफ़्तारी)।", "भीती दाखवली जात आहे (खाते बंद, अटक)."),
    "Payment request": ("पैसे भेजने को कहा जा रहा है।", "पैसे पाठवायला सांगितले जात आहे."),
    "Call to action": ("लिंक/नंबर पर तुरंत कार्रवाई करने को कहा जा रहा है।", "लिंक/नंबरवर लगेच कृती करायला सांगितले जात आहे."),
    "Foreign currency": ("विदेशी मुद्रा ($/€/£) का ज़िक्र — भारत में लेनदेन ₹ में होता है, यह संदिग्ध है।", "परदेशी चलन ($/€/£) — भारतात व्यवहार ₹ मध्ये होतो, हे संशयास्पद आहे."),
    "International phone number": ("विदेशी फ़ोन नंबर — अनजान अंतरराष्ट्रीय नंबर से सावधान रहें।", "परदेशी फोन नंबर — अनोळखी आंतरराष्ट्रीय नंबरपासून सावध रहा."),
    "Suspicious link": ("लिंक संदिग्ध है — उसे न खोलें।", "लिंक संशयास्पद आहे — उघडू नका."),
}
ACT = {
    "HIGH": ("लिंक न खोलें, OTP/PIN किसी को न बताएं, नंबर ब्लॉक करें और 1930 पर रिपोर्ट करें।", "लिंक उघडू नका, OTP/PIN कोणालाही सांगू नका, नंबर ब्लॉक करा आणि 1930 वर तक्रार करा."),
    "MEDIUM": ("सावधान रहें। लिंक न खोलें; बैंक के आधिकारिक ऐप/नंबर से पुष्टि करें।", "सावध रहा. लिंक उघडू नका; बँकेच्या अधिकृत ॲप/नंबरवरून खात्री करा."),
    "LOW": ("ख़तरा कम दिखता है, फिर भी OTP/पासवर्ड किसी को न दें।", "धोका कमी दिसतो, तरीही OTP/पासवर्ड कोणालाही देऊ नका."),
}


def manipulation(text):
    return {k: min(100, 40 * len(re.findall(rx, text, re.I))) for k, rx in MANIP.items()}


def goals(text):
    return [g for g, rx in GOALS if re.search(rx, text, re.I)]


STOP = set('the and you your for with this that are was have has from will can not but all our out any one get let its via'.split())


def top_words(model, text, n=5):
    """Words that pushed the Naive Bayes model toward 'scam' (log-likelihood ratio)."""
    if hasattr(model, "explain"):
        return model.explain(text, n)
    if not hasattr(model, "c"):
        return []
    out = []
    for w in set(re.findall(r"[a-z0-9₹']+", text.lower())):
        if len(w) < 3 or w in STOP or model.c[0][w] + model.c[1][w] == 0:
            continue
        llr = math.log((model.c[1][w] + 1) / (model.tot[1] + model.v)) - math.log((model.c[0][w] + 1) / (model.tot[0] + model.v))
        if llr > 0.3:
            out.append((w, round(llr, 2)))
    return sorted(out, key=lambda x: -x[1])[:n]


def translate(r, lang):
    if lang == "en":
        return None
    k = 0 if lang == "hi" else 1
    lines = [HM[n][k] for n in r["indicators"] if n in HM]
    return lines or [("कोई संदिग्ध संकेत नहीं मिला।", "कोणतेही संशयास्पद संकेत आढळले नाहीत.")[k]], ACT[r["level"]][k]
