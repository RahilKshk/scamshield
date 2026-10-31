import html, time, os
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import engine as E
import insight as I
import quiz_gen as QG

HERE = os.path.dirname(os.path.abspath(__file__))
st.set_page_config(page_title="ScamShield", page_icon="🛡️", layout="wide", initial_sidebar_state="auto")
try:
    st.markdown("<style>" + open(os.path.join(HERE, "theme.css"), encoding="utf-8").read() + "</style>", unsafe_allow_html=True)
except FileNotFoundError:
    st.warning("theme.css was not found next to app.py, so the new design cannot load. Copy theme.css into the same folder as app.py and refresh.")

LAB = {"HIGH": ("Scam detected", "#FF5364"), "MEDIUM": ("Suspicious message", "#F5B942"), "LOW": ("Looks safe", "#20D68A")}
SEV = {"High": "#FF5364", "Medium": "#F5B942", "Low": "#20D68A"}
PAGES = [":material/space_dashboard: Dashboard", ":material/forum: Message scanner", ":material/image_search: Screenshot scanner",
         ":material/history: Detection history", ":material/quiz: Spot the scam", ":material/menu_book: Scam guide"]
TIPS = [("Fake KYC and bank alerts", "Banks never ask for OTP, PIN or CVV by SMS or call."),
        ("Lottery and prizes", "You can't win a contest you never entered. Real prizes never need a fee."),
        ("Parcel and delivery", "Track parcels only in the courier's official app."),
        ("Job fraud", "Real employers don't charge registration fees."),
        ("Digital arrest", "No agency arrests anyone over video call. Hang up and call 1930."),
        ("UPI collect requests", "You never need your PIN to receive money.")]
ocr_comp = components.declare_component("ocr", path=os.path.join(HERE, "ocr_component"))


@st.cache_resource
def get_model():
    return E.build_model()


M = get_model()
S = st.session_state          # per-visitor memory: nothing is stored on the server
for k, v in {"hist": [], "last": "", "lastsrc": "", "txt": "", "ocr_text": "", "ocr_empty": False, "best": 0, "rounds": 0, "nav": PAGES[0], "lang": "en"}.items():
    S.setdefault(k, v)


def do_analyze(t, src):
    S.last, S.lastsrc = t, src
    r0 = E.analyze(t, M)
    S.hist.insert(0, {"Time": time.strftime("%d %b %H:%M"), "Message": t[:70], "Score": r0["score"], "Level": r0["level"], "Type": r0["scam_type"]})


def new_round():
    S.qz = QG.generate(8, seed=time.time_ns()); S.rounds += 1; S.qi = 0; S.qs = 0; S.qans = None; S.qstreak = 0


if "qz" not in S:
    new_round()


def head(title, desc):
    eng = "Trained model active" if type(M).__name__ == "JsonLR" else "Built-in model active"
    st.markdown(f"<div class='pagehead'><div><h2>{title}</h2><p>{desc}</p></div><span class='chip'><span class='dot'></span>{eng}</span></div>", unsafe_allow_html=True)


def kpi(label, val, color="#F1F5F9"):
    return f"<div class='kpi'><small>{label}</small><b style='color:{color}'>{val}</b></div>"


def show_result(t):
    r = E.analyze(t, M); lab, c = LAB[r["level"]]; sc = r["score"]
    ring = (f"<svg width='132' height='132' viewBox='0 0 36 36' style='flex:none'><circle cx='18' cy='18' r='15.9155' fill='none' stroke='#263448' stroke-width='3'/>"
            f"<circle cx='18' cy='18' r='15.9155' fill='none' stroke='{c}' stroke-width='3' stroke-linecap='round' stroke-dasharray='{sc} 100' transform='rotate(-90 18 18)'/>"
            f"<text x='18' y='19.6' text-anchor='middle' font-size='8' font-weight='800' fill='{c}'>{sc}%</text>"
            f"<text x='18' y='24.2' text-anchor='middle' font-size='2.4' fill='#94A3B8'>RISK SCORE</text></svg>")
    st.markdown(f"""<div class='card' style='border-color:{c}88;box-shadow:0 0 44px {c}26'><div style='display:flex;gap:22px;align-items:center;flex-wrap:wrap'>{ring}
      <div style='flex:1;min-width:200px'><span class='eyebrow' style='color:{c}'>THREAT ASSESSMENT</span><div style='font-size:1.8rem;font-weight:800;color:{c};line-height:1.15'>{lab}</div>
      <div style='margin-top:4px'>{r["scam_type"]}</div><div style='color:#94A3B8;font-size:.8rem;margin-top:6px'>Rules {r["rule_score"]}% · AI model {r["ml_score"]}% · a heuristic risk score, not a probability</div></div></div></div>""", unsafe_allow_html=True)
    st.markdown(f"<div class='card' style='border-left:4px solid {c}'><b>What to do</b><br><span style='color:#CBD5E1'>{r['action']}</span></div>", unsafe_allow_html=True)
    tr = I.translate(r, S.lang)
    if tr:
        st.markdown("<div class='card'><b>सरल भाषा में / सोप्या भाषेत</b><br>" + "<br>".join("• " + x for x in tr[0]) + f"<br><b>{tr[1]}</b></div>", unsafe_allow_html=True)
    if r["indicators"]:
        st.markdown("".join(f"<span class='pill' style='background:{SEV[d['severity']]}22;color:{SEV[d['severity']]};border-color:{SEV[d['severity']]}55'>{n}</span>" for n, d in r["indicators"].items()), unsafe_allow_html=True)
    else:
        st.success("No scam indicators found.")
    g = I.goals(t)
    if g and sc >= 30:
        st.markdown("<div class='card'><b>What the scammer wants</b><br>" + "<br>".join("→ " + x for x in g) + "</div>", unsafe_allow_html=True)
    with st.expander("Why it's flagged"):
        st.markdown("<div style='line-height:1.9'>" + "".join(f"<mark>{html.escape(s)}</mark>" if hot else html.escape(s) for s, hot in r["segs"]) + "</div>", unsafe_allow_html=True)
        for n, d in r["indicators"].items():
            st.write(f"**{n}** — _{', '.join(d['examples'])}_")
        st.caption(r["reason"])
    with st.expander("Manipulation profile"):
        st.markdown("".join(f"<div style='margin:9px 0'><div style='display:flex;justify-content:space-between;font-size:.85rem'><span>{k}</span><b>{v}%</b></div><div class='bar'><i style='width:{v}%;background:#39C6D8'></i></div></div>" for k, v in I.manipulation(t).items()), unsafe_allow_html=True)
    if r["urls"]:
        with st.expander(f"Link check ({len(r['urls'])})"):
            for u in r["urls"]:
                st.markdown(f"**`{u['defanged']}`** · {u['level']} ({u['score']})")
                for x in u["reasons"]: st.write("• " + x)
    tw = I.top_words(M, t)
    if tw:
        with st.expander("What the AI noticed"):
            st.write("  ".join(f"`{w}` +{x}" for w, x in tw))
    st.markdown("<a class='btn' href='tel:1930'>Call 1930</a><a class='btn g' href='https://cybercrime.gov.in' target='_blank'>Report online</a><br><small style='color:#94A3B8'>Forward scam SMS to 1909</small>", unsafe_allow_html=True)
    st.download_button("Download report", E.report_text(t, r), "scamshield_report.txt", use_container_width=True)


def page_dash():
    st.markdown("<div class='hero'><span class='eyebrow'>AI-POWERED SCAM INTELLIGENCE</span><h1>Stay one step ahead of <em>scams.</em></h1>"
                "<p>AI-powered intelligence to identify suspicious messages, detect potential fraud, and protect your digital interactions.</p></div>", unsafe_allow_html=True)
    a, b, _ = st.columns([1.2, 1.2, 2])
    a.button("Analyze a message", type="primary", use_container_width=True, on_click=lambda: S.update(nav=PAGES[1]))
    b.button("Scan a screenshot", use_container_width=True, on_click=lambda: S.update(nav=PAGES[2]))
    h = S.hist; n = lambda lv: sum(x["Level"] == lv for x in h)
    st.markdown("<div class='grid'>" + kpi("Messages analyzed", len(h)) + kpi("Threats detected", n("HIGH"), "#FF5364") + kpi("Suspicious", n("MEDIUM"), "#F5B942") + kpi("Safe", n("LOW"), "#20D68A") + "</div><small style='color:#64748B'>Counts reflect this session only.</small>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        rows = "".join(f"<div class='row'><span class='dot' style='background:{LAB[x['Level']][1]};box-shadow:none;margin-top:6px;flex:none'></span><div><b>{LAB[x['Level']][0]} · {x['Score']}%</b><br><span style='color:#94A3B8'>{html.escape(x['Message'])}</span></div></div>" for x in h[:5])
        st.markdown(f"<div class='card'><b>Recent activity</b>{rows or '<p style=color:#94A3B8>No analyses yet. Scan a message to get started.</p>'}</div>", unsafe_allow_html=True)
    with c2:
        ty = {}
        for x in h:
            if x["Type"] != "No clear scam pattern": ty[x["Type"]] = ty.get(x["Type"], 0) + 1
        mx = max(ty.values()) if ty else 1
        rows = "".join(f"<div style='margin:12px 0'><div style='display:flex;justify-content:space-between;font-size:.85rem'><span>{html.escape(k)}</span><b>{v}</b></div><div class='bar'><i style='width:{v / mx * 100}%;background:linear-gradient(90deg,#20D68A,#39C6D8)'></i></div></div>" for k, v in sorted(ty.items(), key=lambda i: -i[1]))
        st.markdown(f"<div class='card'><b>Threat distribution</b>{rows or '<p style=color:#94A3B8>Detected scam types will appear here.</p>'}</div>", unsafe_allow_html=True)


def page_text():
    head("Message scanner", "Paste an SMS, WhatsApp message, email or link for an explained risk assessment.")
    st.text_area("Message", key="txt", height=190, max_chars=3000, placeholder="Paste the suspicious message here…", label_visibility="collapsed")
    a, b = st.columns([3, 1])
    if a.button("Analyze message", type="primary", use_container_width=True, disabled=not S.txt.strip()):
        do_analyze(S.txt.strip(), "text")
    b.button("Clear", use_container_width=True, on_click=lambda: S.update(txt="", last="", lastsrc=""))
    if S.last and S.lastsrc == "text":
        show_result(S.last)
    else:
        st.markdown("<div class='card' style='text-align:center;color:#94A3B8'>Your analysis appears here as soon as you press Analyze.</div>", unsafe_allow_html=True)


def page_ocr():
    head("Screenshot scanner", "Upload a screenshot. The text is read in your browser and analyzed automatically.")
    res = ocr_comp(key="ocr", default=None)
    if res and res.get("id") != S.get("ocr_id"):
        S.ocr_id = res["id"]; S.ocr_text = res["text"].strip(); S.ocr_empty = not S.ocr_text
        if S.ocr_text: do_analyze(S.ocr_text, "ocr")
    if S.ocr_empty:
        st.warning("No readable text was found in that image. Try a clearer or larger screenshot.")
    elif S.last and S.lastsrc == "ocr":
        st.markdown(f"<div class='card'><b>Extracted text</b><div class='bubble'>{html.escape(S.ocr_text)}</div></div>", unsafe_allow_html=True)
        show_result(S.last)
    else:
        st.markdown("<div class='card' style='text-align:center;color:#94A3B8'>Drop a screenshot above to see the extracted text and result.</div>", unsafe_allow_html=True)


def page_hist():
    head("Detection history", "Your analyses from this session. Nothing is stored on the server.")
    if not S.hist:
        st.markdown("<div class='card' style='text-align:center;color:#94A3B8'>No scans yet.</div>", unsafe_allow_html=True); return
    df = pd.DataFrame(S.hist)
    st.markdown("<div class='grid'>" + kpi("Scans", len(df)) + kpi("High risk", int((df.Level == "HIGH").sum()), "#FF5364") + kpi("Average risk", f"{df.Score.mean():.0f}%", "#39C6D8") + "</div>", unsafe_allow_html=True)
    st.bar_chart(df.Level.value_counts())
    st.dataframe(df, use_container_width=True, hide_index=True)
    a, b = st.columns(2)
    a.download_button("Export CSV", df.to_csv(index=False), "history.csv", use_container_width=True)
    b.button("Clear history", use_container_width=True, on_click=lambda: S.update(hist=[]))


def page_quiz():
    head("Spot the scam", "Fresh questions every round. Decide whether each message is a scam or genuine.")
    qz, n = S.qz, len(S.qz)
    if S.qi >= n:
        S.best = max(S.best, S.qs)
        st.markdown(f"<div class='card' style='text-align:center'><div style='font-size:2.6rem;font-weight:800;color:#20D68A'>{S.qs}/{n}</div>{'Scam-proof!' if S.qs >= n - 1 else 'Getting sharp' if S.qs >= n * 0.6 else 'Keep practising'}<br><small style='color:#94A3B8'>Best this session: {S.best}/{n}</small></div>", unsafe_allow_html=True)
        st.button("New round (fresh questions)", type="primary", use_container_width=True, on_click=new_round)
        return
    q = qz[S.qi]
    st.progress(S.qi / n, text=f"Round {S.rounds} · Question {S.qi + 1} of {n} · Streak {S.qstreak}")
    st.markdown(f"<div class='bubble'>{html.escape(q['text'])}</div>", unsafe_allow_html=True)
    if S.qans is None:
        def pick(g):
            ok = g == q["scam"]; S.qans = "yes" if ok else "no"; S.qs += int(ok); S.qstreak = S.qstreak + 1 if ok else 0
        a, b = st.columns(2)
        a.button("Scam", use_container_width=True, on_click=pick, args=(True,))
        b.button("Safe", use_container_width=True, on_click=pick, args=(False,))
    else:
        ok = S.qans == "yes"; vr = E.analyze(q["text"], M); c = "#20D68A" if ok else "#FF5364"
        st.markdown(f"<div class='card' style='border-left:4px solid {c}'><b style='color:{c}'>{'Correct' if ok else 'Not quite'}</b> · this was <b>{'a scam' if q['scam'] else 'genuine'}</b> ({q['tag']}).<br>{q['why']}<br><small style='color:#94A3B8'>ScamShield's verdict: {vr['level']} · {vr['score']}%</small></div>", unsafe_allow_html=True)
        st.button("Next", type="primary", use_container_width=True, on_click=lambda: S.update(qi=S.qi + 1, qans=None))
    st.button("Shuffle new questions", use_container_width=True, on_click=new_round)


def page_guide():
    head("Scam guide", "Quick rules that protect you from the most common scams in India.")
    st.markdown("<div class='grid' style='grid-template-columns:repeat(auto-fit,minmax(260px,1fr))'>" + "".join(f"<div class='kpi'><b style='font-size:1.05rem'>{a}</b><small style='margin-top:6px;font-size:.9rem'>{b}</small></div>" for a, b in TIPS) + "</div>", unsafe_allow_html=True)
    st.markdown("<div class='card'><b>Privacy</b><br><span style='color:#94A3B8'>Messages are analysed in memory and never saved on the server. Screenshots are read inside your browser.</span></div>", unsafe_allow_html=True)


with st.sidebar:
    st.markdown("<div class='brand'><svg width='38' height='38' viewBox='0 0 60 64'><path d='M30 4 L54 12 V32 C54 46 44 54 30 60 C16 54 6 46 6 32 V12 Z' fill='rgba(32,214,138,.15)' stroke='#20D68A' stroke-width='3'/><path d='M20 32 l7 7 l14 -15' fill='none' stroke='#20D68A' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/></svg>"
                "<div><b>ScamShield</b><small>Intelligence. Protection. Trust.</small></div></div>", unsafe_allow_html=True)
    st.radio("Navigation", PAGES, key="nav", label_visibility="collapsed")
    st.selectbox("Explain results in", ["en", "hi", "mr"], format_func={"en": "English", "hi": "हिन्दी", "mr": "मराठी"}.get, key="lang")
    st.markdown(f"<div style='margin-top:18px'><span class='chip'><span class='dot'></span>System operational</span></div><small style='color:#64748B;display:block;margin-top:10px'>ScamShield v5.0 · {html.escape(os.path.basename(HERE))}</small>", unsafe_allow_html=True)

[page_dash, page_text, page_ocr, page_hist, page_quiz, page_guide][PAGES.index(S.nav)]()
