from urllib.parse import urlparse
import time
import validators
import streamlit as st
import requests
import os

# Page config
st.set_page_config(
    page_title="ThreatLens",
    page_icon="🖥️",
    layout="wide"
)

# Custom CSS (UPDATED)
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500&family=Inter:wght@400;600&family=Great+Vibes&display=swap');

body {
    background-color: #0e1117;
    color: #00ff9f;
    font-family: 'Inter', sans-serif;
}

.stApp {
    background-color: #0e1117;
}

/* Cursive Title */
.main-title {
    font-family: 'Great Vibes', cursive;
    text-align: center;
    font-size: 64px;
    color: #00ff9f;
    margin-bottom: 30px;
}

/* Input */
.stTextInput>div>div>input {
    background-color: #1c1f26;
    color: white;
    border: 1px solid #00ff9f;
}

/* Button */
.stButton>button {
    background-color: #00ff9f;
    color: black;
    border-radius: 8px;
    font-weight: bold;
}

/* Metric */
.stMetric {
    background-color: #1c1f26;
    padding: 10px;
    border-radius: 10px;
    border: 1px solid #00ff9f;
    box-shadow: 0 0 10px rgba(0,255,159,0.2);
}

/* REMOVE submit text (FORCE REMOVE) */
small, 
[data-testid="stTextInput"] small,
[data-testid="stForm"] small,
[data-baseweb="input"] + div,
[data-testid="stTextInput"] div[role="alert"] {
    display: none !important;
}
</style>
""", unsafe_allow_html=True)

# History
if "history" not in st.session_state:
    st.session_state.history = []

# API Key
API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    st.error("API key not found. Set VT_API_KEY.")
    st.stop()

# HEADER (UPDATED)
st.markdown('<div class="main-title">ThreatLens</div>', unsafe_allow_html=True)

# Form
with st.form("url_form"):
    url = st.text_input("Enter URL", placeholder="example.com")
    submitted = st.form_submit_button("Analyze")

if submitted:

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not validators.url(url):
        st.error("Invalid URL")
        st.stop()

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    protocol = parsed_url.scheme

    malicious = suspicious = harmless = undetected = 0
    risk_score = 0

    with st.spinner("Analyzing threat intelligence..."):

        headers = {"x-apikey": API_KEY}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if response.status_code != 200:
            st.error("Submission failed")
            st.stop()

        analysis_id = response.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        for _ in range(10):
            res = requests.get(analysis_url, headers=headers)

            if res.status_code != 200:
                st.error("Fetch failed")
                st.stop()

            data = res.json()
            if data["data"]["attributes"]["status"] == "completed":
                stats = data["data"]["attributes"]["stats"]
                break

            time.sleep(2)
        else:
            st.error("Timeout")
            st.stop()

    # Extract stats
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total_engines = malicious + suspicious + harmless + undetected
    flagged = malicious + suspicious

    # Risk score
    if flagged == 0:
        risk_score = 0
    elif flagged <= 2:
        risk_score = 30
    elif flagged <= 5:
        risk_score = 60
    else:
        risk_score = 90

    # URL Details
    st.subheader("URL Details")
    st.write(f"Domain: {domain}")
    st.write(f"Protocol: {protocol}")
    st.divider()

    # Detection info
    st.info(f"Detected by {flagged}/{total_engines} engines")

    # Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Malicious", malicious)
    col2.metric("Suspicious", suspicious)
    col3.progress(risk_score / 100)
    col3.caption(f"Risk Score: {risk_score}/100")

    # Verdict
    if risk_score >= 80:
        verdict, color = "HIGH RISK", "red"
    elif risk_score >= 40:
        verdict, color = "MEDIUM RISK", "orange"
    else:
        verdict, color = "LOW RISK", "green"

    st.markdown(f"""
    <div style="
        padding:25px;
        border-radius:15px;
        border:2px solid {color};
        text-align:center;
        box-shadow: 0 0 20px {color};
        margin-bottom:20px;
    ">
        <h1 style="color:{color};">{verdict}</h1>
        <p>Risk Score: {risk_score}/100</p>
        <p>{flagged}/{total_engines} engines flagged</p>
    </div>
    """, unsafe_allow_html=True)

    # Explanation
    st.subheader("Why this result?")
    reasons = []

    if malicious:
        reasons.append(f"{malicious} engines marked malicious")
    if suspicious:
        reasons.append(f"{suspicious} engines marked suspicious")

    if risk_score >= 80:
        reasons.append("Multiple detections indicate high threat")
    elif risk_score >= 40:
        reasons.append("Suspicious indicators detected")
    else:
        reasons.append("No major threats found")

    for r in reasons:
        st.write(f"- {r}")

    # Save history
    st.session_state.history.insert(0, {
        "url": domain,
        "risk": verdict,
        "score": risk_score
    })
    st.session_state.history = st.session_state.history[:5]

# History
st.subheader("Recent Scans")
for item in st.session_state.history:
    st.write(f"{item['url']} → {item['risk']} ({item['score']}/100)")