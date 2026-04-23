from urllib.parse import urlparse
import time
import validators
import streamlit as st
import requests
import os
import plotly.graph_objects as go

# Page config
st.set_page_config(
    page_title="ThreatLens",
    page_icon="🖥️",
    layout="wide"
)

# History storage
if "history" not in st.session_state:
    st.session_state.history = []

# Custom CSS
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Great+Vibes&family=Inter:wght@400;600&display=swap');

body {
    background-color: #0e1117;
    color: #00ff9f;
    font-family: 'Inter', sans-serif;
}

.main-title {
    font-family: 'Great Vibes', cursive;
    text-align: center;
    font-size: 64px;
    color: #00ff9f;
    margin-bottom: 30px;
}

.stTextInput>div>div>input {
    background-color: #1c1f26;
    color: white;
    border: 1px solid #00ff9f;
}

.stButton>button {
    background-color: #00ff9f;
    color: black;
    border-radius: 8px;
    font-weight: bold;
}

.stMetric {
    background-color: #1c1f26;
    padding: 10px;
    border-radius: 10px;
    border: 1px solid #00ff9f;
}

/* Remove helper text */
small {
    display: none !important;
}
</style>
""", unsafe_allow_html=True)

# API Key
API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    st.error("API key not found. Set VT_API_KEY.")
    st.stop()

# Header
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

    # Save history (clean version)
    st.session_state.history.insert(0, {
        "url": domain,
        "risk": risk_score,
        "malicious": malicious,
        "suspicious": suspicious
    })
    st.session_state.history = st.session_state.history[:5]

    # URL details
    st.subheader("URL Details")
    st.write(f"Domain: {domain}")
    st.write(f"Protocol: {protocol}")
    st.divider()

    # Detection info
    st.info(f"Detected by {flagged}/{total_engines} engines")

    # Metrics
    col1, col2 = st.columns(2)
    col1.metric("Malicious", malicious)
    col2.metric("Suspicious", suspicious)

    # Gauge (NEW)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        title={'text': "Risk Score"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "#00ff9f"},
            'steps': [
                {'range': [0, 30], 'color': "#1f3d2b"},
                {'range': [30, 60], 'color': "#4d3d00"},
                {'range': [60, 100], 'color': "#4d0000"}
            ],
        }
    ))

    st.plotly_chart(fig, use_container_width=True)

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

# History display
st.subheader("Recent Scans")

if st.session_state.history:
    for item in st.session_state.history:
        st.markdown(f"""
        **URL:** {item['url']}  
        Risk: {item['risk']}/100  
        Malicious: {item['malicious']} | Suspicious: {item['suspicious']}
        """)
else:
    st.info("No scans yet")