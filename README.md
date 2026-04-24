# ThreatLens

ThreatLens is a lightweight threat intelligence tool designed to simulate how a SOC analyst evaluates suspicious URLs. It leverages multi-engine detection from VirusTotal and applies a custom risk scoring model to provide clear, actionable insights in real time.

---

## Features

- URL validation and real-time analysis  
- Multi-engine threat detection using VirusTotal  
- Custom risk scoring system (0–100)  
- Interactive risk visualization (gauge chart)  
- Detailed explanation of detection results  
- Recent scan history tracking  
- Deployed on Streamlit Cloud  

---

## How It Works

1. User submits a URL through the interface  
2. The URL is sent to the VirusTotal API  
3. Multiple security engines scan and return results  
4. The response is processed and analyzed  
5. A risk score is calculated based on detection data  
6. Results are displayed with a visual gauge and final verdict  

---

## Risk Scoring Logic

The risk score (0–100) is calculated using:

- Number of engines flagging the URL as malicious  
- Ratio of malicious detections to total engines  
- Weightage given to confirmed malicious vs suspicious flags  

Score Interpretation:
- 0–20 → Safe  
- 21–50 → Suspicious  
- 51–100 → High Risk  

This scoring system helps prioritize threats similar to how SOC analysts triage alerts.

---

## Architecture

User Input  
↓  
Streamlit UI  
↓  
VirusTotal API  
↓  
Data Processing Layer  
↓  
Risk Scoring Engine  
↓  
Visualization (Plotly Gauge + Verdict)

---

## Sample Analysis

Input: http://example-suspicious-site.com  
Engines Flagged: 15 / 70  
Risk Score: 82 (High Risk)  

Verdict: Likely malicious — user interaction not recommended.

---

## Tech Stack

- Python  
- Streamlit  
- VirusTotal API  
- Plotly  

---

## Demo

https://threatlens-app.streamlit.app/

(Add screenshots here for better visibility)

---

## Use Cases

- SOC Level 1 analysts for quick URL triage  
- Cybersecurity students learning threat intelligence workflows  
- Demonstrating real-world detection and scoring systems  
- Basic threat analysis for suspicious links  

---

## Limitations

- Dependent on VirusTotal API rate limits  
- Does not perform dynamic or behavioral analysis  
- Limited to URL-based threat intelligence  
- No integration with real-time network traffic  

---

## Setup

1. Get a free API key from VirusTotal  
2. Add it to Streamlit secrets:

'''
VT_API_KEY = "your_api_key"
'''

3. Run the application locally:

'''
streamlit run app.py
'''

---

## Future Improvements

- Integration with additional threat intelligence sources  
- Machine learning-based anomaly detection  
- Email and file hash analysis support  
- SIEM integration for alert correlation  

---

## Disclaimer

This tool is intended for educational and research purposes only. It should not be used as a sole source of truth for security decisions.
