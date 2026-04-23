# ThreatLens

A real-time URL Threat Intelligence tool that analyzes suspicious links using VirusTotal API and provides risk scoring, detection metrics, and visual insights.

## Features

- URL validation and analysis  
- Multi-engine threat detection using VirusTotal  
- Risk scoring system (0–100)  
- Interactive gauge visualization  
- Explanation of threat results  
- Recent scan history tracking  
- Deployed using Streamlit Cloud  

## Tech Stack

- Python  
- Streamlit  
- VirusTotal API  
- Plotly  

## How it Works

1. User enters a URL  
2. URL is submitted to VirusTotal  
3. Multiple security engines analyze the URL  
4. Results are processed into a risk score  
5. Output is displayed with a visual gauge and verdict  

## Setup

1. Get a free API key from VirusTotal  
2. Add it in Streamlit secrets:

```
VT_API_KEY = "your_api_key"
```

## Live Demo

https://threatlens-app.streamlit.app/

## Use Case

This tool simulates a SOC Level 1 analyst workflow by analyzing URL reputation and identifying potential threats in real time.
