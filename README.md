# CyberDashboard 🔐

A Flask-based cybersecurity vulnerability dashboard integrating Nessus API, 
MITRE ATT&CK framework mapping, and Claude AI analysis for real-time 
network security monitoring.

## Features
- Live Nessus vulnerability scan data via API
- MITRE ATT&CK framework mapping for each vulnerability
- AI-powered security analysis using Claude
- Severity breakdown — Critical, High, Medium, Low, Info
- Host-level vulnerability tracking
- Auto-refreshes every 5 minutes

## Tech Stack
Python, Flask, Nessus API, MITRE ATT&CK, Claude AI, HTML/CSS/JavaScript

## Setup
1. Clone the repo
2. Install dependencies: `pip install -r requirements.txt`
3. Create `.env` file with your API keys
4. Run: `python app.py`
5. Open: `http://localhost:5000`
