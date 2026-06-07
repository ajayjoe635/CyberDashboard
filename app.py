from flask import Flask, render_template, jsonify
import requests
import json
import os
import urllib3
from dotenv import load_dotenv

# Disable SSL warnings for local Nessus
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

app = Flask(__name__)

NESSUS_URL = os.getenv("NESSUS_URL", "https://localhost:8834")
ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY", "")
SECRET_KEY = os.getenv("NESSUS_SECRET_KEY", "")
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")

HEADERS = {
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
    "Content-Type": "application/json"
}

# MITRE ATT&CK mapping based on vulnerability types
MITRE_MAP = {
    "ssl": {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Collection"},
    "tls": {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Collection"},
    "smb": {"id": "T1021.002", "name": "Remote Services: SMB", "tactic": "Lateral Movement"},
    "rdp": {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "ssh": {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "ftp": {"id": "T1021.002", "name": "Remote Services: FTP", "tactic": "Lateral Movement"},
    "http": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "default": {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    "password": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "patch": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "cve": {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
    "backdoor": {"id": "T1543", "name": "Create or Modify System Process", "tactic": "Persistence"},
    "open port": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "icmp": {"id": "T1595.001", "name": "Scanning IP Blocks", "tactic": "Reconnaissance"},
    "dns": {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
    "snmp": {"id": "T1602", "name": "Data from Configuration Repository", "tactic": "Collection"},
}

def get_mitre_mapping(vuln_name, vuln_description=""):
    text = (vuln_name + " " + vuln_description).lower()
    for keyword, mapping in MITRE_MAP.items():
        if keyword in text:
            return mapping
    return MITRE_MAP["default"]

def get_scans():
    try:
        r = requests.get(f"{NESSUS_URL}/scans", headers=HEADERS, verify=False)
        return r.json().get("scans", [])
    except Exception as e:
        return []

def get_scan_details(scan_id):
    try:
        r = requests.get(f"{NESSUS_URL}/scans/{scan_id}", headers=HEADERS, verify=False)
        return r.json()
    except Exception as e:
        return {}

def get_ai_analysis(vulnerabilities):
    if not CLAUDE_API_KEY:
        return "Claude API key not configured. Add CLAUDE_API_KEY to your .env file."
    
    try:
        vuln_summary = []
        for v in vulnerabilities[:10]:
            vuln_summary.append(f"- {v.get('plugin_name', 'Unknown')} (Severity: {v.get('severity_label', 'Unknown')})")
        
        vuln_text = "\n".join(vuln_summary)
        
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": CLAUDE_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1000,
                "messages": [{
                    "role": "user",
                    "content": f"""You are a cybersecurity analyst. Analyze these vulnerabilities found on a home lab network and provide:
1. A brief executive summary (2-3 sentences)
2. Top 3 most critical risks
3. Immediate remediation recommendations

Vulnerabilities found:
{vuln_text}

Keep it concise and actionable. Format with clear sections."""
                }]
            }
        )
        
        data = response.json()
        return data.get("content", [{}])[0].get("text", "Analysis unavailable")
    except Exception as e:
        return f"AI analysis error: {str(e)}"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scans")
def api_scans():
    scans = get_scans()
    return jsonify(scans)

@app.route("/api/scan/<int:scan_id>")
def api_scan_detail(scan_id):
    details = get_scan_details(scan_id)
    
    vulnerabilities = []
    severity_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    severity_colors = {0: "#4a9eff", 1: "#2ecc71", 2: "#ffb547", 3: "#ff6b35", 4: "#ff4757"}
    
    if "vulnerabilities" in details:
        for vuln in details["vulnerabilities"]:
            severity_num = vuln.get("severity", 0)
            plugin_name = vuln.get("plugin_name", "Unknown")
            mitre = get_mitre_mapping(plugin_name)
            
            vulnerabilities.append({
                "plugin_id": vuln.get("plugin_id"),
                "plugin_name": plugin_name,
                "severity": severity_num,
                "severity_label": severity_map.get(severity_num, "Info"),
                "severity_color": severity_colors.get(severity_num, "#4a9eff"),
                "count": vuln.get("count", 1),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["name"],
                "mitre_tactic": mitre["tactic"],
            })
    
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulnerabilities:
        label = v["severity_label"]
        if label in severity_counts:
            severity_counts[label] += 1
    
    ai_analysis = get_ai_analysis(vulnerabilities)
    
    hosts = details.get("hosts", [])
    host_list = []
    for h in hosts:
        host_list.append({
            "hostname": h.get("hostname", "Unknown"),
            "ip": h.get("hostname", "Unknown"),
            "critical": h.get("critical", 0),
            "high": h.get("high", 0),
            "medium": h.get("medium", 0),
            "low": h.get("low", 0),
            "info": h.get("info", 0),
            "score": h.get("score", 0)
        })
    
    return jsonify({
        "scan_info": details.get("info", {}),
        "vulnerabilities": sorted(vulnerabilities, key=lambda x: x["severity"], reverse=True),
        "severity_counts": severity_counts,
        "hosts": host_list,
        "ai_analysis": ai_analysis,
        "total_vulns": len(vulnerabilities)
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🔐 CyberDashboard starting at http://localhost:{port}")
    app.run(debug=False, host="0.0.0.0", port=port)
