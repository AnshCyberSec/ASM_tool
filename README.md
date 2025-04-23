# 🛡️ ASM TOOL - Automated Attack Surface Monitoring Tool

> **Reconnaissance Redefined. Risks Revealed. Real-Time Intelligence.**

✨ *Crafted with Precision & Passion by Anshuman Dalabehera*

---

## 🚀 Introduction

In the world of cybersecurity, knowing your attack surface is critical. **ASM TOOL** is a powerful, modular framework that helps you scan, analyze, and assess risks across domains—giving you deep insights into your online exposure *before the hackers do*.

With features like subdomain enumeration, SSL/TLS analysis, OSINT checks, and more, ASM TOOL is your **first line of defense** in identifying and securing potential vulnerabilities.

---

## 🧾 About the Project

ASM TOOL is designed to identify and assess vulnerabilities across domains. It leverages powerful reconnaissance techniques like:

- Subdomain Enumeration
- SSL/TLS Analysis
- Port Scanning
- OSINT Checks
- AI-Powered Risk Analysis

This tool empowers cybersecurity professionals to monitor attack surfaces and take proactive actions *before vulnerabilities are exploited*.

---

## 🎯 Purpose

With increasing cyber threats, proactive security is a must. ASM TOOL bridges the gap between detection and prevention, helping:

- 🔐 **Security Professionals**
- 🧪 **Penetration Testers**
- 🛡️ **DevSecOps Teams**
- 🖥️ **System Administrators**
- 🧠 **Anyone in Cybersecurity**

---

## 📁 Folder Structure

Anshuman_Dalabehera/
│
├── asm_tool/
│   ├── modules/
│   │   ├── subdomain.py              # Subdomain enumeration
│   │   ├── live_subdomains.py        # Check which subdomains are live
│   │   ├── port_scan.py              # Port scanning using Nmap
│   │   ├── headers.py                # HTTP security headers check
│   │   ├── ssl_analysis.py           # SSL/TLS configuration analysis
│   │   ├── ai_analysis.py            # AI-powered risk score & analysis
│   │   ├── sensitive_paths.py        # Sensitive path discovery (admin, backup, etc.)
│   │   ├── whois_dns.py              # WHOIS & DNS record fetching
│   │   ├── osint.py                  # OSINT & breach check
│   │   ├── tech_stack.py             # Technology stack detection (Wappalyzer)
│   │   └── __init__.py               # Makes 'modules' a Python package
│   │
│   ├── main.py                       # Main controller script (CLI entrypoint)
│   ├── utils.py                      # Utility functions (logging, file ops, etc.)
│   ├── input.csv                     # Input file containing list of domains
│   ├── requirements.txt              # Python dependencies
│   ├── README.md                     # Project documentation
│
├── outputs/
│   ├── <domain>/
│   │   ├── subdomains.json
│   │   ├── live_subdomains.json
│   │   ├── port_scan.json
│   │   ├── ssl_analysis.json
│   │   ├── headers.json
│   │   ├── tech_stack.json
│   │   ├── whois_dns.json
│   │   ├── osint.json
│   │   ├── sensitive_paths.json
│   │   └── final_report.json        # Merged AI + Module-based report
│
└── .gitignore                        # (optional) Ignore .env, __pycache__, etc.






---

## 🧩 Module Overview

| Module                | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `subdomain.py`        | Discovers subdomains using tools like Sublist3r              |
| `live_subdomain.py`   | Filters and lists only live subdomains                       |
| `port_scan.py`        | Scans for open ports and exposed services                    |
| `ssl_analysis.py`     | Analyzes SSL/TLS configuration and certificate validity      |
| `headers.py`          | Audits HTTP headers for security misconfigurations           |
| `ai_analysis.py`      | Provides AI-powered risk scoring and recommendations         |
| `sensitive_paths.py`  | Identifies potential sensitive paths like `/admin`, `/login` |
| `whois_dns.py`        | Performs WHOIS lookup and DNS record analysis                |
| `osint.py`            | Performs OSINT checks (e.g. breach history)                  |
| `tech_stack.py`       | Detects technology stack used in the domain                  |

---

## ✨ Features

- 🔍 **Subdomain Enumeration**  
- 🔓 **Port Scanning**  
- 🛡️ **SSL/TLS Certificate Analysis**  
- ⚡ **Live Subdomain Detection**  
- 🧠 **AI-Powered Risk Analysis**  
- 🕵️‍♂️ **Sensitive Path Discovery**  
- 🔎 **WHOIS & DNS Lookup**  
- 📚 **OSINT Breach Checks**  
- 🧱 **Technology Stack Detection**  

---

## 🧪 Installation

```bash
# 1. Clone the repository
git clone <repo_url>

# 2. Navigate to the project
cd Anshuman_Dalabehera/asm_tool

# 3. Install dependencies
pip install -r requirements.txt





1. ⚙️ Usage
Add domains to input.csv:

example.com
testsite.com
mydomain.org



2. Run the tool:

python main.py --input input.csv


3. View the results:
Reports are saved in the outputs/{domain}/ folder in JSON format.

📊 Sample Output
🧠 Risk Summary:

Domain: example.com
Risk Score: 85/100
Threat Level: High
Critical Findings:
- Open ports: 80, 443
- SSL misconfiguration
- Sensitive paths: /admin, /login



✅ Recommended Actions:
Close unused ports and enable firewalls.

Implement strong SSL configurations.

Secure sensitive paths using authentication.

Update outdated software components.


🧾 Sample JSON Output

{
  "domain": "example.com",
  "risk_score": 85,
  "threat_level": "High",
  "findings": {
    "subdomains": ["www.example.com", "blog.example.com"],
    "open_ports": [80, 443],
    "ssl_analysis": {
      "certificate_valid": false,
      "cipher_strength": "Weak"
    },
    "sensitive_paths": ["/admin", "/login"],
    "osint": {
      "breaches_found": true,
      "breach_details": "Found domain in previous data leaks."
    }
  },
  "recommendations": [
    "Patch SSL/TLS vulnerabilities.",
    "Close open ports 80, 443 if not needed.",
    "Restrict access to sensitive paths."
  ]
}



🛠️ Tech Stack


1.Python 3.10+

2. sublist3r, requests, nmap, sslyze, whatweb

3. AI Risk Analysis: Custom logic using rules/statistical analysis

4. Output Format: JSON reports for automation or integration




📌 Final Note
ASM TOOL is more than a scanner—it's your silent guardian.
Built to reveal risks before they become real threats.



Thank you for exploring ASM TOOL – Automated Attack Surface Monitoring Tool.
This project was crafted with precision, passion, and a purpose — to make reconnaissance smarter and security stronger.

If you find this tool helpful or have suggestions to improve it, feel free to contribute or connect with me.

Stay Secure. Stay Ahead.
— Anshuman Dalabehera
