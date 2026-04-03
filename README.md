# 🔍 Nmap Recon Analyzer

A Python-based SOC (Security Operations Center) tool that parses Nmap XML scan results, assesses port risk levels, and suggests enumeration commands for penetration testing and network reconnaissance.

---

## 🚀 Features

- Parses Nmap XML output automatically
- Identifies open, filtered, and closed ports
- Assigns risk levels (Critical / High / Medium / Low) to each service
- Suggests enumeration commands for high-risk services
- Generates a clean SOC-style report

---

## 🛠️ Installation
```bash
git clone https://github.com/AsmithTank77-droid/nmap-recon-analyzer.git
cd nmap-recon-analyzer
```

**Requirements:**
- Python 3.x
- Nmap installed on your system

---

## 📖 Usage

**Step 1 - Run an Nmap scan and save as XML:**
```bash
nmap -sV -oX scan.xml 
```

**Step 2 - Run the analyzer:**
```bash
python3 analyzer.py
```

---

## 📊 Example Output
NMAP RECON ANALYZER - SOC REPORT
PORT     PROTOCOL   SERVICE          RISK
22       tcp        ssh              High
80       tcp        http             Medium
445      tcp        microsoft-ds     High
SUGGESTED ENUMERATION COMMANDS:
Port 22 (ssh):
-> Try SSH enumeration: nmap --script ssh-auth-methods
-> Check for weak credentials or brute force

---

## ⚠️ Disclaimer

This tool is intended for authorized penetration testing and educational purposes only. Always obtain proper written permission before scanning any network or system.

---

## 👤 Author

**AsmithTank77-droid**  
Cybersecurity enthusiast | Python developer
