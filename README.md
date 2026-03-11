# Nmap Recon Analyzer

A SOC-style reconnaissance tool that parses Nmap scan results and generates
a clean, organized report with risk assessments and enumeration suggestions.

## Features
- Parses Nmap XML scan output
- Classifies services by port
- Assigns risk levels (High, Medium, Low)
- Suggests enumeration commands for each service
- Outputs a clean SOC-style table report

## Requirements
- Python 3
- Nmap installed on your system

## Installation
git clone https://github.com/yourusername/nmap-recon-analyzer
cd nmap-recon-analyzer

## Usage
1. Run an Nmap scan and save as XML:
nmap -sV -oX scan.xml target

2. Run the analyzer:
python3 analyzer.py
## Example Output
============================================================
         NMAP RECON ANALYZER - SOC REPORT
============================================================
PORT     PROTOCOL   SERVICE            RISK       STATE
------------------------------------------------------------
22       tcp        Remote Access      High       open
80       tcp        Web Service        Medium     open
445      tcp        File Sharing       High       filtered
============================================================

SUGGESTED ENUMERATION COMMANDS:
------------------------------------------------------------
Port 22 (Remote Access):
  -> Try SSH enumeration: nmap --script ssh-auth-methods
  -> Check for weak credentials or brute force

Port 80 (Web Service):
  -> Run directory enumeration with gobuster
  -> Check technologies with whatweb

## Author
cyb3rgoon
