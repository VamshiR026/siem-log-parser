# siem-log-parser
A lightweight log parser to extract and analyze security IOCs
siem-log-parser/
│
├── README.md
├── parser.py
├── sample_logs/
│   └── windows_event_log.txt
├── output/
│   └── iocs.json
└── requirements.txt

import re
import json
from pathlib import Path

# Input & Output Paths
LOG_FILE = "sample_logs/windows_event_log.txt"
OUTPUT_FILE = "output/iocs.json"

# IOC Patterns
patterns = {
    "ip": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "hash_md5": r"\b[a-fA-F\d]{32}\b",
    "hash_sha256": r"\b[a-fA-F\d]{64}\b",
    "url": r"\bhttps?://[^\s/$.?#].[^\s]*\b"
}

def extract_iocs(log_data):
    iocs = {key: set() for key in patterns}
    for key, pattern in patterns.items():
        matches = re.findall(pattern, log_data)
        iocs[key].update(matches)
    return {k: list(v) for k, v in iocs.items() if v}

def main():
    Path("output").mkdir(exist_ok=True)
    with open(LOG_FILE, 'r') as f:
        logs = f.read()
    iocs = extract_iocs(logs)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(iocs, f, indent=4)
    print("IOCs extracted and saved to", OUTPUT_FILE)

if __name__ == "__main__":
    main()

# 🛡️ SIEM Log Parser & IOC Extractor

A lightweight Python-based tool designed for SOC analysts to parse logs and extract Indicators of Compromise (IOCs) such as IP addresses, hashes, and URLs from log files.

## 🔧 Features

- Parses Windows Event Logs, Syslogs, and Firewall Logs
- Extracts:
  - IP Addresses
  - MD5/SHA256 Hashes
  - URLs
- Saves results in JSON format
- Easily extendable with more IOC types

## 📂 Sample Log Format (in `sample_logs/`):



