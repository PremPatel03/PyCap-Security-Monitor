[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Library-Scapy-red.svg)](https://scapy.net/)
[![Security](https://img.shields.io/badge/Focus-Network_Security-green.svg)]()

## Overview
SentinelIDS is a custom, lightweight Intrusion Detection System (IDS) and traffic analyzer built in Python. It captures live network traffic, dissects TCP/IP packets in real-time, and logs anomalous or insecure network behavior to a local database for forensic analysis. 

This project was developed to demonstrate a practical understanding of low-level network protocols, packet sniffing, and automated threat detection.

## Threat Model & Features
This tool is designed to monitor local network interfaces and detect common security misconfigurations and reconnaissance tactics:

* **Insecure Protocol Detection:** Actively monitors for cleartext protocols (e.g., HTTP on Port 80, FTP on Port 21) that leave data vulnerable to man-in-the-middle (MitM) credential harvesting.
* **Reconnaissance Detection (Port Scans):** Implements state-tracking to detect aggressive Nmap-style port scans (e.g., identifying when a single source IP touches multiple unique ports within a 3-second window).
* **Automated SIEM Reporting:** Includes a secondary script (`generate_report.py`) that acts as a localized Security Information and Event Management (SIEM) dashboard, querying the SQLite database to generate actionable forensic summaries.

## Technology Stack
* **Language:** Python 3
* **Packet Manipulation:** Scapy
* **Database:** SQLite3 (Local logging)
* **Data Analysis:** Pandas (For forensic reporting)

## Installation & Setup

### Prerequisites
* Python 3.8 or higher.
* Administrative/Root privileges (required to bind to the Network Interface Card for sniffing).
* **Windows Users:** You must install [Npcap](https://npcap.com/) (Ensure "WinPcap API-compatible mode" is checked during installation).

### Installation
1. Clone the repository:
```bash
   git clone [[https://github.com/YourUsername/SentinelIDS.git](https://github.com/PremPatel03/PyCap-Security-Monitor)]([https://github.com/YourUsername/SentinelIDS.git](https://github.com/PremPatel03/PyCap-Security-Monitor))
   cd SentinelIDS
   ```
2. Install the required Python libraries:
   ```bash
   pip install scapy pandas
   ```

## Usage

### 1. Start the IDS
Because the script requires raw socket access, you must run it with elevated privileges.
* **Linux/Mac:** `sudo python3 lightweight_ids.py`
* **Windows:** Open Command Prompt or PowerShell as **Administrator** and run: `python lightweight_ids.py`

### 2. Generate Traffic
To test the IDS, you can:
* Visit `http://neverssl.com` to trigger the Insecure Protocol (HTTP) alert.
* Run a local `nmap` scan against your machine to trigger the Port Scan alert.

### 3. Generate Forensic Report
Once traffic has been captured, stop the IDS (`Ctrl+C`) and run the reporting tool to view the SIEM dashboard:
```bash
python generate_report.py
```

## Example Output
**Real-Time Logging:**
```text
[!] 2026-05-25 14:30:22 | Insecure Protocol | 192.168.1.15 -> 104.21.23.55 | Unencrypted HTTP traffic (Port 80).
[!] 2026-05-25 14:35:10 | Port Scan | 192.168.1.100 -> Multiple | Hit 6 unique ports within 3.0 seconds.
```

**Forensic Summary Report:**
```text
=========================================
       IDS FORENSIC SUMMARY REPORT       
=========================================

Total Alerts Logged: 142

--- Top 5 Offending Source IPs ---
src_ip           incident_count
192.168.1.100    120
192.168.1.15     22

--- Incident Breakdown by Type ---
alert_type          count
Port Scan           120
Insecure Protocol   22
=========================================
```

## ⚠️ Disclaimer
This tool was created for educational purposes and authorized network defense training. Only run packet sniffers and vulnerability scans on networks and devices you explicitly own or have permission to monitor.
"""

