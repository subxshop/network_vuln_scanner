🔍 Network Vulnerability Scanner (Python + Tkinter)
A lightweight network vulnerability scanner that discovers devices on a subnet, identifies open ports, detects running services, and performs real‑time vulnerability analysis using both a local database and live CVE lookups.

This tool is designed for educational and authorized security testing.

🚀 Features
Host Discovery – Finds active devices on a subnet

Port Scanning – Identifies open ports and service versions

Real‑Time Vulnerability Analysis

Local vulnerability database

Live CVE lookup via CIRCL API

Graphical User Interface (GUI)

Tabs for Hosts, Ports, and Vulnerabilities

Progress bar + Cancel Scan

Save Report to text file

Threaded Scanning – GUI stays responsive

Cross‑platform support (Windows, macOS, Linux)

📦 Installation
1. Clone the repository
Code
git clone https://github.com/subxshop/network_vuln_scanner
cd network_vuln_scanner
2. Create a virtual environment (recommended)
Code
python -m venv venv
.\venv\Scripts\Activate.ps1   # Windows PowerShell
3. Install dependencies
Code
pip install -r requirements.txt
4. Install Nmap
Required for port scanning.
Download from: https://nmap.org/download.html (nmap.org in Bing)

▶️ Running the Application
Code
python gui.py
The GUI will open and allow you to:

Enter a subnet

Start a scan

View hosts, ports, and vulnerabilities

Save a report

🧪 Testing
The system has been tested for:

Host discovery accuracy

Port scanning reliability

CVE lookup stability

GUI responsiveness under load

Cancel scan behavior

Report generation

⚠️ Legal Notice
This tool is for educational use and authorized security testing only.
Do not scan networks you do not own or have explicit permission to test.
