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
1️⃣ Install Python 3
Download Python from:
https://www.python.org/downloads/

During installation:
✔ Check “Add Python to PATH”

2️⃣ Install Npcap (Required for ARP Scanning)
Download Npcap from:
https://npcap.com

During installation, check:
✔ Install Npcap in WinPcap API‑compatible Mode

Restart your laptop after installation.

3️⃣ Download the Project
Download ZIP:
Click Code → Download ZIP

Extract the folder

4️⃣ Create a Virtual Environment
Open PowerShell inside the project folder:

Code
cd C:\path\to\network_vuln_scanner
python -m venv venv
5️⃣ Activate the Virtual Environment
PowerShell blocks scripts by default, so run:

Code
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Then activate:

Code
.\venv\Scripts\Activate.ps1
You should now see:

Code
(venv)
6️⃣ Install Required Python Packages
Run:

Code
pip install scapy python-nmap
If you have a requirements.txt, use:

Code
pip install -r requirements.txt
7️⃣ Run the Scanner
Start the GUI:

Code
python gui.py

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
