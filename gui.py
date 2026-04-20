import tkinter as tk
from tkinter import ttk, scrolledtext
import threading

from main import run_scan
from src.discovery.host_discovery import discover_hosts
from src.scanning.port_scanner import scan_ports
from src.vuln.vuln_scanner import analyze_vulnerabilities

cancel_scan = False

def cancel_scan_action():
    global cancel_scan
    cancel_scan = True

def save_report():
    with open("scan_report.txt", "w", encoding="utf-8") as f:
        f.write("=== Hosts ===\n")
        f.write(hosts_tab.get("1.0", tk.END))
        f.write("\n=== Ports ===\n")
        f.write(ports_tab.get("1.0", tk.END))
        f.write("\n=== Vulnerabilities ===\n")
        f.write(vuln_tab.get("1.0", tk.END))

def start_scan():
    thread = threading.Thread(target=run_scan_thread, daemon=True)
    thread.start()

def run_scan_thread():
    global cancel_scan
    cancel_scan = False

    target = target_entry.get()
    profile = profile_var.get()

    hosts_tab.delete(1.0, tk.END)
    ports_tab.delete(1.0, tk.END)
    vuln_tab.delete(1.0, tk.END)

    progress_var.set(0)

    # --- DISCOVERY ---
    hosts_tab.insert(tk.END, "Discovering hosts...\n")
    root.update_idletasks()

    hosts = discover_hosts(target)
    progress_var.set(20)

    for h in hosts:
        hosts_tab.insert(tk.END, f"{h['ip']}  MAC: {h['mac']}\n")

    root.update_idletasks()

    # --- PORT SCANNING + REAL-TIME VULNS ---
    ports_tab.insert(tk.END, "Scanning ports...\n")
    root.update_idletasks()

    if not hosts:
        ports_tab.insert(tk.END, "\nNo hosts found.\n")
        vuln_tab.insert(tk.END, "\nNo hosts found.\n")
        progress_var.set(100)
        return

    for idx, host in enumerate(hosts):
        if cancel_scan:
            ports_tab.insert(tk.END, "\nScan canceled.\n")
            vuln_tab.insert(tk.END, "\nScan canceled.\n")
            progress_var.set(0)
            root.update_idletasks()
            return

        ip = host["ip"]
        ports_tab.insert(tk.END, f"\nHost: {ip}\n")
        root.update_idletasks()

        result = scan_ports([host], profile)[0]

        for p in result["ports"]:
            ports_tab.insert(tk.END, f"  Port {p['port']} - {p['state']} - {p['name']}\n")

        # --- REAL-TIME VULNERABILITY CHECK ---
        vulns = analyze_vulnerabilities([result])[0]["vulnerabilities"]

        vuln_tab.insert(tk.END, f"\nHost: {ip}\n")

        if not vulns:
            vuln_tab.insert(tk.END, "  No known vulnerabilities.\n")
        else:
            for v in vulns:
                if v["type"] == "local":
                    tag = v["severity"].upper()
                    vuln_tab.insert(
                        tk.END,
                        f"  [LOCAL] {tag} - Port {v['port']} ({v['service']})\n",
                        tag
                    )
                    vuln_tab.insert(tk.END, f"      {v['description']}\n")

                elif v["type"] == "cve":
                    tag = v["severity"].upper()
                    vuln_tab.insert(
                        tk.END,
                        f"  [CVE] {v['cve_id']} ({v['cvss']}) - {v['service']} {v['version']}\n",
                        tag
                    )
                    vuln_tab.insert(tk.END, f"      {v['description']}\n")

        # progress
        progress = 20 + int(80 * (idx + 1) / len(hosts))
        progress_var.set(progress)

        hosts_tab.see(tk.END)
        ports_tab.see(tk.END)
        vuln_tab.see(tk.END)
        root.update_idletasks()

    progress_var.set(100)

# --- GUI SETUP ---

root = tk.Tk()
root.title("Network Vulnerability Scanner")
root.geometry("900x600")

top_frame = tk.Frame(root)
top_frame.pack(fill="x", pady=5)

tk.Label(top_frame, text="Target IP/Subnet:").pack(side="left", padx=5)
target_entry = tk.Entry(top_frame, width=30)
target_entry.pack(side="left", padx=5)

profile_var = tk.StringVar(value="quick")
ttk.Label(top_frame, text="Scan Profile:").pack(side="left", padx=5)
ttk.OptionMenu(top_frame, profile_var, "quick", "quick", "full").pack(side="left", padx=5)

scan_button = tk.Button(top_frame, text="Start Scan", command=start_scan)
scan_button.pack(side="left", padx=5)

cancel_button = tk.Button(top_frame, text="Cancel Scan", command=cancel_scan_action)
cancel_button.pack(side="left", padx=5)

save_button = tk.Button(top_frame, text="Save Report", command=save_report)
save_button.pack(side="left", padx=5)

progress_var = tk.IntVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
progress_bar.pack(fill="x", pady=5)

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

hosts_tab = scrolledtext.ScrolledText(notebook, width=80, height=20)
ports_tab = scrolledtext.ScrolledText(notebook, width=80, height=20)
vuln_tab = scrolledtext.ScrolledText(notebook, width=80, height=20)

notebook.add(hosts_tab, text="Hosts")
notebook.add(ports_tab, text="Ports")
notebook.add(vuln_tab, text="Vulnerabilities")

vuln_tab.tag_config("HIGH", foreground="red")
vuln_tab.tag_config("MEDIUM", foreground="orange")
vuln_tab.tag_config("LOW", foreground="green")

root.mainloop()


