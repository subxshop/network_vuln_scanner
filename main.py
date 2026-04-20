import argparse
from src.discovery.host_discovery import discover_hosts
from src.scanning.port_scanner import scan_ports
from src.vuln.vuln_scanner import analyze_vulnerabilities

def main():
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("target", help="Target IP or subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--profile", default="quick", help="Scan profile: quick or full")
    args = parser.parse_args()

    print("MAIN.PY IS RUNNING")

    print(f"[+] Starting scan on {args.target}...")
    hosts = discover_hosts(args.target)

    print("\n[+] Discovered Hosts:")
    for host in hosts:
        print(f" - {host['ip']}  MAC: {host['mac']}")

    scan_results = scan_ports(hosts, args.profile)

    print("\n[+] Scan Results:")
    for host in scan_results:
        print(f"\nHost: {host['ip']}")
        for port in host["ports"]:
            print(f"  Port {port['port']} - {port['state']} - {port['name']} {port['version']}")

    vuln_results = analyze_vulnerabilities(scan_results)

    print("\n[+] Vulnerability Findings:")
    for host in vuln_results:
        print(f"\nHost: {host['ip']}")
        if not host["vulnerabilities"]:
            print("  No known vulnerabilities found.")
        else:
            for v in host["vulnerabilities"]:
                print(f"  [!] {v['severity'].upper()} - Port {v['port']} ({v['service']})")
                print(f"      {v['description']}")

def run_scan(target, profile="quick"):
    yield "DISCOVERY_START"

    hosts = discover_hosts(target)
    yield ("DISCOVERY_DONE", hosts)

    yield "SCAN_START"

    scan_results = scan_ports(hosts, profile)
    yield ("SCAN_DONE", scan_results)

    yield "VULN_START"

    vuln_results = analyze_vulnerabilities(scan_results)
    yield ("VULN_DONE", vuln_results)

    output = []

    output.append("Discovered Hosts:")
    for h in hosts:
        output.append(f" - {h['ip']}  MAC: {h['mac']}")

    output.append("\nPort Scan Results:")
    for host in scan_results:
        output.append(f"\nHost: {host['ip']}")
        for p in host["ports"]:
            output.append(f"  Port {p['port']} - {p['state']} - {p['name']}")

    output.append("\nVulnerability Findings:")
    for host in vuln_results:
        output.append(f"\nHost: {host['ip']}")
        if not host["vulnerabilities"]:
            output.append("  No known vulnerabilities.")
        else:
            for v in host["vulnerabilities"]:
                output.append(f"  [!] {v['severity'].upper()} - Port {v['port']} ({v['service']})")
                output.append(f"      {v['description']}")

    return output

if __name__ == "__main__":
    main()
    
from src.discovery.host_discovery import discover_hosts
from src.scanning.port_scanner import scan_ports
from src.vuln.vuln_scanner import analyze_vulnerabilities

def run_scan(target, profile="quick"):
    hosts = discover_hosts(target)
    scan_results = scan_ports(hosts, profile)
    vuln_results = analyze_vulnerabilities(scan_results)

    return hosts, scan_results, vuln_results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python main.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    hosts, scan_results, vuln_results = run_scan(target)

    print("[+] Discovered Hosts:")
    for h in hosts:
        print(f" - {h['ip']}  MAC: {h['mac']}")

    print("\n[+] Port Scan Results:")
    for host in scan_results:
        print(f"\nHost: {host['ip']}")
        for p in host["ports"]:
            print(f"  Port {p['port']} - {p['state']} - {p['name']}")

    print("\n[+] Vulnerability Findings:")
    for host in vuln_results:
        print(f"\nHost: {host['ip']}")
        if not host["vulnerabilities"]:
            print("  No known vulnerabilities.")
        else:
            for v in host["vulnerabilities"]:
                if v["type"] == "local":
                    print(f"  [LOCAL] {v['severity'].upper()} - Port {v['port']} ({v['service']})")
                    print(f"      {v['description']}")
                elif v["type"] == "cve":
                    print(f"  [CVE] {v['cve_id']} ({v['cvss']}) - {v['service']} {v['version']}")
                    print(f"      {v['description']}")
