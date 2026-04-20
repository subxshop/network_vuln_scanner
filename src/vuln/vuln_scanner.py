import json
import os
from src.vuln.cve_lookup import lookup_cves

def load_vuln_db():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, "vuln_db.json")

    with open(db_path, "r") as f:
        return json.load(f)

def analyze_vulnerabilities(scan_results):
    db = load_vuln_db()
    findings = []

    for host in scan_results:
        host_ip = host["ip"]
        host_findings = []

        for port_info in host["ports"]:
            port = str(port_info["port"])
            service = port_info["name"]
            version = port_info.get("version", "")

            # Local DB match
            if port in db:
                for issue in db[port]["issues"]:
                    host_findings.append({
                        "type": "local",
                        "severity": issue["severity"],
                        "description": issue["description"],
                        "service": db[port]["service"],
                        "port": port
                    })

            # Real-time CVE lookup
            if service and version:
                cves = lookup_cves(service, version)
                for cve in cves:
                    host_findings.append({
                        "type": "cve",
                        "severity": "high" if cve["cvss"] >= 7 else "medium",
                        "description": cve["summary"],
                        "cve_id": cve["id"],
                        "cvss": cve["cvss"],
                        "service": service,
                        "version": version,
                        "port": port
                    })

        findings.append({
            "ip": host_ip,
            "vulnerabilities": host_findings
        })

    return findings
