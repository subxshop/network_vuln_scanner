import nmap

def scan_ports(hosts, profile="quick"):
    print("[+] Starting port scan...")

    nm = nmap.PortScanner()

    profiles = {
        "quick": "1-1024",
        "full": "1-65535"
    }

    port_range = profiles.get(profile, "1-1024")

    results = []

    for host in hosts:
        ip = host["ip"]
        print(f"[+] Scanning {ip} on ports {port_range}...")

        try:
            nm.scan(ip, port_range, arguments="-T4")

            host_result = {
                "ip": ip,
                "ports": []
            }

            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    ports = nm[ip][proto].keys()
                    for port in ports:
                        service = nm[ip][proto][port]
                        host_result["ports"].append({
                            "port": port,
                            "state": service["state"],
                            "name": service.get("name", ""),
                            "version": service.get("version", "")
                        })

            results.append(host_result)

        except Exception as e:
            print(f"[!] Error scanning {ip}: {e}")

    return results