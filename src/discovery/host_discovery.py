from scapy.all import ARP, Ether, srp
import subprocess
import platform

def discover_hosts(target):
    """
    Discover active hosts on the network using ARP (local networks)
    and ICMP ping sweep as fallback.
    """
    print(f"[+] Discovering hosts in {target}...")

    hosts = []

    try:
        # ARP scan (works only on local subnet)
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=2, verbose=0)[0]

        for sent, received in result:
            hosts.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })

        if hosts:
            print(f"[+] ARP scan found {len(hosts)} hosts.")
            return hosts

    except PermissionError:
        print("[!] ARP scan requires admin privileges. Falling back to ping sweep.")

    # ICMP ping sweep fallback
    print("[+] Running ping sweep...")

    base_ip = target.split("/")[0]
    base = ".".join(base_ip.split(".")[:-1])

    for i in range(1, 255):
        ip = f"{base}.{i}"
        if ping(ip):
            hosts.append({"ip": ip, "mac": None})

    print(f"[+] Ping sweep found {len(hosts)} hosts.")
    return hosts


def ping(ip):
    """
    Cross-platform ping function.
    Returns True if host responds.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]

    try:
        output = subprocess.run(command, stdout=subprocess.DEVNULL)
        return output.returncode == 0
    except Exception:
        return False