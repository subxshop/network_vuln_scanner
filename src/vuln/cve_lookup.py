import requests

def lookup_cves(service_name, version):
    try:
        url = f"https://cve.circl.lu/api/search/{service_name}/{version}"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return []

        data = response.json()

        cves = []
        for item in data.get("results", []):
            cves.append({
                "id": item.get("id"),
                "summary": item.get("summary"),
                "cvss": item.get("cvss", 0)
            })

        return cves

    except Exception:
        return []
