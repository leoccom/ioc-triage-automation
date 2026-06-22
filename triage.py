import requests, sys, time, csv


# CONFIGS
API_KEY = "" # AbuseIPDB API Key
ABUSE_THRESHOLD = 50 # confidence score (0-100) above which flagged as High Priority
INPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else "alert.csv"
OUTPUT_FILE = "triage_report.csv"
REQUEST_DELAY = 1.2 # time(second) between API calls



def check_ip(ip):
    """Query AbuseIPDB for a single IP and return relevant fields."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(url=url, headers=headers, params=params, timeout=10)
        response.raise_for_status() # Raises HTTPError, if one occurred
        data = response.json()["data"]

        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "total_reports": data.get("totalReports", 0),
            "error": "",
        }
    
    except Exception as e:
        return {
            "ip": ip,
            "abuse_score": -1,
            "country": "N/A",
            "isp": "N/A",
            "total_reports": 0,
            "error": str(e),
        }
    

def recommendation(score):
    """Translate abuse score into a triage action."""
    if score < 0:
        return "ERROR - check manually"
    elif score >= ABUSE_THRESHOLD:
        return "HIGH PRIORITY - escalate"
    elif score > 0:
        return "MONITOR"
    else:
        return "LIKELY BENIGN"


def main():
    # Read input IPs
    try:
        with open(INPUT_FILE, newline="") as f:
            reader = csv.DictReader(f)
            ips = [row["ip"].strip() for row in reader if row.get("ip")]
    except FileNotFoundError:
        print(f"Could not find {INPUT_FILE}. Make sure the file exists and has an 'ip' column.")
        return
    except KeyError:
        print("Input CSV must have a column named 'ip'.")
        return
    
    if not ips:
        print("No IPs found in input file.")
        return
    
    print(f"Loaded {len(ips)} IPs. Querying AbuseIPDB...")

    results = []
    for i, ip in enumerate(ips, 1):
        print(f"  [{i}/{len(ips)}] Checking {ip}...")
        result = check_ip(ip)
        result["recommendation"] = recommendation(result["abuse_score"])
        results.append(result)
        time.sleep(REQUEST_DELAY)

    # Sort so that highest-risk IPs appear first
    results.sort(key=lambda r: r["abuse_score"], reverse=True)

    # Write report
    with open(OUTPUT_FILE, mode='w', newline="") as f:
        fieldnames = ["ip", "abuse_score", "country", "isp", "total_reports", "recommendation", "error"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    high_priority = sum(1 for r in results if r["recommendation"].startswith("HIGH"))
    print(f"\nDone. {high_priority} high-priority IP(s) flagged.")
    print(f"Full report written to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
