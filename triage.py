import argparse, os, ipaddress, requests, sys, time, csv
from dotenv import load_dotenv


# CONFIGS
DEFAULT_INPUT = "alerts.csv"
DEFAULT_OUTPUT = "triage_report.csv"
DEFAULT_THRESHOLD = 50 # confidence score (0-100) above which flagged as High Priority
DEFAULT_DELAY = 1.2 # time(second) between API calls
load_dotenv()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automate IOC IP triage using AbuseIPDB.")
    parser.add_argument('-i', "--input", default=DEFAULT_INPUT, help="Path to input CSV file")
    parser.add_argument('-o', "--output", default=DEFAULT_OUTPUT, help="Path to output report CSV")
    parser.add_argument('-t', "--threshold", type=int, default=DEFAULT_THRESHOLD, help="Score threshold for escalation")
    parser.add_argument('-d', "--delay", type=float, default=DEFAULT_DELAY, help="Delay between API queries (seconds)")
    return parser.parse_args()

def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_global:
            return True
    except ValueError:
        return False


def check_ip(session: requests.Session,ip: str, api_key: str) -> dict:
    """Query AbuseIPDB for a single IP and return relevant fields."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = session.get(url=url, headers=headers, params=params, timeout=10)

        if response.status_code == 429:
            return {
                "ip": ip,
                "abuse_score": -1,
                "country": "N/A",
                "isp": "N/A",
                "usage_type": "N/A",
                "total_reports": 0,
                "error": "Rate limit exceeded (HTTP 429)"
            }

        response.raise_for_status()
        data = response.json().get("data", {})

        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "usage_type": data.get("usageType", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "error": "",
        }

    except requests.RequestException as e:
        return {
            "ip": ip,
            "abuse_score": -1,
            "country": "N/A",
            "isp": "N/A",
            "usage_type": "N/A",
            "total_reports": 0,
            "error": str(e),
        }

    

def get_recommendation(score: int, error_msg: str, threshold: int) -> str:
    if error_msg:
        return "ERROR - check manually"
    if score >= threshold:
        return "HIGH PRIORITY - escalate"
    if score > 0:
        return "MONITOR"
    return "LIKELY BENIGN"


def main():
    args = parse_arguments()
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        print("Error: ABUSEIPDB_API_KEY environment variable is not set.", file=sys.stderr)
        print("Set it using: export ABUSEIPDB_API_KEY='your_api_key_here'", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input, mode='r', newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            raw_ips = [row["ip"].strip() for row in reader if row.get("ip")]
    except FileNotFoundError:
        print(f"Error: Could not find input file '{args.input}'.", file=sys.stderr)
        sys.exit(1)
    except KeyError:
        print("Error: Input CSV must contain an 'ip' header.", file=sys.stderr)
        sys.exit(1)

    # Deduplicate IP addresses
    unique_ips = dict.fromkeys(raw_ips)
    if not unique_ips:
        print("No IPs found in input file.")
        return
    
    print(f"Loaded {len(unique_ips)} unique IP(s). Beginning triage...")

    results = []
    with requests.Session() as session:
        for index, ip in enumerate(unique_ips, 1):
            print(f"  [{index}/{len(unique_ips)}] Checking {ip}...")
            res = check_ip(session, ip, api_key)
            res["recommendation"] = get_recommendation(res["abuse_score"], res["error"], args.threshold)
            results.append(res)
            time.sleep(args.delay)

    # Sort so that highest-risk IPs appear first
    results.sort(key=lambda r: r["abuse_score"], reverse=True)

    # Write report
    fieldnames = ["ip", "abuse_score", "country", "isp", "usage_type", "total_reports", "recommendation", "error"]
    with open(args.output, mode='w', newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    high_priority = sum(1 for r in results if r["recommendation"].startswith("HIGH"))
    print(f"\nTriage complete. Flagged {high_priority} high-priority IP(s).")
    print(f"Results written to: {args.output}")

if __name__ == "__main__":
    main()
