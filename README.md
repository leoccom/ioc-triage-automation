# IOC Triage Automation Tool

## Overview
This script automates the first step of SOC alert triage: taking a list of
source IP addresses (e.g., exported from a SIEM like Splunk) and checking
each one against AbuseIPDB's threat intelligence database. It outputs a
prioritized report so an analyst can immediately see which IPs need
escalation versus which are likely benign.

## Why I built this
SOC analysts spend a lot of time manually looking up IPs during alert
triage. This script removes that manual step, demonstrating how
automation can reduce mean-time-to-respond (MTTR) and let analysts focus
on actual investigation instead of repetitive lookups.

## How it works
1. **Splunk** — An SPL query identifies suspicious source IPs (e.g., IPs
   with high failed-login counts or repeated requests) and exports them
   to `alerts.csv`.
2. **Python script (`triage.py`)** — Reads the CSV, queries the
   AbuseIPDB API for each IP, and pulls back:
   - Abuse confidence score (0–100)
   - Country
   - ISP
   - Total abuse reports
3. **Output** — Writes `triage_report.csv`, sorted by risk, with a
   recommendation per IP:
   - `HIGH PRIORITY - escalate` (score ≥ 50)
   - `MONITOR` (score > 0 but below threshold)
   - `LIKELY BENIGN` (score = 0)
   - `ERROR - check manually` (API lookup failed)

## Example SPL query used to generate input
```
index=botsv1 sourcetype=stream:http
| stats count by src_ip
| where count > 10
| rename src_ip as ip
| table ip
```

## Setup
1. Get a free API key at https://www.abuseipdb.com/account/api/keys
2. Paste it into `triage.py` (`API_KEY` variable)
3. Install dependencies:
   ```
   pip install requests
   ```
4. Run:
   ```
   python triage.py alerts.csv
   ```

## Sample output
| ip | abuse_score | country | isp | total_reports | recommendation |
|----|----|----|----|----|----|
| 185.220.101.1 | 100 | DE | Artikel10 e.V. | 151 | HIGH PRIORITY - escalate |
| 8.8.8.8 | 0 | US | Google LLC | 128 | LIKELY BENIGN |

## Possible future improvements
- Add support for batch lookups via VirusTotal as a second source
- Auto-create tickets in TheHive for high-priority IPs
- Add Slack/email alert webhook for HIGH PRIORITY findings