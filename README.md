# Azure Honeynet & Live Threat Detection

A live Azure honeynet built on top of an existing hybrid Active Directory lab, deliberately exposed to the public internet for 72 hours to collect real-world attack telemetry. Microsoft Sentinel was used as the central SIEM to ingest, enrich, and visualise attack data using KQL, GeoIP watchlists, and custom workbooks.

> **Lab environment:** Built on top of the [AD + Azure Hybrid Security Lab](https://github.com/Moise10/active-directory-security-lab)

---

## Architecture

| Component               | Details                               |
| ----------------------- | ------------------------------------- |
| Cloud Platform          | Microsoft Azure                       |
| SIEM                    | Microsoft Sentinel (via Defender XDR) |
| Log Analytics Workspace | AD-Lab-LogAnlayticsWorkspace          |
| Windows VM              | ad-project-vm (Windows Server 2019)   |
| Linux VM                | AD-linux-vm (Ubuntu)                  |
| Virtual Network         | AD_Lab_Vnet / subnet2                 |
| Honeynet Duration       | 72 hours                              |
| NSG State (open)        | All inbound traffic allowed           |
| NSG State (hardened)    | RDP restricted to trusted IP only     |

---

## What is a Honeynet?

A honeynet is a deliberately vulnerable environment designed to attract real attackers and observe their behaviour. By removing network restrictions and exposing services like RDP and SSH to the open internet, the environment becomes a target for automated scanners and botnets. All activity is logged and analysed in a SIEM, providing genuine threat intelligence data rather than simulated attacks.

---

## Phase 1 — Environment Exposure

### NSG Rules (Before — Hardened)

Both VMs had restrictive NSG rules in place prior to the honeynet phase:

| Rule              | Port | Source                            | Action |
| ----------------- | ---- | --------------------------------- | ------ |
| RDP               | 3389 | Trusted IP only (213.156.101.217) | Allow  |
| SSH               | 22   | Trusted IP only                   | Allow  |
| All other inbound | Any  | Any                               | Deny   |

### NSG Rules (During — Honeynet Open)

All inbound restrictions were removed to expose both VMs to the internet:

| Rule            | Port | Protocol | Source | Priority | Action |
| --------------- | ---- | -------- | ------ | -------- | ------ |
| AllowAnyInbound | Any  | Any      | Any    | 100      | Allow  |
| RDP             | 3389 | TCP      | Any    | 110      | Allow  |
| SSH             | 22   | TCP      | Any    | 120      | Allow  |
| SMB             | 445  | TCP      | Any    | 130      | Allow  |

Both VMs were left running with these rules for 72 hours with no interaction.

---

## Phase 2 — Sentinel Workbooks & Detection Rules

Five custom Sentinel workbooks were built to monitor and visualise the incoming attack data in real time:

| Workbook                  | Purpose                                                                  |
| ------------------------- | ------------------------------------------------------------------------ |
| Attack Map                | World map of attacker IPs sized by attempt volume using GeoIP enrichment |
| Brute Force by IP         | Failed logons grouped by source IP with targeted account list            |
| Brute Force by Account    | Failed logons grouped by target account with attacking IP list           |
| GeoIP-Top-Attackers       | Top 20 attacking IPs with city, country, latitude, longitude             |
| VM-Authentication-failure | Authentication failure trends over time                                  |

### Analytics Rules

Two scheduled analytics rules were configured in Sentinel to generate incidents automatically:

**Rule 1 — Brute Force by IP**

- Trigger: 10 or more EventID 4625 from the same IP within 1 hour
- Severity: Medium
- MITRE: T1110 — Brute Force
- Entity mapping: IP address

**Rule 2 — Brute Force by Account**

- Trigger: 10 or more EventID 4625 against the same account within 1 hour
- Severity: High
- MITRE: T1110.001 — Password Guessing
- Entity mapping: Account name

### GeoIP Enrichment

A 54,803-row GeoIP watchlist (`geoip-summarized.csv`) was used to enrich attacker IPs with city, country, latitude, and longitude. The watchlist uses CIDR ranges as the search key, requiring `ipv4_is_in_range()` matching in KQL rather than a direct join.

**KQL — GeoIP enrichment query:**

```kql
let topIPs = SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(72h)
| summarize Attempts = count() by IpAddress
| top 20 by Attempts desc;
topIPs
| extend dummy = 1
| join kind=leftouter (
    _GetWatchlist("geoip")
    | project network, countryname, cityname, latitude, longitude
    | extend dummy = 1
) on $left.dummy == $right.dummy
| where ipv4_is_in_range(IpAddress, network)
| summarize Attempts = max(Attempts), cityname = max(cityname), countryname = max(countryname),
            latitude = max(latitude), longitude = max(longitude) by IpAddress
| top 20 by Attempts desc
| project IpAddress, Attempts, cityname, countryname, latitude, longitude
```

---

## Phase 3 — Live Attack Data & Analysis

### Attack Volume (72 hours)

| Metric                                     | Value         |
| ------------------------------------------ | ------------- |
| Total failed logon attempts (EventID 4625) | 150,000+      |
| Peak hourly attempts                       | ~10,000       |
| Countries of origin                        | 15+           |
| Unique attacking IPs                       | 20+ tracked   |
| Primary target account                     | administrator |
| Time to first attack after exposure        | Under 1 hour  |

### Attack Map

![Attack Map](screenshots/honeynet-attack-map.png)

_World map of attacker IPs plotted by city using GeoIP watchlist enrichment. Bubble size represents attempt volume._

### Top Attacking IPs (72h)

| IP Address      | Attempts | City         | Country        |
| --------------- | -------- | ------------ | -------------- |
| 80.94.95.83     | 49,934   | Maarn        | Netherlands    |
| 80.66.83.43     | 23,144   | Düsseldorf   | Germany        |
| 20.113.160.179  | 10,705   | Cape Town    | South Africa   |
| 77.90.185.18    | 10,591   | Birmingham   | United Kingdom |
| 171.243.190.236 | 6,228    | Jacksonville | United States  |
| 116.101.0.113   | 6,222    | Gyeryong-si  | South Korea    |
| 182.186.41.179  | 6,218    | Ulju-gun     | South Korea    |
| 103.140.16.134  | 6,202    | Rawalpindi   | Pakistan       |
| 94.26.68.20     | 3,497    | Milan        | Italy          |
| 217.110.68.58   | 3,479    | Stuttgart    | Germany        |

### Attack Behaviour Analysis

Two distinct attack patterns were observed:

**Pattern 1 — Single account RDP brute force**

IPs such as `103.164.204.201` (1,562 attempts), `139.135.138.115` (1,428 attempts), and `183.83.33.10` (1,090 attempts) targeted exclusively the `administrator` account. This is characteristic of automated RDP bots that attempt a fixed set of common passwords against the default Windows administrator account.

**Pattern 2 — Dictionary/wordlist attack**

IPs such as `94.26.68.20` (Milan, 91 unique accounts) and `217.110.68.58` (Stuttgart, 72 unique accounts) attempted authentication against a wide range of account names including `GUARD`, `INSTALL`, `POSTMASTER`, `HOME`, `SYSADMIN`, `SUPPORT`, `STUDENT1`, `MASTER`, and `ROOT`. This indicates a wordlist-based attack targeting common service and default accounts.

**Coordinated scanning**

The two South Korean IPs (`116.101.0.113` and `182.186.41.179`) registered nearly identical attempt counts (6,222 and 6,218) within the same time window, suggesting coordinated scanning infrastructure operating in parallel.

### Attack Timechart

![Attack Timechart](screenshots/honeynet-timechart.png)

_Hourly attempt volume over 72 hours. The spike pattern reflects botnet scheduling — scanners rotate through targets and return in waves rather than attacking continuously. Peak of approximately 10,000 attempts in a single hour was recorded on March 9._

### Brute Force by IP Workbook

![Brute Force by IP](screenshots/honeynet-bruteforce-ip.png)

### Brute Force by Account Workbook

![Brute Force by Account](screenshots/honeynet-bruteforce-account.png)

_4,430 attempts against the `administrator` account in a single hour window, accounting for 100% of account-targeted attempts during peak activity._

---

## Phase 4 — Hardening & Before/After Comparison

After 72 hours, the NSG rules were restored to their original hardened state:

| Rule              | Port | Source               | Action |
| ----------------- | ---- | -------------------- | ------ |
| RDP               | 3389 | 213.156.101.217 only | Allow  |
| SSH               | 22   | 213.156.101.217 only | Allow  |
| All other inbound | Any  | Any                  | Deny   |

### Impact of Hardening

| Metric                    | Honeynet Open   | After Hardening |
| ------------------------- | --------------- | --------------- |
| Failed logons per hour    | Up to 10,000    | 0               |
| Sentinel incidents        | Multiple active | 0               |
| Exposed attack surface    | RDP, SSH, SMB   | None            |
| Attacking IPs reaching VM | 20+             | 0               |

Restoring a single IP-restriction rule on the NSG reduced inbound attack attempts to zero immediately, demonstrating the direct impact of network-layer access controls on exposure.

---

## Key Findings

1. **Internet-exposed RDP is attacked within minutes.** The Windows VM began receiving failed logon attempts within the first hour of exposure — no advertisement or targeting required.

2. **The `administrator` account is the primary target.** The majority of single-account brute force attempts targeted `administrator` exclusively, reinforcing the importance of disabling or renaming this account in production environments.

3. **Two distinct attack methodologies coexist.** Focused single-account RDP bots and broad wordlist scanners operate simultaneously and can be distinguished clearly through Sentinel workbooks.

4. **Coordinated scanning infrastructure is real and detectable.** Near-identical attempt counts from geographically separate IPs within the same time window is a clear indicator of organised botnet activity.

5. **NSG rules are the single most effective control.** One IP-restriction rule eliminated 100% of attack traffic immediately after the honeynet was closed.

---

## Tools & Technologies

| Category          | Technology                      |
| ----------------- | ------------------------------- |
| Cloud             | Microsoft Azure                 |
| SIEM              | Microsoft Sentinel              |
| Log ingestion     | Azure Monitor Agent (AMA) + DCR |
| Query language    | KQL                             |
| Threat enrichment | GeoIP watchlist (54,803 rows)   |
| Visualisation     | Sentinel Workbooks (5 custom)   |
| Network security  | Network Security Groups (NSG)   |
| Detection         | Scheduled Analytics Rules       |
| MITRE coverage    | T1110, T1110.001                |

## Related Project

This honeynet was built on top of an existing hybrid identity and security lab:

[AD + Azure Hybrid Security Lab](https://github.com/Moise10/active-directory-security-lab) — covers on-premises Active Directory, Azure Entra ID hybrid identity, network security, Key Vault, and Microsoft Sentinel log collection across a hybrid environment.
