# Successful RDP Logins

## Overview

Surfaces every successful RDP connection across the environment by parsing **Event ID 1149** from the `TerminalServices-RemoteConnectionManager/Operational` channel. Event 1149 fires when a user successfully passes RDP network authentication — making it a reliable, low-noise signal for tracking who is RDP-ing into which host, from where.

Useful as both a **scheduled hunt** (review external/unexpected source IPs) and a **pivot query** during incident triage (lateral movement reconstruction).

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Lateral Movement | **T1021.001** — Remote Services: Remote Desktop Protocol |
| Initial Access | **T1133** — External Remote Services (when source IP is external) |

## Data Source

- **Channel:** `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- **Event Code:** `1149`
- **Collected via:** Windows Event Forwarding (WEF) / Elastic Agent Windows integration

## Query (ES|QL)

```sql
FROM logs-*
| WHERE winlog.channel == "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" AND event.code == "1149"
| EVAL dest_ip = MV_FIRST(MV_SORT(host.ip))
| EVAL time_bucket = DATE_TRUNC(1 minute, @timestamp)
| STATS first_seen = MIN(@timestamp), event_count = COUNT(*) BY winlog.computer_name, dest_ip, winlog.user_data.Param1, winlog.user_data.Param2, winlog.user_data.Param3, time_bucket
| EVAL first_seen_fmt = DATE_FORMAT("MM/dd/yy hh:mm:ss a", first_seen)
| RENAME winlog.user_data.Param1 AS user.name, winlog.user_data.Param2 AS user.domain, winlog.user_data.Param3 AS source.ip, winlog.computer_name AS destination.host, dest_ip AS destination.ip
| KEEP user.name, user.domain, source.ip, destination.host, destination.ip, first_seen_fmt, event_count
| WHERE `user.domain` != "<INTERNAL_DOMAIN>"   -- optional: exclude a known-noisy internal domain
```

## How It Works

1. **Filter** to Event ID 1149 on the TerminalServices RemoteConnectionManager channel — only successful RDP network authentications.
2. **`MV_FIRST(MV_SORT(host.ip))`** — hosts often report multiple IPs (IPv4 + IPv6 + virtual adapters); sorting and taking the first gives a deterministic single destination IP per host.
3. **`DATE_TRUNC(1 minute, ...)`** — buckets events into 1-minute windows so rapid reconnects collapse into one row instead of spamming results.
4. **`STATS ... BY`** — aggregates per user / source IP / destination host / minute, keeping the earliest timestamp and a count.
5. **Param mapping** — Event 1149 stores its data in generic `user_data` params: `Param1` = username, `Param2` = domain, `Param3` = source IP. The `RENAME` maps these to ECS-style field names for readability.
6. **Domain exclusion** — optional final filter to remove a high-volume internal domain that is reviewed by a separate process.

## Tuning & False Positives

- Event 1149 fires on **successful network-layer auth**, before the interactive session is fully established. It will not catch failed attempts (see [Rule 02](02-rdp-failed-logins-brute-force.md)).
- Expect noise from jump boxes, RMM tools, and admin workstations — build an allowlist of expected source IPs or admin accounts.
- If `Param3` is an internal RFC1918 address, this is internal lateral movement; if public, investigate immediately (RDP should not be internet-exposed).

## Triage Steps

1. Is the **source IP** expected for this user? (VPN pool, office egress, jump host)
2. Is the **destination host** something this user normally accesses?
3. Correlate with Security channel **4624 LogonType 10** on the destination host for full session details.
4. Check for follow-on activity: new processes, service installs (7045), scheduled tasks (4698), account changes.
5. If source is external/public: check firewall for RDP exposure, review for brute-force history against the same host.
