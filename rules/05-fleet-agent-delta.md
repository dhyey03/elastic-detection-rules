# Fleet Agent Offline / Unhealthy Delta

## Overview

Alerts when the number of **offline or unhealthy Elastic Agents increases** within the last 5 minutes compared to the preceding 10 minutes. A sudden jump in offline agents can mean an attacker is disabling endpoint sensors before acting (defense evasion), a site-wide outage, or a botched agent upgrade — all of which a SOC needs to know about within minutes, because every offline agent is a blind spot.

This is an **operational + security hybrid detection**: it monitors the health of the monitoring itself.

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Defense Evasion | **T1562.001** — Impair Defenses: Disable or Modify Tools |
| Defense Evasion | **T1489** — Service Stop (agent service killed) |

## Data Source

- **Index:** `metrics-fleet_server.agent_status-default`
- Key fields: `fleet.agents.offline`, `fleet.agents.unhealthy` (point-in-time gauge values reported by Fleet Server)

## Query (ES|QL)

```sql
FROM metrics-fleet_server.agent_status-default
| WHERE @timestamp >= NOW() - 15 minutes
| EVAL bucket = CASE(@timestamp >= NOW() - 5 minutes, "recent", "older")
| STATS max_offline = MAX(fleet.agents.offline),
        max_unhealthy = MAX(fleet.agents.unhealthy)
  BY bucket
| STATS recent_offline = MAX(CASE(bucket == "recent", max_offline, NULL)),
        older_offline = MAX(CASE(bucket == "older", max_offline, NULL)),
        recent_unhealthy = MAX(CASE(bucket == "recent", max_unhealthy, NULL)),
        older_unhealthy = MAX(CASE(bucket == "older", max_unhealthy, NULL))
| EVAL delta_offline = recent_offline - older_offline,
       delta_unhealthy = recent_unhealthy - older_unhealthy
| WHERE delta_offline >= 1 OR delta_unhealthy >= 1
```

## How It Works

1. **15-minute lookback, two buckets** — `CASE()` splits the window into `recent` (last 5 min) and `older` (5–15 min ago). This is a self-contained baseline: no external state or transform needed.
2. **First STATS** — takes the peak offline/unhealthy gauge value within each bucket.
3. **Second STATS (pivot)** — the conditional `MAX(CASE(...))` pattern pivots the two bucket rows into a single row with four columns, enabling direct subtraction. This is the standard ES|QL workaround for comparing time buckets, since ES|QL has no native lag/lead function.
4. **Delta computation** — `recent − older`. A positive delta means agents went offline/unhealthy *within the last 5 minutes*.
5. **Threshold** — any increase (`>= 1`) fires. Because it compares deltas rather than absolute counts, a fleet that permanently has some offline agents won't alert continuously — only *changes* alert.

## Tuning & False Positives

- **Patch windows and planned reboots** cause benign spikes — suppress during maintenance windows or raise the threshold to `>= 3` for large fleets.
- Laptop fleets naturally flap (sleep/wake, travel). Consider running this against server-heavy policies only, or lengthen the "recent" bucket.
- Schedule the rule to run every 5 minutes so the buckets tile cleanly.

## Triage Steps

1. Open **Fleet → Agents**, filter by offline/unhealthy, and identify *which* agents changed state.
2. One host? Check if the machine is up (ping, RDP, console) — if the host is alive but the agent is dead, treat as possible tampering: pull the agent/endpoint service logs and look for service-stop events (7036), process kills, or uninstall activity.
3. Many hosts at one site? Likely network/site outage — confirm with the firewall/switch monitoring.
4. Many hosts after a policy/agent update? Roll back and check Fleet server logs.
5. If tampering is suspected, isolate the host via EDR from another control plane if available and preserve logs before reboot.
