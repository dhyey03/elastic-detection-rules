# System Restart / Shutdown Timeline (Investigation Query)

## Overview

An **investigation/triage query** (not a scheduled detection) that reconstructs a precise timeline of shutdown, startup, crash, and service-state events on a specific host during a defined time window. Used when an agent unexpectedly went offline (see [Rule 05](05-fleet-agent-delta.md)), when a server crashed, or when verifying whether a reboot was clean, user-initiated, or unexpected — the last of which can indicate tampering, a crash caused by an exploit, or an attacker rebooting to apply persistence.

This query was originally built during an investigation into suspicious authentication activity (Kerberos ticket abuse hypothesis) where establishing whether the domain controller/database host rebooted cleanly during the suspect window was a key triage question.

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Impact | **T1529** — System Shutdown/Reboot |
| Defense Evasion | **T1562** — Impair Defenses (unexpected restarts can clear volatile evidence or restart tampered services) |

## Data Source

- **Channel:** Windows System log
- **Event Codes:**

| Code | Meaning |
|---|---|
| `1074` | A process/user initiated a shutdown or restart (includes who and why) |
| `6005` | Event Log service started (system boot marker) |
| `6006` | Event Log service stopped (clean shutdown marker) |
| `6008` | **Unexpected shutdown** (crash, power loss — no clean 6006 before boot) |
| `7036` | Service entered running/stopped state (Service Control Manager) |

## Query (ES|QL)

```sql
FROM logs-system.system*
| WHERE data_stream.namespace == "<TENANT_NAMESPACE>"
| WHERE host.name == "<HOSTNAME>"
| WHERE @timestamp >= TO_DATETIME("<WINDOW_START_ISO8601>")
  AND @timestamp <= TO_DATETIME("<WINDOW_END_ISO8601>")
| WHERE event.code IN ("1074", "6005", "6006", "6008", "7036")
| KEEP @timestamp, event.code, message
| SORT @timestamp ASC
```

Example window values: `"2026-01-01T15:55:00Z"` / `"2026-01-01T16:35:00Z"` — set these to bracket the incident time (±20 minutes is a good starting point).

## How It Works

1. **Scope tightly** — one tenant namespace, one host, one bounded time window. Investigation queries should be surgical, not broad.
2. **Event code set** — the five codes together tell a complete reboot story: 1074 (who/why) → 6006 (clean stop) → 6005 (boot) is a *clean* restart; 6005 **without** a preceding 6006, or a 6008, is a *crash or hard power event*. 7036 fills in which services stopped/started around the boundary.
3. **`KEEP` + `SORT ASC`** — minimal columns in chronological order produce a readable narrative timeline for the incident notes.

## Interpretation Guide

| Pattern | Reading |
|---|---|
| 1074 → 6006 → 6005 | Clean, initiated restart. Check the 1074 message for the initiating **user and process** — `winlogon.exe`/admin = manual, `wuauclt`/`MoUsoCoreWorker` = Windows Update |
| 6005 with no prior 6006 | Hard crash or power pull — correlate with 6008 and hardware logs |
| 6008 | Confirmed unexpected shutdown |
| 7036 storms before shutdown | Note *which* services stopped — security tooling stopping before an "unexpected" reboot is a red flag |

## Triage Steps

1. Read the **1074 message**: initiating account, process, and stated reason. An unexpected account (service account, remote admin session) initiating a reboot deserves follow-up.
2. If the reboot was during a suspected credential-abuse window (e.g. Kerberoasting/ticket-forging hypothesis), correlate with Security-channel events on the DC: 4769 (TGS requests, RC4 encryption `0x17`), 4768, 4624 from unusual sources.
3. Cross-check with Fleet/EDR agent status (Rule 05) to confirm the offline gap matches the reboot window exactly — a mismatch suggests the agent was stopped separately from the reboot.
4. Verify patching/RMM schedules before escalating — most reboots are maintenance.
