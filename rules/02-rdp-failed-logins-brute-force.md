# Failed RDP Logins (Brute Force / Password Guessing)

## Overview

Hunts failed network and RDP logons (**Event ID 4625**) caused specifically by a **bad password against a valid username** — the classic brute-force / password-spray signature. Filtering on the NTSTATUS sub-status codes eliminates unrelated 4625 noise (expired passwords, disabled accounts, time restrictions).

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Credential Access | **T1110.001** — Brute Force: Password Guessing |
| Credential Access | **T1110.003** — Brute Force: Password Spraying |

## Data Source

- **Channel:** Windows Security
- **Event Code:** `4625` (An account failed to log on)
- **Logon Types:** `3` (Network) and `10` (RemoteInteractive / RDP)

## Query (ES|QL)

```sql
FROM logs-* METADATA _id, _version, _index
| WHERE data_stream.namespace == "<TENANT_NAMESPACE>"
| WHERE event.code == "4625"
| WHERE winlog.event_data.LogonType IN ("3", "10")
| WHERE winlog.event_data.Status == "0xc000006d"
| WHERE winlog.event_data.SubStatus == "0xc000006a"
| EVAL username = COALESCE(winlog.event_data.TargetUserName, user.name)
| EVAL domain = winlog.event_data.TargetDomainName
| EVAL source_ip = COALESCE(winlog.event_data.IpAddress, TO_STRING(source.ip))
| WHERE NOT user.name RLIKE ".*\\$$"
| WHERE NOT ENDS_WITH(user.name, "$")
| EVAL event_time = DATE_FORMAT("MM/dd/yyyy hh:mm:ss a", @timestamp)
| KEEP _id, _version, _index, event_time, host.name, user.name, domain, source_ip, winlog.event_data.LogonType, winlog.event_data.Status, winlog.event_data.SubStatus, winlog.event_data.FailureReason
| SORT event_time DESC
```

## How It Works

1. **`METADATA _id, _version, _index`** — carries document metadata through the pipeline so each result row links directly back to the raw event in Discover for pivoting.
2. **Namespace scoping** — in a multi-tenant deployment, `data_stream.namespace` isolates the hunt to one client tenant.
3. **Status code filtering** — the key precision step:
   - `Status 0xC000006D` = `STATUS_LOGON_FAILURE` (bad credentials)
   - `SubStatus 0xC000006A` = **correct username, wrong password**
   This combination confirms the attacker knows (or guessed) a valid account name — far more interesting than `0xC0000064` (nonexistent user).
4. **Logon types 3 and 10** — network auth (SMB, NLA pre-auth for RDP) and RemoteInteractive (RDP). NLA-enabled RDP failures often log as Type 3, so both must be included.
5. **Machine account exclusion** — `RLIKE ".*\\$$"` and `ENDS_WITH(..., "$")` drop computer accounts (e.g. `WORKSTATION01$`), which fail routinely due to clock skew or stale credentials and are almost never brute-force targets.
6. **`COALESCE` fallbacks** — different agents/pipelines populate either `winlog.event_data.*` or the ECS field, so both are checked.

## Tuning & False Positives

- A single failure is not brute force — look for **volume and velocity** per `source_ip` + `user.name`. To alert (rather than hunt), wrap in `STATS COUNT(*) BY source_ip, user.name` with a threshold (e.g. ≥10 failures in 5 minutes).
- Common benign causes: users mistyping after a password change, saved credentials in RDP clients / mapped drives, service accounts with rotated passwords.
- Watch for the **spray pattern**: one source IP, many usernames, 1–3 attempts each — the per-user count stays low but the source-IP count is high.

## Triage Steps

1. Count failures per source IP — internal or external?
2. Check whether the targeted account **subsequently logged in successfully** (4624 / Rule 01) from the same source — that flips this from "attempt" to "compromise."
3. If external source: confirm whether RDP/SMB is internet-exposed on the firewall; block the IP; check threat intel (AbuseIPDB, MISP).
4. If internal source: identify the process/host generating attempts — could be malware spreading laterally or a misconfigured service.
5. Consider account lockout status (4740) and notify the account owner if credentials may be known to the attacker.
