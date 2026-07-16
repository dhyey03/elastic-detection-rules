# Impossible Travel Detection

## Overview

Detects a single identity logging in successfully from **geographically distant locations within a 15-minute window** — physically impossible travel that strongly indicates session hijacking, credential theft, or token replay (e.g. AiTM phishing).

Fires on either of two conditions:
- Logins from **more than one country**, or
- Logins from **multiple states AND multiple cities AND multiple IPs** (catches domestic anomalies that a country-only check would miss).

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Initial Access / Defense Evasion | **T1078.004** — Valid Accounts: Cloud Accounts |
| Credential Access | **T1539** — Steal Web Session Cookie (AiTM token theft often presents as impossible travel) |

## Data Source

- O365 / Entra ID sign-in audit logs (or any identity source producing `event.action: login_success` with `source.geo` enrichment)
- Requires **GeoIP enrichment** on `source.ip`

## Query (ES|QL)

```sql
FROM logs-* METADATA _id
| WHERE event.action == "login_success"
| WHERE event.outcome == "success"
| WHERE source.ip IS NOT NULL
| WHERE source.geo.country_iso_code IS NOT NULL
| EVAL user_id = COALESCE(user.email, o365.audit.UserId, user.name)
| WHERE user_id IS NOT NULL
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), login_count = COUNT(*),
        ips = VALUES(source.ip), countries = VALUES(source.geo.country_iso_code),
        country_names = VALUES(source.geo.country_name), states = VALUES(source.geo.region_name),
        cities = VALUES(source.geo.city_name), emails = VALUES(user.email),
        username = MAX(user.name), namespace = MAX(data_stream.namespace),
        user_agents = VALUES(user_agent.original), os_names = VALUES(user_agent.os.name),
        browser_names = VALUES(user_agent.name), event_ids = VALUES(_id)
  BY user_id
| EVAL country_count = MV_COUNT(MV_DEDUPE(countries)),
       state_count = MV_COUNT(MV_DEDUPE(states)),
       city_count = MV_COUNT(MV_DEDUPE(cities)),
       ip_count = MV_COUNT(MV_DEDUPE(ips)),
       span_seconds = DATE_DIFF("seconds", first_seen, last_seen),
       span_minutes = ROUND(span_seconds / 60.0, 1),
       countries = MV_CONCAT(TO_STRING(countries), ", "),
       states = MV_CONCAT(TO_STRING(states), ", "),
       cities = MV_CONCAT(TO_STRING(cities), ", "),
       ips = MV_CONCAT(TO_STRING(ips), ", "),
       user_agents = MV_CONCAT(TO_STRING(user_agents), " | ")
| WHERE login_count >= 2
| WHERE span_minutes <= 15
| WHERE country_count > 1 OR (state_count > 1 AND city_count > 1 AND ip_count > 1)
| SORT span_seconds ASC
| KEEP user_id, username, emails, namespace, login_count, country_count, countries, state_count, states, city_count, cities, ip_count, ips, first_seen, last_seen, span_minutes, user_agents, os_names, browser_names, event_ids
```

## How It Works

1. **Identity normalization** — `COALESCE(user.email, o365.audit.UserId, user.name)` builds a single stable `user_id` across log sources that populate different identity fields.
2. **Per-user aggregation** — `STATS ... BY user_id` collapses all successful logins per user in the query time range, collecting every distinct IP, country, state, city, and user agent via `VALUES()`.
3. **Cardinality math** — `MV_COUNT(MV_DEDUPE(...))` counts *unique* locations. `MV_CONCAT` flattens the multivalue fields into readable comma-separated strings for the analyst.
4. **Time-window constraint** — `span_minutes <= 15` between first and last login makes the travel "impossible" rather than just "frequent traveler."
5. **Two-tier trigger** — multi-country is always suspicious; the domestic tier requires state + city + IP all to differ, reducing GeoIP-jitter false positives.
6. **`event_ids = VALUES(_id)`** — every raw document ID is preserved so the analyst can pivot straight to the underlying events.
7. **`SORT span_seconds ASC`** — tightest (most impossible) windows float to the top.

## Tuning & False Positives

- **VPNs and mobile carriers** are the #1 FP source — a user switching from office Wi-Fi to cellular can jump cities in GeoIP. The user-agent columns help spot this (same device/browser on both logins = likely benign network change).
- **Cloud proxy / SASE egress** (Zscaler, iCloud Private Relay) causes country-level jumps. Maintain an allowlist of known proxy egress ranges.
- Run as a scheduled ES|QL rule with lookback ≥ the 15-minute span (e.g. run every 15 min over the last 30 min).
- Tighten by requiring `country_count > 1` only, or loosen span to 60 min for slower token-replay patterns.

## Triage Steps

1. Compare **user agents and OS** across both logins — different device families in different countries is high-confidence compromise.
2. Check whether either IP belongs to a known **VPN/proxy/hosting provider** (ASN lookup).
3. Review what the suspicious session **did**: inbox rules created (Rule 07), MFA changes (Rule 04), mail access, file downloads.
4. If confirmed: revoke sessions, reset credentials, revoke refresh tokens, review MFA methods, and check for persistence.
