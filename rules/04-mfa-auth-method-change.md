# MFA / Strong Authentication Method Change (O365)

## Overview

Detects when a user account's **StrongAuthenticationMethod** (MFA method) is modified in O365/Entra ID from an IP address **outside the organization's trusted egress ranges**. Attackers who phish credentials or steal session tokens routinely register their own MFA device as a persistence mechanism — this rule catches that move.

The query correlates two event types per user: `UserLoggedIn` (to capture the source IP context) and `modified-user-account` with a non-null `StrongAuthenticationMethod.NewValue` (the actual MFA change).

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Persistence | **T1098.005** — Account Manipulation: Device Registration |
| Persistence | **T1556.006** — Modify Authentication Process: Multi-Factor Authentication |

## Data Source

- **Dataset:** `o365.audit` (Azure AD / Entra ID audit events via the O365 integration)
- Key fields: `event.action`, `o365.audit.ModifiedProperties.StrongAuthenticationMethod.NewValue`, `related.ip`, `related.user`

## Query (ES|QL)

```sql
FROM logs-* METADATA _id
| WHERE (event.action == "UserLoggedIn"
    OR (event.action == "modified-user-account"
        AND o365.audit.ModifiedProperties.StrongAuthenticationMethod.NewValue IS NOT NULL))
| STATS max_timestamp = MAX(@timestamp),
        Event_Actions = VALUES(event.action),
        IPs = VALUES(related.ip),
        Properties = VALUES(o365.audit.ModifiedProperties.StrongAuthenticationMethod.NewValue),
        Cities = VALUES(source.geo.city_name),
        Countries = VALUES(source.geo.country_iso_code),
        Emails = VALUES(COALESCE(user.email))
  BY related.user
| EVAL Event_Actions = MV_CONCAT(TO_STRING(Event_Actions), " ")
| WHERE TO_STRING(Event_Actions) LIKE "*modified-user-account*"
| WHERE NOT (TO_STRING(IPs) IN (
    "<TRUSTED_IP_1>",   -- data center egress
    "<TRUSTED_IP_2>",   -- office location A
    "<TRUSTED_IP_3>",   -- office location B
    "<TRUSTED_IP_4>", "<TRUSTED_IP_5>",   -- colo / secondary sites
    "<TRUSTED_IP_6>", "<TRUSTED_IP_7>", "<TRUSTED_IP_8>", "<TRUSTED_IP_9>", "<TRUSTED_IP_10>",  -- branch routers
    "<TRUSTED_IP_11>"   -- corporate HQ
  ))
| WHERE NOT CIDR_MATCH(IPs, "<TRUSTED_CIDR>")   -- trusted campus/ISP range
| WHERE NOT (TO_STRING(Emails) LIKE "*@<EXCLUDED_EMAIL_DOMAIN>*")   -- excluded sub-tenant
```

## How It Works

1. **Dual-event capture** — pulls both login events and MFA-modification events so that the aggregation per `related.user` carries the source IPs and geo of the surrounding sign-in activity, not just the change event itself.
2. **Per-user STATS** — collects all IPs, cities, countries, and the new MFA method values seen for the user in the window.
3. **`LIKE "*modified-user-account*"`** — after aggregation, keeps only users who actually had an MFA change (login-only users are dropped).
4. **Trusted-IP allowlist** — changes made from office/data center/VPN egress IPs are expected (helpdesk-assisted enrollments, onboarding). Everything else surfaces for review.
5. **CIDR exclusion** — excludes an entire trusted range in one expression instead of listing every IP.
6. **Email-domain exclusion** — filters out a sub-tenant whose MFA enrollments are managed separately (high-volume, low-risk population).

## Tuning & False Positives

- **New-hire onboarding** and phone upgrades are the main benign causes — users enrolling MFA from home. Consider correlating with account-creation date or an HR onboarding feed.
- Keep the allowlist in a **lookup index or saved list** rather than hardcoded IPs where possible, so updates don't require editing the rule.
- Consider adding `Properties` filtering to prioritize additions of **new phone numbers / authenticator apps** over method reordering.

## Triage Steps

1. What is the **new MFA method value**? A new phone number or authenticator registration is far more suspicious than a method being removed or reordered.
2. Where is the source IP? Residential ISP near the user's home = probably benign; hosting provider/VPN/foreign country = escalate.
3. Was the change **preceded by an unusual login** (check Rule 03 impossible travel, risky sign-in)?
4. Contact the user out-of-band to confirm they made the change.
5. If unauthorized: remove the attacker's MFA method, revoke all sessions/tokens, reset credentials, and audit inbox rules (Rule 07) and app consents.
