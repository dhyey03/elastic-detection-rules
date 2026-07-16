# Suspicious Inbox Rule Creation (O365)

## Overview

Detects the creation or modification of **Exchange Online inbox rules** (`New-InboxRule` / `Set-InboxRule`) from IP addresses outside the organization's trusted egress ranges. Inbox rules are one of the most common post-compromise actions in Business Email Compromise (BEC): attackers create rules to **auto-delete or auto-move security warnings, hide replies during invoice-fraud threads, or forward mail externally**.

Because legitimate users usually manage rules from known office/VPN IPs, the trusted-IP exclusion makes this rule high signal.

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Collection | **T1114.003** — Email Collection: Email Forwarding Rule |
| Defense Evasion | **T1564.008** — Hide Artifacts: Email Hiding Rules |

## Data Source

- **Dataset:** `o365.audit` (Exchange Online audit via the O365 integration)
- Key fields: `event.action`, `o365.audit.ClientIP`, `o365.audit.Parameters.*`

## Query (KQL — Security Detection Rule)

```
event.dataset:o365.audit and
(event.action : "New-InboxRule" or event.action : "Set-InboxRule") and
not o365.audit.ClientIP : (
  "<TRUSTED_IP_1>" or
  "<TRUSTED_IP_2>" or
  "<TRUSTED_IP_3>" or
  "<TRUSTED_IP_4>" or
  "<TRUSTED_IP_5>" or
  "<TRUSTED_IP_6>" or
  "<TRUSTED_IP_7>" or
  "<TRUSTED_IP_8>" or
  "<TRUSTED_IP_9>" or
  "<TRUSTED_IP_10>" or
  "<TRUSTED_IP_11>" or
  "<TRUSTED_CIDR_1>" or
  "<TRUSTED_CIDR_2>"
)
```

## How It Works

1. **Action filter** — `New-InboxRule` catches rule creation; `Set-InboxRule` catches modification of an existing rule (attackers sometimes repurpose an existing benign rule to evade "new rule" detections).
2. **ClientIP exclusion** — a `not ... : (a or b or ...)` list of trusted office, data center, and VPN egress IPs/CIDRs. Anything created from outside these ranges alerts.
3. Deployed as a **KQL custom query rule** in the Elastic Security app (rather than ES|QL) so each matching event generates its own alert with full document context for the triage timeline.

## Tuning & False Positives

- Users legitimately create rules from home/mobile — the volume is usually low enough to review each alert, but if noisy, add a second condition targeting *suspicious rule properties*: `DeleteMessage`, `MoveToFolder` (RSS Subscriptions / Conversation History / Archive are attacker favorites), `ForwardTo` / `RedirectTo` external domains, or rule names that are single characters (`"."`, `","`, `".."`).
- Maintain the trusted-IP list in an **Elastic exception list** instead of hardcoding, so it can be updated without editing the rule and reused across rules.
- Consider a companion rule for `Set-Mailbox` with forwarding SMTP address changes and `Remove-InboxRule` (attackers cleaning up).

## Triage Steps

1. Pull the rule parameters from `o365.audit.Parameters`: **name, conditions, and actions**. Deletion/forwarding/moving-to-obscure-folder actions are the red flags.
2. Geolocate and reputation-check the ClientIP (VPN? hosting provider? foreign?).
3. Check the user's recent sign-in history for the same IP — correlate with [Rule 03 (Impossible Travel)](03-impossible-travel.md) and [Rule 04 (MFA changes)](04-mfa-auth-method-change.md).
4. Review the mailbox for the pattern the rule is hiding: vendor invoice threads, payroll-change requests, password-reset emails.
5. If malicious: disable the rule, revoke sessions and tokens, reset credentials, search for other rules across the tenant (`Get-InboxRule` sweep), and notify affected counterparties if BEC fraud was in flight.
