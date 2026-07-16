# Elastic Detection Rules

A library of production-tested detection queries for Elastic Security (ES|QL and KQL), built for multi-tenant SOC environments. Each rule is mapped to MITRE ATT&CK, documented with a line-by-line query breakdown, and includes tuning guidance and triage steps.

> **Note:** All IP addresses, tenant namespaces, hostnames, and domains have been replaced with placeholders (e.g. `<TRUSTED_IP_1>`, `<TENANT_NAMESPACE>`). Populate these with your own environment values before deploying.

## Rule Index

| # | Rule | Data Source | MITRE ATT&CK | Language |
|---|------|------------|--------------|----------|
| 1 | [Successful RDP Logins](rules/01-rdp-successful-logins.md) | Windows TerminalServices logs | T1021.001 (Remote Services: RDP) | ES\|QL |
| 2 | [Failed RDP Logins (Brute Force)](rules/02-rdp-failed-logins-brute-force.md) | Windows Security (4625) | T1110 (Brute Force) | ES\|QL |
| 3 | [Impossible Travel](rules/03-impossible-travel.md) | O365 / identity provider audit logs | T1078 (Valid Accounts) | ES\|QL |
| 4 | [MFA / Strong Auth Method Change](rules/04-mfa-auth-method-change.md) | O365 audit logs | T1098.005 (Account Manipulation: Device Registration) | ES\|QL |
| 5 | [Fleet Agent Offline/Unhealthy Delta](rules/05-fleet-agent-delta.md) | Fleet Server agent metrics | T1562.001 (Impair Defenses: Disable Security Tools) | ES\|QL |
| 6 | [System Restart / Shutdown Timeline](rules/06-system-restart-timeline.md) | Windows System logs | T1529 (System Shutdown/Reboot) | ES\|QL |
| 7 | [Suspicious Inbox Rule Creation](rules/07-inbox-rule-creation.md) | O365 Exchange audit logs | T1114.003 (Email Forwarding Rule), T1564.008 (Hide Artifacts: Email Rules) | KQL |

## Environment

- **SIEM:** Elastic Security (Elastic Stack 8.x)
- **Query languages:** ES|QL for scheduled detections and hunts, KQL for detection rules in the Security app
- **Log sources:** Windows Event Forwarding (WEF), Elastic Defend, O365 audit, Azure, Fleet Server metrics
- **Architecture:** Multi-tenant, with tenants separated by `data_stream.namespace`

## Placeholder Conventions

| Placeholder | Meaning |
|---|---|
| `<TENANT_NAMESPACE>` | `data_stream.namespace` value identifying a client tenant |
| `<TRUSTED_IP_n>` | Known-good egress IPs (offices, data centers, VPN gateways) |
| `<TRUSTED_CIDR>` | Known-good IP range |
| `<INTERNAL_DOMAIN>` | Internal AD domain to exclude from results |
| `<EXCLUDED_EMAIL_DOMAIN>` | Email domain excluded from alerting (e.g. student tenant) |
| `<HOSTNAME>` | Specific host under investigation |

## Repo Structure

```
elastic-detection-rules/
├── README.md
└── rules/
    ├── 01-rdp-successful-logins.md
    ├── 02-rdp-failed-logins-brute-force.md
    ├── 03-impossible-travel.md
    ├── 04-mfa-auth-method-change.md
    ├── 05-fleet-agent-delta.md
    ├── 06-system-restart-timeline.md
    └── 07-inbox-rule-creation.md
```

## Disclaimer

These queries are shared for educational and portfolio purposes. All environment-specific identifiers have been removed. Test in a non-production space and tune thresholds/allowlists before enabling in production.
