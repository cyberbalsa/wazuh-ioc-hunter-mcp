---
name: threat-overview
description: "Get a quick overview of the current threat landscape in the Wazuh SIEM. Shows top alerts, active agents, severity distribution, and notable events. Use when the user wants a situational awareness briefing."
---

# Threat Overview Workflow

You are producing a threat landscape briefing from the Wazuh SIEM environment. Execute these queries in parallel and synthesize the results.

## Step 0: Load Network Map

Read `docs/network-map.md` to understand the lab topology — domains, hosts, IPs, users, groups, services, and trust relationships. This is essential for contextualizing which hosts are DCs vs member servers, which users are domain admins, and what trust paths exist.

## Step 1: Gather Data (run in parallel)

Execute all of these simultaneously:

1. **`get_agent_info`** (no agent_name) — list all agents with event counts and max severity
2. **`get_alerts`** with `severity: "critical"` — any critical alerts?
3. **`get_alerts`** with `severity: "high"` — high severity alerts
4. **`get_alerts`** with `severity: "medium"`, `max_results: 10` — medium severity sample
5. **`get_index_list`** with `pattern: "wazuh-alerts-*"` — data coverage and volume

## Step 2: Identify Top Threats

From the alerts gathered:
- Group alerts by **MITRE ATT&CK tactic** (Credential Access, Lateral Movement, Persistence, etc.)
- Group by **agent** to identify the most targeted/compromised hosts
- Identify any **rule groups** with unusual spikes (syscheck, authentication_failures, etc.)

## Step 3: Check for Active Attacks

Use `search_logs` to check for known attack patterns:
- `rule_level_min: 10, rule_group: "authentication_failures"` — credential attacks / brute force
- `query_string: "service" AND "created"` — persistence via new services
- `query_string: "pass-the-hash"` — NTLM lateral movement
- Check for suspicious filenames with `search_ioc` (type: filename) for any user-provided IOCs

## Step 4: Produce the Briefing

Format as a structured security briefing:

### Threat Overview Briefing

**Environment:**
- Total agents: X active
- Data coverage: [date range]
- Alert volume: X total alerts

**Severity Summary:**
- Critical: X alerts (list rule descriptions)
- High: X alerts (list rule descriptions)
- Medium: X alerts
- Low: X alerts

**Top Threats:**
1. [Threat name] — X events across Y hosts — MITRE: [tactic/technique]
2. [Threat name] — X events across Y hosts — MITRE: [tactic/technique]
3. ...

**Most Targeted Hosts:**
1. [agent name] (IP) — X high+ severity events — key rules: ...
2. ...

**Active Attack Indicators:**
- [List any ongoing or recent attack patterns found]

**Recommendations:**
- Priority 1: [Most urgent action]
- Priority 2: [Next action]
- ...
