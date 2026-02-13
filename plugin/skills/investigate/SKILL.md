---
name: investigate
description: "Deep investigation of a specific host/agent in the Wazuh SIEM. Use when the user wants to analyze a compromised or suspicious system. Provides severity breakdown, executed programs, registry changes, login activity, and timeline."
argument-hint: "[agent/host name]"
---

# Host Investigation Workflow

You are performing a deep-dive investigation of a specific host in the Wazuh SIEM environment. Follow this structured workflow.

## Step 1: Identify the Target

Parse the user's input for:
- An **agent name** (the Wazuh agent hostname)
- An **agent ID** (numeric ID)
- If neither is provided, use `get_agent_info` to list all agents and ask the user to pick one

## Step 2: Get the Overview

Use `investigate_host` with the agent name. This runs 5 parallel queries and returns:
- Agent metadata (ID, IP, OS)
- Severity distribution (low/medium/high/critical event counts)
- Executables seen via BAM registry (with SHA256 hashes)
- High severity events with full log context
- Login activity (users, source IPs, logon types)
- Top triggered rules
- Activity timeline (6-hour buckets)

Start with the default `hours_back` for the attack window, then expand to `hours_back: 48` for delayed syscheck artifacts.

## Step 3: Analyze Executables

From the BAM registry entries:
- Flag any **suspicious executables** (unusual names, paths like `\Temp\`, `\Downloads\`, `\AppData\`)
- Note execution by **user context** (extracted from the registry path SID)
- For each suspicious exe, use `search_ioc` with `ioc_type: "filename"` and wider `hours_back` to find it on other hosts (lateral movement indicator)
- Cross-reference SHA256 hashes — same hash on multiple hosts = same binary spreading

## Step 4: Analyze Authentication

Look for:
- **Remote logons** with NTLM (pass-the-hash indicators)
- **Unusual user accounts** logging into the host
- **Failed logon bursts** (brute force / credential stuffing)
- **Lateral movement patterns** — use `search_logs` with the suspect username as `query_string`

## Step 5: Analyze High Severity Events

For any Level 7+ events:
- Use `get_rule_info` to get full rule details, MITRE ATT&CK mappings, and affected-agent counts
- Check if the same rule fired on other hosts (spreading/coordinated attack)
- Note any **"New Windows Service Created"** events (persistence mechanism)
- Note any **application errors** around the attack time (payload execution artifacts)

## Step 6: Build the Timeline

Construct a chronological narrative:
1. Initial access (how the attacker got in)
2. Execution (what ran, what services were created)
3. Persistence (registry changes, services, scheduled tasks)
4. Lateral movement (remote logons to other hosts)
5. Impact (what the attacker achieved)

## Step 7: Report

Provide:
1. **Host Summary**: Name, IP, OS, role in the attack (initial access, pivot point, target)
2. **Compromise Timeline**: Chronological event sequence
3. **Indicators Found**: Filenames, hashes, IPs, usernames
4. **MITRE ATT&CK Mapping**: Tactics and techniques observed
5. **Lateral Movement**: Which other hosts were accessed from/to this host
6. **Recommendations**: Containment and remediation steps
