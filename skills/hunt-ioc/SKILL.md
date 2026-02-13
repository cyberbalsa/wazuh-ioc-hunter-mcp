---
name: hunt-ioc
description: "Hunt for an Indicator of Compromise (IOC) across Wazuh SIEM data. Use when the user provides an IP address, file hash, domain, URL, or filename to investigate. Searches across all Wazuh alert data and provides context around any findings."
argument-hint: "[IOC value — IP, hash, domain, URL, or filename]"
---

# IOC Hunt Workflow

You are performing an IOC (Indicator of Compromise) hunt against a Wazuh SIEM environment. Follow this structured workflow using the wazuh-ioc-hunter MCP tools.

## Step 0: Load Network Context

Read `docs/network-map.md` to understand the lab topology. This helps you contextualize findings — for example, knowing which IPs belong to which hosts, which users are legitimate admins vs. suspicious, and what trust relationships exist between domains.

## Step 1: Classify the IOC

Determine the IOC type from the user's input:
- **IP address** (e.g. `10.0.0.1`, `203.0.113.50`) → `ioc_type: "ip"`
- **File hash** (SHA256/MD5/SHA1) → `ioc_type: "hash"`
- **Domain** (e.g. `evil.example.com`) → `ioc_type: "domain"`
- **URL** (contains path like `/malware/payload`) → `ioc_type: "url"`
- **Filename** (e.g. `suspicious.exe`, `payload.dll`) → `ioc_type: "filename"`
- **Unknown** → `ioc_type: "auto"` (searches all fields)

## Step 2: Search for the IOC

Use `search_ioc` with the classified type. Start with the default time window. If no results:
1. Try `ioc_type: "auto"` for broader field coverage
2. Widen the window with `hours_back: 48` (syscheck detections are delayed from scheduled scans)
3. Try `search_logs` with the IOC value as a quoted `query_string` for full-text search

## Step 3: Analyze Findings

For each hit, extract and report:
- **When**: Timestamp of the event
- **Where**: Agent name, agent IP, affected host
- **What**: Rule description, syscheck event type, file paths
- **Severity**: Rule level and MITRE ATT&CK mapping if available
- **Hashes**: SHA256/MD5 values for file-based IOCs

## Step 4: Pivot and Expand

Based on findings, automatically pivot:
- If a **filename** is found → extract its SHA256 hash and search for that hash on other hosts
- If an **IP** is found → check which agents communicated with it
- If found on a **host** → use `investigate_host` to get full context on that agent
- If a **rule** triggered → use `get_rule_info` to understand the detection and which other hosts triggered it

## Step 5: Report

Provide a structured summary:
1. **IOC**: The value searched and its type
2. **Verdict**: Found/Not Found in Wazuh data
3. **Timeline**: Chronological sequence of events
4. **Affected Hosts**: List of agents where the IOC appeared
5. **Related IOCs**: Any hashes, IPs, or filenames discovered during pivoting
6. **MITRE ATT&CK**: Relevant tactics and techniques
7. **Recommendations**: Next investigation steps

## Important Notes

- BAM registry entries (`syscheck.value_name`) show exe execution but are detected on delayed syscheck scheduled scans (may appear hours or days after actual execution)
- Use wider `hours_back` for syscheck/registry artifacts than for real-time events
- Keep smaller `hours_back` for real-time events (logon, service creation, errors)
