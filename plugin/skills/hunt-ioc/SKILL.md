---
name: hunt-ioc
description: "Hunt for an Indicator of Compromise (IOC) across Wazuh SIEM data. Use when the user provides an IP address, file hash, domain, URL, or filename to investigate. Searches across all Wazuh alert data and provides context around any findings."
argument-hint: "[IOC value — IP, hash, domain, URL, or filename]"
---

# IOC Hunt Workflow

You are an **orchestrator** performing an IOC (Indicator of Compromise) hunt against a Wazuh SIEM environment. You delegate searches to subagents to keep your main context clean, and synthesize their findings into a final report.

## Step 0: Plan the Hunt

**Use `EnterPlanMode`** to plan the investigation before executing. In plan mode:

1. Read `docs/network-map.md` to understand the lab topology (domains, hosts, IPs, users, trust relationships)
2. Classify the IOC (see classification table below)
3. Outline the search strategy: which tools to use, what pivots might be needed
4. Exit plan mode with `ExitPlanMode` when the plan is ready

### IOC Classification Table

| Input Pattern | IOC Type |
|---|---|
| IP address (e.g. `10.0.0.1`, `203.0.113.50`) | `ip` |
| File hash (SHA256/MD5/SHA1) | `hash` |
| Domain (e.g. `evil.example.com`) | `domain` |
| URL (contains path like `/malware/payload`) | `url` |
| Filename (e.g. `suspicious.exe`, `payload.dll`) | `filename` |
| Unknown | `auto` (searches all fields) |

## Step 1: Create Task List

After exiting plan mode, create a to-do list using `TaskCreate` to track each phase:

1. "Search for IOC [value]" — initial search
2. "Analyze initial findings" — extract key indicators
3. "Pivot: [description]" — one task per pivot search needed
4. "Compile final report" — synthesis

Mark tasks as `in_progress` before starting them, `completed` when done.

## Step 2: Search for the IOC (Subagent)

**Delegate the initial search to a subagent** using the `Task` tool. This keeps raw search data out of your main context.

Launch a `general-purpose` subagent with this prompt pattern:

```
Search Wazuh SIEM for IOC "[VALUE]" using these MCP tools in order:

1. Use `search_ioc` with ioc_type: "[TYPE]", hours_back: 2
2. If no results, try ioc_type: "auto"
3. If still no results, try hours_back: 48 (syscheck detections are delayed)
4. If still no results, try `search_logs` with query_string: "\"[VALUE]\""

For any results found, report back ONLY:
- Total hit count
- List of affected agents (name, IP) with event counts
- Earliest and latest timestamps
- Rule IDs and levels triggered (deduplicated)
- Any SHA256/MD5 hashes found
- Any related IPs, filenames, or domains found in the data
- MITRE ATT&CK tactics/techniques if present

If results were spilled to a file, read that file first.
Do NOT return raw search output — only the structured summary above.
```

## Step 3: Analyze Findings

From the subagent's summary, identify:
- **When**: Time range of activity
- **Where**: Which hosts are affected
- **What**: What rules fired, what artifacts were found
- **Severity**: Highest rule levels and MITRE mappings
- **Pivots needed**: Hashes to cross-reference, hosts to investigate, rules to look up

Update your task list: mark the search task as completed, create new pivot tasks.

## Step 4: Pivot and Expand (Parallel Subagents)

Launch **multiple subagents in parallel** for pivot searches. Each pivot is a separate `Task` call with `subagent_type: "general-purpose"`.

### Hash Pivot
```
Search Wazuh for hash "[SHA256]" using search_ioc with ioc_type: "hash", hours_back: 48.
Report: which agents have this hash, timestamps, file paths, and rule IDs.
If results were spilled to a file, read that file first.
```

### Host Investigation
```
Use investigate_host on agent "[AGENT_NAME]" with hours_back: 336.
Report: severity summary, suspicious executables (unusual paths like \Temp\, \Downloads\),
login anomalies (unexpected users, remote NTLM logons), top rules, and timeline highlights.
If results were spilled to a file, read that file first.
```

### Rule Lookup
```
Use get_rule_info for rule "[RULE_ID]".
Report: rule description, level, MITRE ATT&CK mapping, compliance frameworks,
and which agents triggered this rule with counts.
If results were spilled to a file, read that file first.
```

### IP Pivot
```
Search Wazuh for IP "[IP_ADDRESS]" using search_ioc with ioc_type: "ip", hours_back: 48.
Report: which agents communicated with this IP, timestamps, rule descriptions, and directions (src vs dst).
If results were spilled to a file, read that file first.
```

**Launch all applicable pivots in a single message** (parallel Task calls). Mark pivot tasks as completed as results come back.

## Step 5: Report

Synthesize all subagent summaries into a structured report. Mark the report task as completed.

1. **IOC**: The value searched and its type
2. **Verdict**: Found / Not Found in Wazuh data
3. **Timeline**: Chronological sequence of events
4. **Affected Hosts**: List of agents where the IOC appeared, with context from the network map
5. **Related IOCs**: Any hashes, IPs, or filenames discovered during pivoting
6. **MITRE ATT&CK**: Relevant tactics and techniques observed
7. **Recommendations**: Next investigation steps (containment, deeper analysis, etc.)

## Important Notes

- BAM registry entries (`syscheck.value_name`) show exe execution but are detected on delayed syscheck scheduled scans (may appear hours or days after actual execution)
- Use wider `hours_back` for syscheck/registry artifacts than for real-time events
- Keep smaller `hours_back` for real-time events (logon, service creation, errors)
- **Large results are automatically spilled to `/tmp/wazuh-ioc-hunter/`** — subagents should read those files if the tool output mentions a file path
- Always delegate searches to subagents — never run search_ioc, search_logs, or investigate_host directly in the main context
