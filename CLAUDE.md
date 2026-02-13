# Wazuh IOC Hunter

This plugin provides 8 MCP tools for hunting Indicators of Compromise (IOCs) in a Wazuh SIEM environment via its OpenSearch backend.

## Network Map

The lab network topology is documented in `docs/network-map.md`. Read this file to understand the domain structure, hosts, users, groups, and attack paths. To use a different network map, replace `docs/GOAD.pdf` and regenerate `docs/network-map.md`.

## Available MCP Tools

| Tool | Purpose |
|------|---------|
| `search_ioc` | Search for an IOC (IP, hash, domain, URL, filename) across Wazuh alert data |
| `search_logs` | Search logs with Lucene query string and filters (agent, rule, level, group) |
| `get_alerts` | Get alerts sorted by severity (low/medium/high/critical) |
| `get_agent_info` | List agents or get detailed agent info with alert stats |
| `investigate_host` | Deep host investigation: executables, registry, logins, severity timeline |
| `run_query` | Execute raw OpenSearch DSL queries for advanced analysis |
| `get_rule_info` | Look up Wazuh rules with MITRE ATT&CK and compliance mappings |
| `get_index_list` | List OpenSearch indices matching a pattern |

## Configuration

All connection settings are configured via environment variables. Export these in your shell profile:

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `WAZUH_OPENSEARCH_URL` | — | OpenSearch endpoint URL (required) |
| `WAZUH_OPENSEARCH_USER` | `admin` | OpenSearch username |
| `WAZUH_OPENSEARCH_PASS` | — | OpenSearch password (required) |
| `WAZUH_TIME_ANCHOR` | `2025-10-09T20:36:04Z` | Center of default search window (ISO 8601) |
| `WAZUH_HOURS_BACK` | `2` | Default search window in hours (centered on anchor) |
| `NODE_TLS_REJECT_UNAUTHORIZED` | — | Set to `0` for self-signed certs (common with Wazuh) |

## Key Data Patterns

- **BAM Registry entries** (`syscheck.value_name`) record executable paths — detected by syscheck on scheduled scans (delayed detection)
- **Windows Event Logs** provide real-time logon success/failure, service creation, and error events
- **MITRE ATT&CK** mappings are available on many rules via `rule.mitre`
- **Syscheck artifacts** may appear hours after the actual event due to scheduled scan intervals

## Skills

Use `/hunt-ioc` to start an IOC hunting investigation, `/investigate` to deep-dive a host, or `/threat-overview` for the current threat landscape.
