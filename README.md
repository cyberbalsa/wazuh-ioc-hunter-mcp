# Wazuh IOC Hunter MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that enables Claude Code to hunt for Indicators of Compromise (IOCs) in a [Wazuh](https://wazuh.com/) SIEM via its OpenSearch backend.

## Features

- **8 tools** for comprehensive threat hunting
- **IOC search** across IP, hash, domain, URL, and filename fields
- **Deep host investigation** with severity, executables, registry, and login analysis
- **MITRE ATT&CK** and compliance mapping support
- **Raw OpenSearch DSL** passthrough for advanced queries
- Works as a **Claude Code plugin** with guided hunting skills

## Tools

| Tool | Purpose |
|------|---------|
| `search_ioc` | Search for an IOC (IP, hash, domain, URL, filename) across Wazuh alerts |
| `search_logs` | Search logs with Lucene query string and filters |
| `get_alerts` | Get alerts sorted by severity (low/medium/high/critical) |
| `get_agent_info` | List agents or get detailed agent info with stats |
| `investigate_host` | Deep host investigation: executables, registry, logins, timeline |
| `run_query` | Execute raw OpenSearch DSL queries |
| `get_rule_info` | Look up Wazuh rules with MITRE ATT&CK mappings |
| `get_index_list` | List OpenSearch indices |

## Skills (Claude Code Plugin)

| Skill | Usage | Purpose |
|-------|-------|---------|
| `/hunt-ioc` | `/hunt-ioc 192.168.1.100` | Guided IOC hunting with auto-pivoting |
| `/investigate` | `/investigate myhost` | Deep host compromise investigation |
| `/threat-overview` | `/threat-overview` | Situational awareness briefing |

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/cyberbalsa/wazuh-ioc-hunter-mcp.git
cd wazuh-ioc-hunter-mcp
npm install
npm run build
```

### 2. Configure

Copy the example config and set your Wazuh credentials:

```bash
cp .mcp.json.example .mcp.json
```

Edit `.mcp.json` with your Wazuh OpenSearch URL and credentials. Or set environment variables:

```bash
export WAZUH_OPENSEARCH_URL="https://your-wazuh-host:9200"
export WAZUH_OPENSEARCH_USER="admin"
export WAZUH_OPENSEARCH_PASS="your-password"
export WAZUH_TIME_ANCHOR="2025-01-01T00:00:00Z"  # Center of your search window
export WAZUH_HOURS_BACK="24"                       # Default search window in hours
```

### 3. Use with Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "wazuh-ioc-hunter": {
      "command": "node",
      "args": ["/path/to/wazuh-ioc-hunter-mcp/dist/index.js"],
      "env": {
        "NODE_TLS_REJECT_UNAUTHORIZED": "0",
        "WAZUH_OPENSEARCH_URL": "https://your-wazuh-host:9200",
        "WAZUH_OPENSEARCH_USER": "admin",
        "WAZUH_OPENSEARCH_PASS": "your-password"
      }
    }
  }
}
```

### 4. Install as Claude Code Plugin

To install as a marketplace plugin with skills:

```bash
# Clone into Claude Code plugins directory
git clone https://github.com/cyberbalsa/wazuh-ioc-hunter-mcp.git \
  ~/.claude/plugins/marketplaces/cyberbalsa
cd ~/.claude/plugins/marketplaces/cyberbalsa
npm install && npm run build
```

Then restart Claude Code. The plugin provides `/hunt-ioc`, `/investigate`, and `/threat-overview` skills.

## Configuration

All settings can be configured via environment variables or by editing `src/lib/constants.ts`:

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `WAZUH_OPENSEARCH_URL` | — | OpenSearch endpoint URL |
| `WAZUH_OPENSEARCH_USER` | `admin` | OpenSearch username |
| `WAZUH_OPENSEARCH_PASS` | — | OpenSearch password |
| `WAZUH_TIME_ANCHOR` | `2025-10-09T20:36:04Z` | Center of default search window |
| `WAZUH_HOURS_BACK` | `2` | Default hours before/after anchor |
| `NODE_TLS_REJECT_UNAUTHORIZED` | — | Set to `0` for self-signed certs |

## Architecture

```
src/
  index.ts                # MCP server entry point (8 tools registered)
  opensearch-client.ts    # fetch() wrapper with Basic auth
  lib/
    constants.ts          # Connection config, field mappings, defaults
    formatters.ts         # Result formatting and time range helpers
  tools/
    search-ioc.ts         # IOC search with field-type mapping
    search-logs.ts        # General log search with filters
    get-alerts.ts         # Alert retrieval by severity
    get-agent-info.ts     # Agent listing and detail
    investigate-host.ts   # Deep host investigation
    run-query.ts          # Raw OpenSearch DSL passthrough
    get-rule-info.ts      # Rule lookup with MITRE/compliance
    get-index-list.ts     # Index listing via _cat API
plugin/
  skills/                 # Claude Code skill definitions
  commands/               # Slash commands
  hooks/                  # Plugin lifecycle hooks
```

## License

MIT
