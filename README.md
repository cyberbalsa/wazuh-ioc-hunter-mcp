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

---

## Installation

### Option A: Standalone MCP Server

Use this if you just want the MCP tools without the plugin skills.

```bash
# 1. Clone the repo
git clone https://github.com/cyberbalsa/wazuh-ioc-hunter-mcp.git
cd wazuh-ioc-hunter-mcp

# 2. Install dependencies and build
npm install
npm run build

# 3. Copy the example config and fill in your credentials
cp .mcp.json.example .mcp.json
# Edit .mcp.json with your Wazuh OpenSearch URL and credentials

# 4. Restart Claude Code in this directory — the MCP server will auto-start
```

You can also add it to any project's `.mcp.json` manually:

```json
{
  "mcpServers": {
    "wazuh-ioc-hunter": {
      "command": "node",
      "args": ["/absolute/path/to/wazuh-ioc-hunter-mcp/dist/index.js"],
      "env": {
        "NODE_TLS_REJECT_UNAUTHORIZED": "0",
        "WAZUH_OPENSEARCH_URL": "https://your-wazuh-host:9200",
        "WAZUH_OPENSEARCH_USER": "admin",
        "WAZUH_OPENSEARCH_PASS": "your-password",
        "WAZUH_TIME_ANCHOR": "2025-01-01T00:00:00Z",
        "WAZUH_HOURS_BACK": "24"
      }
    }
  }
}
```

Or register it globally (available in all projects):

```bash
claude mcp add --global wazuh-ioc-hunter \
  -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
  -e WAZUH_OPENSEARCH_URL=https://your-wazuh-host:9200 \
  -e WAZUH_OPENSEARCH_USER=admin \
  -e WAZUH_OPENSEARCH_PASS=your-password \
  -- node /absolute/path/to/wazuh-ioc-hunter-mcp/dist/index.js
```

### Option B: Claude Code Marketplace Plugin (with Skills)

Use this to get the full plugin experience with `/hunt-ioc`, `/investigate`, and `/threat-overview` skills.

```bash
# 1. Create the marketplace plugins directory if it doesn't exist
mkdir -p ~/.claude/plugins/marketplaces

# 2. Clone the repo into the marketplace directory
git clone https://github.com/cyberbalsa/wazuh-ioc-hunter-mcp.git \
  ~/.claude/plugins/marketplaces/cyberbalsa

# 3. Install dependencies and build
cd ~/.claude/plugins/marketplaces/cyberbalsa
npm install
npm run build

# 4. Create your .mcp.json with credentials (this file is gitignored)
cp .mcp.json.example .mcp.json
# Edit .mcp.json — set WAZUH_OPENSEARCH_URL, WAZUH_OPENSEARCH_USER, WAZUH_OPENSEARCH_PASS

# 5. Restart Claude Code
# The plugin will be detected automatically. You should see:
#   - 8 MCP tools (search_ioc, investigate_host, etc.)
#   - 3 skills (/hunt-ioc, /investigate, /threat-overview)
```

To verify the plugin is loaded, run `/hunt-ioc` or ask Claude to `search_ioc`.

### Option C: Add MCP Server via `claude` CLI

If you don't need skills, you can register the MCP server directly with the `claude` CLI:

```bash
# Clone and build first
git clone https://github.com/cyberbalsa/wazuh-ioc-hunter-mcp.git ~/wazuh-ioc-hunter-mcp
cd ~/wazuh-ioc-hunter-mcp && npm install && npm run build

# Register as a project-level MCP server (current directory only)
claude mcp add wazuh-ioc-hunter \
  -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
  -e WAZUH_OPENSEARCH_URL=https://your-wazuh-host:9200 \
  -e WAZUH_OPENSEARCH_USER=admin \
  -e WAZUH_OPENSEARCH_PASS=your-password \
  -- node ~/wazuh-ioc-hunter-mcp/dist/index.js

# Or register globally (available in all projects)
claude mcp add --global wazuh-ioc-hunter \
  -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
  -e WAZUH_OPENSEARCH_URL=https://your-wazuh-host:9200 \
  -e WAZUH_OPENSEARCH_USER=admin \
  -e WAZUH_OPENSEARCH_PASS=your-password \
  -- node ~/wazuh-ioc-hunter-mcp/dist/index.js

# Verify it's registered
claude mcp list
```

---

## Configuration

All settings can be configured via environment variables:

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `WAZUH_OPENSEARCH_URL` | — | OpenSearch endpoint URL (required) |
| `WAZUH_OPENSEARCH_USER` | `admin` | OpenSearch username |
| `WAZUH_OPENSEARCH_PASS` | — | OpenSearch password (required) |
| `WAZUH_TIME_ANCHOR` | `2025-10-09T20:36:04Z` | Center of default search window (ISO 8601) |
| `WAZUH_HOURS_BACK` | `2` | Default search window in hours (centered on anchor) |
| `NODE_TLS_REJECT_UNAUTHORIZED` | — | Set to `0` for self-signed certs (common with Wazuh) |

Environment variables are set in `.mcp.json` (standalone) or via `-e` flags with `claude mcp add`.

## Network Map

The `docs/` directory includes the GOAD (Game of Active Directory) lab topology:

- `docs/GOAD.pdf` — Original network diagram
- `docs/network-map.md` — Markdown reference with all domains, hosts, IPs, users, groups, trust relationships, and services

The skills automatically read `docs/network-map.md` for context during investigations. Replace these files with your own network documentation for your environment.

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
    investigate-host.ts   # Deep host investigation (5 parallel queries)
    run-query.ts          # Raw OpenSearch DSL passthrough
    get-rule-info.ts      # Rule lookup with MITRE/compliance
    get-index-list.ts     # Index listing via _cat API
plugin/
  .claude-plugin/         # Plugin metadata (plugin.json)
  .mcp.json               # MCP server config for plugin mode
  CLAUDE.md               # Plugin context for Claude Code
  skills/                 # Skill definitions (SKILL.md files)
    hunt-ioc/             # /hunt-ioc — guided IOC hunting
    investigate/          # /investigate — deep host analysis
    threat-overview/      # /threat-overview — situational briefing
  commands/               # Slash commands
    hunt.md               # /hunt — quick IOC search
  hooks/                  # Plugin lifecycle hooks
    hooks.json            # Setup hook (auto-build on install)
docs/
  GOAD.pdf                # Network topology diagram
  network-map.md          # Network map in markdown
```

## License

MIT
