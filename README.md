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

### Option A: Claude Code Marketplace Plugin (Recommended)

This gives you all 8 MCP tools plus the `/hunt-ioc`, `/investigate`, and `/threat-overview` skills.

1. **Add the marketplace** (run inside Claude Code):
   ```
   /plugin marketplace add cyberbalsa/wazuh-ioc-hunter-mcp
   ```

2. **Install the plugin:**
   ```
   /plugin install wazuh-ioc-hunter@cyberbalsa
   ```

3. **Configure Wazuh connection** — export these in your shell profile (e.g. `~/.bashrc` or `~/.zshrc`):
   ```bash
   export WAZUH_OPENSEARCH_URL=https://your-wazuh-host:9200
   export WAZUH_OPENSEARCH_USER=admin
   export WAZUH_OPENSEARCH_PASS=your-password
   export NODE_TLS_REJECT_UNAUTHORIZED=0  # if using self-signed certs
   ```

4. **Restart Claude Code** — the plugin's setup hook will automatically run `npm install && npm run build`.

To verify, run `/hunt-ioc` or ask Claude to `search_ioc`.

### Option B: Standalone MCP Server

Use this if you just want the MCP tools without the plugin skills.

```bash
# 1. Clone the repo
git clone https://github.com/cyberbalsa/wazuh-ioc-hunter-mcp.git
cd wazuh-ioc-hunter-mcp

# 2. Install dependencies and build
npm install
npm run build

# 3. Add to your project's .mcp.json (see docs/mcp-standalone.json.example)
```

You can add it to any project's `.mcp.json` manually:

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

Or register globally via the `claude` CLI:

```bash
claude mcp add --global wazuh-ioc-hunter \
  -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
  -e WAZUH_OPENSEARCH_URL=https://your-wazuh-host:9200 \
  -e WAZUH_OPENSEARCH_USER=admin \
  -e WAZUH_OPENSEARCH_PASS=your-password \
  -- node /absolute/path/to/wazuh-ioc-hunter-mcp/dist/index.js
```

---

## Configuration

All settings are configured via environment variables:

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `WAZUH_OPENSEARCH_URL` | — | OpenSearch endpoint URL (required) |
| `WAZUH_OPENSEARCH_USER` | `admin` | OpenSearch username |
| `WAZUH_OPENSEARCH_PASS` | — | OpenSearch password (required) |
| `WAZUH_TIME_ANCHOR` | `2025-10-09T20:36:04Z` | Center of default search window (ISO 8601) |
| `WAZUH_HOURS_BACK` | `2` | Default search window in hours (centered on anchor) |
| `NODE_TLS_REJECT_UNAUTHORIZED` | — | Set to `0` for self-signed certs (common with Wazuh) |

For the marketplace plugin, export these in your shell profile. For standalone, set them in `.mcp.json` or via `-e` flags with `claude mcp add`.

## Network Map

The `docs/` directory includes the GOAD (Game of Active Directory) lab topology:

- `docs/GOAD.pdf` — Original network diagram
- `docs/network-map.md` — Markdown reference with all domains, hosts, IPs, users, groups, trust relationships, and services

The skills automatically read `docs/network-map.md` for context during investigations. Replace these files with your own network documentation for your environment.

## Architecture

```
src/                        # MCP server source (TypeScript)
  index.ts                  # Entry point (8 tools registered)
  opensearch-client.ts      # fetch() wrapper with Basic auth
  lib/
    constants.ts            # Connection config, field mappings, defaults
    formatters.ts           # Result formatting and time range helpers
  tools/
    search-ioc.ts           # IOC search with field-type mapping
    search-logs.ts          # General log search with filters
    get-alerts.ts           # Alert retrieval by severity
    get-agent-info.ts       # Agent listing and detail
    investigate-host.ts     # Deep host investigation (5 parallel queries)
    run-query.ts            # Raw OpenSearch DSL passthrough
    get-rule-info.ts        # Rule lookup with MITRE/compliance
    get-index-list.ts       # Index listing via _cat API
package.json                # Node.js package (bin, prepare script for npx)
tsconfig.json               # TypeScript config
.claude-plugin/
  marketplace.json          # Marketplace listing metadata
plugin/                     # Claude Code plugin (cached on install)
  .claude-plugin/
    plugin.json             # Plugin identity and version
  .mcp.json                 # MCP server config (npx from GitHub)
  CLAUDE.md                 # Plugin context for Claude Code
  skills/                   # Skill definitions (SKILL.md files)
    hunt-ioc/               # /hunt-ioc — guided IOC hunting
    investigate/            # /investigate — deep host analysis
    threat-overview/        # /threat-overview — situational briefing
  commands/                 # Slash commands
    hunt.md                 # /hunt — quick IOC search
  hooks/
    hooks.json              # Plugin hooks
docs/
  GOAD.pdf                  # Network topology diagram
  network-map.md            # Network map in markdown
  mcp-standalone.json.example  # Standalone config template
```

## License

MIT
