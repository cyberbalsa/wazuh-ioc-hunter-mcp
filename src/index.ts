#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { searchIocSchema, searchIoc } from "./tools/search-ioc.js";
import { searchLogsSchema, searchLogs } from "./tools/search-logs.js";
import { getAlertsSchema, getAlerts } from "./tools/get-alerts.js";
import { getAgentInfoSchema, getAgentInfo } from "./tools/get-agent-info.js";
import { runQuerySchema, runQuery } from "./tools/run-query.js";
import { getRuleInfoSchema, getRuleInfo } from "./tools/get-rule-info.js";
import { getIndexListSchema, getIndexList } from "./tools/get-index-list.js";
import { investigateHostSchema, investigateHost } from "./tools/investigate-host.js";

// Redirect console.log to stderr to prevent corrupting stdio transport
const origLog = console.log;
console.log = (...args: unknown[]) => console.error(...args);

const server = new McpServer({
  name: "wazuh-ioc-hunter",
  version: "1.2.0",
});

// Tool: search_ioc
server.tool(
  "search_ioc",
  "Search for an Indicator of Compromise (IP, hash, domain, URL, filename) across Wazuh alert data",
  searchIocSchema,
  { readOnlyHint: true },
  async (args) => ({
    content: [{ type: "text", text: await searchIoc(args) }],
  }),
);

// Tool: search_logs
server.tool(
  "search_logs",
  "Search Wazuh logs with a Lucene query string and optional filters (agent, rule, level, group)",
  searchLogsSchema,
  { readOnlyHint: true },
  async (args) => ({
    content: [{ type: "text", text: await searchLogs(args) }],
  }),
);

// Tool: get_alerts
server.tool(
  "get_alerts",
  "Get recent Wazuh alerts sorted by severity. Filter by severity level, agent, or rule group.",
  getAlertsSchema,
  { readOnlyHint: true },
  async (args) => ({
    content: [{ type: "text", text: await getAlerts(args) }],
  }),
);

// Tool: get_agent_info
server.tool(
  "get_agent_info",
  "List all Wazuh agents or get detailed info for a specific agent including alert stats and top rules",
  getAgentInfoSchema,
  { readOnlyHint: true },
  async (args) => ({
    content: [{ type: "text", text: await getAgentInfo(args) }],
  }),
);

// Tool: run_query
server.tool(
  "run_query",
  "Execute a raw OpenSearch DSL query against Wazuh indices. Returns raw JSON response.",
  runQuerySchema,
  { readOnlyHint: true },
  async (args) => ({
    content: [{ type: "text", text: await runQuery(args) }],
  }),
);

// Tool: get_rule_info
server.tool(
  "get_rule_info",
  "Look up a Wazuh rule by ID. Returns rule details, MITRE mappings, compliance info, and occurrence stats.",
  getRuleInfoSchema,
  { readOnlyHint: true },
  async (args) => ({
    content: [{ type: "text", text: await getRuleInfo(args) }],
  }),
);

// Tool: get_index_list
server.tool(
  "get_index_list",
  "List OpenSearch indices matching a pattern. Shows index health, doc count, and size.",
  getIndexListSchema,
  { readOnlyHint: true },
  async (args) => ({
    content: [{ type: "text", text: await getIndexList(args) }],
  }),
);

// Tool: investigate_host
server.tool(
  "investigate_host",
  "Deep investigation of a single host/agent. Shows severity distribution, executables seen (BAM registry), high severity events, login activity, registry changes, and activity timeline.",
  investigateHostSchema,
  { readOnlyHint: true },
  async (args) => ({
    content: [{ type: "text", text: await investigateHost(args) }],
  }),
);

// Graceful shutdown
process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Wazuh IOC Hunter MCP server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
