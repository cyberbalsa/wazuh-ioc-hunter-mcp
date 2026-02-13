import { z } from "zod";
import { opensearchSearch } from "../opensearch-client.js";
import { DEFAULT_ALERTS_INDEX } from "../lib/constants.js";
import { buildTimeRange } from "../lib/formatters.js";
import { maybeSpill } from "../lib/spill.js";

export const getAgentInfoSchema = {
  agent_id: z.string().optional().describe("Specific agent ID to get details for"),
  agent_name: z.string().optional().describe("Specific agent name to get details for"),
  hours_back: z.number().default(24).describe("Hours before/after time anchor for activity stats"),
  index: z.string().default(DEFAULT_ALERTS_INDEX).describe("Index pattern to search"),
};

export async function getAgentInfo(args: {
  agent_id?: string;
  agent_name?: string;
  hours_back: number;
  index: string;
}): Promise<string> {
  const timeRange = buildTimeRange(args.hours_back);

  if (args.agent_id || args.agent_name) {
    // Get details for a specific agent
    const filter: Record<string, unknown>[] = [
      { range: { timestamp: { gte: timeRange.gte, lte: timeRange.lte } } },
    ];

    if (args.agent_id) filter.push({ term: { "agent.id": args.agent_id } });
    if (args.agent_name) filter.push({ match_phrase: { "agent.name": args.agent_name } });

    const body = {
      query: { bool: { filter } },
      size: 0,
      aggs: {
        agent_info: {
          terms: { field: "agent.name", size: 1 },
          aggs: {
            agent_id: { terms: { field: "agent.id", size: 1 } },
            agent_ip: { terms: { field: "agent.ip", size: 1 } },
            os_name: { terms: { field: "agent.os.name", size: 1 } },
            os_platform: { terms: { field: "agent.os.platform", size: 1 } },
            top_rules: {
              terms: { field: "rule.description", size: 10 },
            },
            severity_distribution: {
              range: {
                field: "rule.level",
                ranges: [
                  { key: "low (0-6)", from: 0, to: 7 },
                  { key: "medium (7-10)", from: 7, to: 11 },
                  { key: "high (11-14)", from: 11, to: 15 },
                  { key: "critical (15+)", from: 15 },
                ],
              },
            },
            rule_groups: { terms: { field: "rule.groups", size: 15 } },
          },
        },
      },
    };

    const response = await opensearchSearch(args.index, body);
    const aggs = response.aggregations as Record<string, unknown> | undefined;
    if (!aggs) return "No agent data found.";

    const agentBuckets = (aggs.agent_info as Record<string, unknown>)?.buckets as Array<Record<string, unknown>> | undefined;
    if (!agentBuckets || agentBuckets.length === 0) return "No agent found matching criteria.";

    const agent = agentBuckets[0];
    const lines: string[] = [];
    lines.push(`Agent: ${agent.key} (${agent.doc_count} events)`);

    const idBuckets = (agent.agent_id as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
    if (idBuckets?.[0]) lines.push(`  ID: ${idBuckets[0].key}`);

    const ipBuckets = (agent.agent_ip as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
    if (ipBuckets?.[0]) lines.push(`  IP: ${ipBuckets[0].key}`);

    const osBuckets = (agent.os_name as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
    if (osBuckets?.[0]) lines.push(`  OS: ${osBuckets[0].key}`);

    // Severity distribution
    const sevBuckets = (agent.severity_distribution as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
    if (sevBuckets) {
      lines.push("\n  Severity Distribution:");
      for (const b of sevBuckets) {
        lines.push(`    ${b.key}: ${b.doc_count}`);
      }
    }

    // Top rules
    const ruleBuckets = (agent.top_rules as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
    if (ruleBuckets) {
      lines.push("\n  Top Rules:");
      for (const b of ruleBuckets) {
        lines.push(`    ${b.key}: ${b.doc_count}`);
      }
    }

    // Rule groups
    const groupBuckets = (agent.rule_groups as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
    if (groupBuckets) {
      lines.push("\n  Rule Groups:");
      for (const b of groupBuckets) {
        lines.push(`    ${b.key}: ${b.doc_count}`);
      }
    }

    return lines.join("\n");
  }

  // List all agents
  const body = {
    query: {
      bool: {
        filter: [{ range: { timestamp: { gte: timeRange.gte, lte: timeRange.lte } } }],
      },
    },
    size: 0,
    aggs: {
      agents: {
        terms: { field: "agent.name", size: 100 },
        aggs: {
          agent_id: { terms: { field: "agent.id", size: 1 } },
          agent_ip: { terms: { field: "agent.ip", size: 1 } },
          os: { terms: { field: "agent.os.platform", size: 1 } },
          max_level: { max: { field: "rule.level" } },
        },
      },
    },
  };

  const response = await opensearchSearch(args.index, body);
  const aggs = response.aggregations as Record<string, unknown> | undefined;
  if (!aggs) return "No agent data found.";

  const buckets = (aggs.agents as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  if (!buckets || buckets.length === 0) return "No agents found in the time range.";

  const lines: string[] = [`Agents (${buckets.length} found):`];
  lines.push("---");

  for (const b of buckets) {
    const idBuckets = (b.agent_id as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
    const ipBuckets = (b.agent_ip as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
    const osBuckets = (b.os as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
    const maxLevel = (b.max_level as Record<string, unknown>)?.value;

    const id = idBuckets?.[0]?.key ?? "?";
    const ip = ipBuckets?.[0]?.key ?? "?";
    const os = osBuckets?.[0]?.key ?? "?";

    lines.push(`  ${b.key} (ID: ${id}) | IP: ${ip} | OS: ${os} | Events: ${b.doc_count} | Max Level: ${maxLevel}`);
  }

  const text = lines.join("\n");
  return maybeSpill(text, buckets.length, "agent-list");
}
