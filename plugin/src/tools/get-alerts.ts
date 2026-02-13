import { z } from "zod";
import { opensearchSearch } from "../opensearch-client.js";
import { DEFAULT_ALERTS_INDEX, MAX_RESULTS, SEVERITY_LEVELS } from "../lib/constants.js";
import { buildTimeRange, formatAlerts } from "../lib/formatters.js";

export const getAlertsSchema = {
  severity: z
    .enum(["low", "medium", "high", "critical"])
    .optional()
    .describe("Filter by severity level"),
  agent_name: z.string().optional().describe("Filter by agent name"),
  rule_group: z.string().optional().describe("Filter by rule group (e.g. 'syscheck', 'web', 'authentication')"),
  hours_back: z.number().default(2).describe("Hours before/after time anchor to search"),
  index: z.string().default(DEFAULT_ALERTS_INDEX).describe("Index pattern to search"),
  max_results: z.number().default(MAX_RESULTS).describe("Maximum results to return"),
};

export async function getAlerts(args: {
  severity?: string;
  agent_name?: string;
  rule_group?: string;
  hours_back: number;
  index: string;
  max_results: number;
}): Promise<string> {
  const timeRange = buildTimeRange(args.hours_back);

  const filter: Record<string, unknown>[] = [
    { range: { timestamp: { gte: timeRange.gte, lte: timeRange.lte } } },
  ];

  if (args.severity) {
    const levels = SEVERITY_LEVELS[args.severity];
    if (levels) {
      filter.push({ range: { "rule.level": { gte: levels.min, lte: levels.max } } });
    }
  }
  if (args.agent_name) {
    filter.push({ match_phrase: { "agent.name": args.agent_name } });
  }
  if (args.rule_group) {
    filter.push({ match_phrase: { "rule.groups": args.rule_group } });
  }

  const body = {
    query: { bool: { filter } },
    size: args.max_results,
    sort: [{ "rule.level": { order: "desc" } }, { timestamp: { order: "desc" } }],
  };

  const response = await opensearchSearch(args.index, body);

  const severityLabel = args.severity ? ` (${args.severity})` : "";
  return formatAlerts(response);
}
