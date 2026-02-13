import { z } from "zod";
import { opensearchSearch } from "../opensearch-client.js";
import { DEFAULT_ALERTS_INDEX, MAX_RESULTS } from "../lib/constants.js";
import { buildTimeRange, formatSearchResults } from "../lib/formatters.js";

export const searchLogsSchema = {
  query_string: z.string().describe("Lucene query string to search logs"),
  agent_name: z.string().optional().describe("Filter by agent name"),
  rule_id: z.string().optional().describe("Filter by rule ID"),
  rule_level_min: z.number().optional().describe("Minimum rule level"),
  rule_level_max: z.number().optional().describe("Maximum rule level"),
  rule_group: z.string().optional().describe("Filter by rule group"),
  hours_back: z.number().default(2).describe("Hours before/after time anchor to search"),
  index: z.string().default(DEFAULT_ALERTS_INDEX).describe("Index pattern to search"),
  max_results: z.number().default(MAX_RESULTS).describe("Maximum results to return"),
};

export async function searchLogs(args: {
  query_string: string;
  agent_name?: string;
  rule_id?: string;
  rule_level_min?: number;
  rule_level_max?: number;
  rule_group?: string;
  hours_back: number;
  index: string;
  max_results: number;
}): Promise<string> {
  const timeRange = buildTimeRange(args.hours_back);

  const must: Record<string, unknown>[] = [
    { query_string: { query: args.query_string } },
  ];
  const filter: Record<string, unknown>[] = [
    { range: { timestamp: { gte: timeRange.gte, lte: timeRange.lte } } },
  ];

  if (args.agent_name) {
    filter.push({ match_phrase: { "agent.name": args.agent_name } });
  }
  if (args.rule_id) {
    filter.push({ term: { "rule.id": args.rule_id } });
  }
  if (args.rule_group) {
    filter.push({ match_phrase: { "rule.groups": args.rule_group } });
  }
  if (args.rule_level_min !== undefined || args.rule_level_max !== undefined) {
    const rangeFilter: Record<string, unknown> = {};
    if (args.rule_level_min !== undefined) rangeFilter.gte = args.rule_level_min;
    if (args.rule_level_max !== undefined) rangeFilter.lte = args.rule_level_max;
    filter.push({ range: { "rule.level": rangeFilter } });
  }

  const body = {
    query: { bool: { must, filter } },
    size: args.max_results,
    sort: [{ timestamp: { order: "desc" } }],
  };

  const response = await opensearchSearch(args.index, body);
  return formatSearchResults(response, `Log Search: "${args.query_string}"`);
}
