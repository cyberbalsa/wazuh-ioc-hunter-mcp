import { z } from "zod";
import { opensearchSearch } from "../opensearch-client.js";
import { DEFAULT_ALERTS_INDEX, MAX_RESULTS, IOC_FIELD_MAP } from "../lib/constants.js";
import { buildTimeRange, formatSearchResults } from "../lib/formatters.js";

export const searchIocSchema = {
  ioc: z.string().describe("The IOC value to search for (IP, hash, domain, URL, or filename)"),
  ioc_type: z
    .enum(["auto", "ip", "hash", "domain", "url", "filename"])
    .default("auto")
    .describe("Type of IOC. 'auto' searches across all fields."),
  hours_back: z.number().default(2).describe("Hours before/after time anchor to search"),
  index: z.string().default(DEFAULT_ALERTS_INDEX).describe("Index pattern to search"),
  max_results: z.number().default(MAX_RESULTS).describe("Maximum results to return"),
};

export async function searchIoc(args: {
  ioc: string;
  ioc_type: string;
  hours_back: number;
  index: string;
  max_results: number;
}): Promise<string> {
  const timeRange = buildTimeRange(args.hours_back);

  let query: Record<string, unknown>;

  if (args.ioc_type === "auto") {
    // Use query_string to search across all fields
    query = {
      bool: {
        must: [{ query_string: { query: `"${args.ioc}"` } }],
        filter: [{ range: { timestamp: { gte: timeRange.gte, lte: timeRange.lte } } }],
      },
    };
  } else if (args.ioc_type === "filename") {
    // Filenames may be embedded in paths, so use wildcard matching
    const fields = IOC_FIELD_MAP.filename ?? [];
    const shouldClauses = fields.map((field) => ({
      wildcard: { [field]: { value: `*${args.ioc}*`, case_insensitive: true } },
    }));

    query = {
      bool: {
        must: [{ bool: { should: shouldClauses, minimum_should_match: 1 } }],
        filter: [{ range: { timestamp: { gte: timeRange.gte, lte: timeRange.lte } } }],
      },
    };
  } else {
    // Search specific fields for the IOC type
    const fields = IOC_FIELD_MAP[args.ioc_type] ?? [];
    const shouldClauses = fields.map((field) => ({
      match_phrase: { [field]: args.ioc },
    }));

    query = {
      bool: {
        must: [{ bool: { should: shouldClauses, minimum_should_match: 1 } }],
        filter: [{ range: { timestamp: { gte: timeRange.gte, lte: timeRange.lte } } }],
      },
    };
  }

  const body = {
    query,
    size: args.max_results,
    sort: [{ timestamp: { order: "desc" } }],
  };

  const response = await opensearchSearch(args.index, body);
  return formatSearchResults(response, `IOC Search: "${args.ioc}" (type: ${args.ioc_type})`);
}
