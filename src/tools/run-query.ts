import { z } from "zod";
import { opensearchRequest } from "../opensearch-client.js";
import { DEFAULT_ALERTS_INDEX } from "../lib/constants.js";
import { maybeSpill } from "../lib/spill.js";

export const runQuerySchema = {
  body: z.string().describe("OpenSearch query DSL as a JSON string"),
  index: z.string().default(DEFAULT_ALERTS_INDEX).describe("Index pattern to search"),
  path_suffix: z.string().default("_search").describe("API path suffix (e.g. '_search', '_count', '_mapping')"),
};

export async function runQuery(args: {
  body: string;
  index: string;
  path_suffix: string;
}): Promise<string> {
  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(args.body);
  } catch {
    return `Error: Invalid JSON in body parameter: ${args.body}`;
  }

  const path = `/${encodeURIComponent(args.index)}/${args.path_suffix}`;
  const method = parsedBody ? "POST" : "GET";
  const response = await opensearchRequest(path, method, parsedBody);

  const text = JSON.stringify(response, null, 2);
  // Count hits if this is a search response, otherwise use line count as proxy
  const resp = response as Record<string, unknown>;
  const hits = (resp?.hits as Record<string, unknown>)?.hits;
  const resultCount = Array.isArray(hits) ? hits.length : 0;
  return maybeSpill(text, resultCount, "raw-query");
}
