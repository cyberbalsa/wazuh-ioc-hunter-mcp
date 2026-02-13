import { z } from "zod";
import { opensearchRequest } from "../opensearch-client.js";
import { DEFAULT_ALERTS_INDEX } from "../lib/constants.js";

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

  return JSON.stringify(response, null, 2);
}
