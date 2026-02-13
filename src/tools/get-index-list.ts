import { z } from "zod";
import { opensearchCat } from "../opensearch-client.js";

export const getIndexListSchema = {
  pattern: z.string().default("wazuh-*").describe("Index name pattern to filter (supports wildcards)"),
};

export async function getIndexList(args: { pattern: string }): Promise<string> {
  const raw = await opensearchCat(`indices/${args.pattern}`);

  let indices: Array<Record<string, string>>;
  try {
    indices = JSON.parse(raw);
  } catch {
    return raw; // Return raw text if not JSON
  }

  if (!Array.isArray(indices) || indices.length === 0) {
    return `No indices found matching pattern: ${args.pattern}`;
  }

  // Sort by index name
  indices.sort((a, b) => (a.index ?? "").localeCompare(b.index ?? ""));

  const lines: string[] = [`Indices matching "${args.pattern}" (${indices.length} found):`];
  lines.push("---");

  for (const idx of indices) {
    const health = idx.health ?? "?";
    const status = idx.status ?? "?";
    const name = idx.index ?? "?";
    const docsCount = idx["docs.count"] ?? "?";
    const storeSize = idx["store.size"] ?? "?";

    lines.push(`  [${health}] ${name} | Status: ${status} | Docs: ${docsCount} | Size: ${storeSize}`);
  }

  return lines.join("\n");
}
