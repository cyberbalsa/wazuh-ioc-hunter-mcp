import { z } from "zod";
import { opensearchSearch } from "../opensearch-client.js";
import { DEFAULT_ALERTS_INDEX } from "../lib/constants.js";
import { buildTimeRange } from "../lib/formatters.js";
import { maybeSpill } from "../lib/spill.js";

export const getRuleInfoSchema = {
  rule_id: z.string().describe("Wazuh rule ID to look up"),
  hours_back: z.number().default(24).describe("Hours before/after time anchor for occurrence stats"),
  index: z.string().default(DEFAULT_ALERTS_INDEX).describe("Index pattern to search"),
};

export async function getRuleInfo(args: {
  rule_id: string;
  hours_back: number;
  index: string;
}): Promise<string> {
  const timeRange = buildTimeRange(args.hours_back);

  const body = {
    query: {
      bool: {
        filter: [
          { term: { "rule.id": args.rule_id } },
          { range: { timestamp: { gte: timeRange.gte, lte: timeRange.lte } } },
        ],
      },
    },
    size: 1,
    sort: [{ timestamp: { order: "desc" } }],
    aggs: {
      affected_agents: {
        terms: { field: "agent.name", size: 20 },
      },
      over_time: {
        date_histogram: {
          field: "timestamp",
          fixed_interval: "1h",
        },
      },
    },
  };

  const response = await opensearchSearch(args.index, body);
  const total = typeof response.hits?.total === "number"
    ? response.hits.total
    : response.hits?.total?.value ?? 0;

  if (total === 0) {
    return `Rule ${args.rule_id}: No occurrences found in the time range.`;
  }

  const hit = response.hits!.hits![0]._source;
  const rule = hit.rule as Record<string, unknown> | undefined;

  const lines: string[] = [];
  lines.push(`Rule ${args.rule_id}: ${rule?.description ?? "Unknown"}`);
  lines.push(`  Level: ${rule?.level ?? "?"}`);
  lines.push(`  Total occurrences: ${total}`);

  if (rule?.groups && Array.isArray(rule.groups)) {
    lines.push(`  Groups: ${(rule.groups as string[]).join(", ")}`);
  }

  // MITRE ATT&CK mappings
  const mitre = rule?.mitre as Record<string, unknown> | undefined;
  if (mitre) {
    const tactics = (mitre.tactic as string[]) ?? [];
    const techniques = (mitre.technique as string[]) ?? [];
    const ids = (mitre.id as string[]) ?? [];
    if (tactics.length > 0) lines.push(`  MITRE Tactics: ${tactics.join(", ")}`);
    if (techniques.length > 0) lines.push(`  MITRE Techniques: ${techniques.join(", ")}`);
    if (ids.length > 0) lines.push(`  MITRE IDs: ${ids.join(", ")}`);
  }

  // Compliance mappings
  for (const framework of ["pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc"]) {
    const val = rule?.[framework] as string[] | undefined;
    if (val && val.length > 0) {
      lines.push(`  ${framework.toUpperCase()}: ${val.join(", ")}`);
    }
  }

  // Affected agents
  const aggs = response.aggregations as Record<string, unknown> | undefined;
  const agentBuckets = (aggs?.affected_agents as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  if (agentBuckets && agentBuckets.length > 0) {
    lines.push("\n  Affected Agents:");
    for (const b of agentBuckets) {
      lines.push(`    ${b.key}: ${b.doc_count} occurrences`);
    }
  }

  // Timeline
  const timeBuckets = (aggs?.over_time as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  if (timeBuckets) {
    const nonZero = timeBuckets.filter((b) => (b.doc_count as number) > 0);
    if (nonZero.length > 0) {
      lines.push("\n  Timeline (hourly):");
      for (const b of nonZero) {
        lines.push(`    ${b.key_as_string}: ${b.doc_count}`);
      }
    }
  }

  const text = lines.join("\n");
  const agentCount = agentBuckets?.length ?? 0;
  const timelineCount = timeBuckets ? timeBuckets.filter((b) => (b.doc_count as number) > 0).length : 0;
  return maybeSpill(text, agentCount + timelineCount, "rule-info");
}
