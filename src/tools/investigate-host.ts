import { z } from "zod";
import { opensearchSearch } from "../opensearch-client.js";
import { DEFAULT_ALERTS_INDEX } from "../lib/constants.js";
import { buildTimeRange } from "../lib/formatters.js";

export const investigateHostSchema = {
  agent_name: z.string().describe("Agent/host name to investigate (e.g. 'npc-petyerbaeli', 'castelblack')"),
  hours_back: z.number().default(336).describe("Hours before/after time anchor to search"),
  index: z.string().default(DEFAULT_ALERTS_INDEX).describe("Index pattern to search"),
};

export async function investigateHost(args: {
  agent_name: string;
  hours_back: number;
  index: string;
}): Promise<string> {
  const timeRange = buildTimeRange(args.hours_back);
  const filter = [
    { match_phrase: { "agent.name": args.agent_name } },
    { range: { timestamp: { gte: timeRange.gte, lte: timeRange.lte } } },
  ];

  // Run multiple aggregation queries in parallel
  const [overview, executables, registryChanges, highSeverity, loginActivity] = await Promise.all([
    // 1. Overview: agent info + severity distribution + top rules
    opensearchSearch(args.index, {
      query: { bool: { filter } },
      size: 0,
      aggs: {
        agent_id: { terms: { field: "agent.id", size: 1 } },
        agent_ip: { terms: { field: "agent.ip", size: 1 } },
        os: { terms: { field: "agent.os.name", size: 1 } },
        severity: {
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
        top_rules: { terms: { field: "rule.description", size: 15 } },
        rule_groups: { terms: { field: "rule.groups", size: 20 } },
        timeline: { date_histogram: { field: "timestamp", fixed_interval: "6h" } },
      },
    }),

    // 2. Executables seen via BAM registry (syscheck.value_name contains exe paths)
    opensearchSearch(args.index, {
      query: {
        bool: {
          filter: [
            ...filter,
            { wildcard: { "syscheck.value_name": "*\\\\*.exe" } },
          ],
        },
      },
      size: 50,
      sort: [{ timestamp: { order: "asc" } }],
      _source: ["timestamp", "syscheck.value_name", "syscheck.event", "syscheck.sha256_after", "rule.id", "rule.description"],
    }),

    // 3. All registry changes (syscheck events)
    opensearchSearch(args.index, {
      query: {
        bool: {
          filter: [
            ...filter,
            { terms: { "rule.id": ["750", "751", "752", "753"] } },
          ],
        },
      },
      size: 0,
      aggs: {
        by_event: { terms: { field: "syscheck.event", size: 10 } },
        by_path: { terms: { field: "syscheck.path", size: 10 } },
      },
    }),

    // 4. High severity events
    opensearchSearch(args.index, {
      query: {
        bool: {
          filter: [
            ...filter,
            { range: { "rule.level": { gte: 7 } } },
          ],
        },
      },
      size: 20,
      sort: [{ "rule.level": { order: "desc" } }, { timestamp: { order: "desc" } }],
      _source: ["timestamp", "rule.id", "rule.description", "rule.level", "rule.groups", "rule.mitre",
                "data.srcip", "data.dstip", "syscheck.path", "syscheck.value_name", "full_log"],
    }),

    // 5. Login activity
    opensearchSearch(args.index, {
      query: {
        bool: {
          filter: [
            ...filter,
            { terms: { "rule.groups": ["authentication_success", "authentication_failed"] } },
          ],
        },
      },
      size: 0,
      aggs: {
        by_user: { terms: { field: "data.dstuser", size: 10 } },
        by_src_ip: { terms: { field: "data.srcip", size: 10 } },
        by_logon_type: { terms: { field: "data.logonType", size: 10 } },
      },
    }),
  ]);

  const lines: string[] = [];
  const aggs = overview.aggregations as Record<string, unknown>;
  const total = typeof overview.hits?.total === "number" ? overview.hits.total : overview.hits?.total?.value ?? 0;

  // Header
  const idBuckets = (aggs?.agent_id as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  const ipBuckets = (aggs?.agent_ip as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  const osBuckets = (aggs?.os as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  lines.push(`═══ HOST INVESTIGATION: ${args.agent_name} ═══`);
  lines.push(`  ID: ${idBuckets?.[0]?.key ?? "?"} | IP: ${ipBuckets?.[0]?.key ?? "?"} | OS: ${osBuckets?.[0]?.key ?? "?"}`);
  lines.push(`  Total events: ${total}`);
  lines.push("");

  // Severity distribution
  const sevBuckets = (aggs?.severity as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  if (sevBuckets) {
    lines.push("─── Severity Distribution ───");
    for (const b of sevBuckets) lines.push(`  ${b.key}: ${b.doc_count}`);
    lines.push("");
  }

  // High severity events
  const highHits = highSeverity.hits?.hits ?? [];
  if (highHits.length > 0) {
    lines.push("─── High Severity Events (Level 7+) ───");
    for (const h of highHits) {
      const s = h._source;
      const ts = s.timestamp ?? s["@timestamp"];
      const rLevel = (s.rule as Record<string, unknown>)?.level;
      const rDesc = (s.rule as Record<string, unknown>)?.description;
      const rId = (s.rule as Record<string, unknown>)?.id;
      lines.push(`  [Level ${rLevel}] ${ts} - Rule ${rId}: ${rDesc}`);
      const fullLog = s.full_log as string | undefined;
      if (fullLog) {
        const truncated = fullLog.length > 200 ? fullLog.slice(0, 200) + "..." : fullLog;
        lines.push(`    ${truncated.replace(/\n/g, " | ")}`);
      }
    }
    lines.push("");
  }

  // Executables seen
  const exeHits = executables.hits?.hits ?? [];
  if (exeHits.length > 0) {
    lines.push("─── Executables (BAM Registry) ───");
    const seen = new Set<string>();
    for (const h of exeHits) {
      const s = h._source;
      const sc = s.syscheck as Record<string, unknown>;
      const valueName = sc?.value_name as string ?? "";
      const event = sc?.event ?? "";
      const sha256 = sc?.sha256_after ?? "";
      const ts = s.timestamp;
      // Extract just the exe name from path
      const exeName = valueName.split("\\").pop() ?? valueName;
      const key = `${exeName}|${event}`;
      if (!seen.has(key)) {
        seen.add(key);
        lines.push(`  [${event}] ${ts} - ${exeName}`);
        lines.push(`    Path: ${valueName}`);
        if (sha256) lines.push(`    SHA256: ${sha256}`);
      }
    }
    lines.push("");
  }

  // Registry change summary
  const regAggs = registryChanges.aggregations as Record<string, unknown>;
  const eventBuckets = (regAggs?.by_event as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  if (eventBuckets && eventBuckets.length > 0) {
    lines.push("─── Registry Changes Summary ───");
    for (const b of eventBuckets) lines.push(`  ${b.key}: ${b.doc_count}`);
    lines.push("");
  }

  // Login activity
  const loginAggs = loginActivity.aggregations as Record<string, unknown>;
  const userBuckets = (loginAggs?.by_user as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  const srcIpBuckets = (loginAggs?.by_src_ip as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  if (userBuckets && userBuckets.length > 0) {
    lines.push("─── Login Activity ───");
    lines.push("  Users:");
    for (const b of userBuckets) lines.push(`    ${b.key}: ${b.doc_count}`);
    if (srcIpBuckets && srcIpBuckets.length > 0) {
      lines.push("  Source IPs:");
      for (const b of srcIpBuckets) lines.push(`    ${b.key}: ${b.doc_count}`);
    }
    lines.push("");
  }

  // Top rules
  const ruleBuckets = (aggs?.top_rules as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  if (ruleBuckets) {
    lines.push("─── Top Rules ───");
    for (const b of ruleBuckets) lines.push(`  ${b.key}: ${b.doc_count}`);
    lines.push("");
  }

  // Activity timeline
  const timeBuckets = (aggs?.timeline as Record<string, unknown>)?.buckets as Array<Record<string, unknown>>;
  if (timeBuckets) {
    const nonZero = timeBuckets.filter((b) => (b.doc_count as number) > 0);
    if (nonZero.length > 0) {
      lines.push("─── Activity Timeline (6h buckets) ───");
      for (const b of nonZero) lines.push(`  ${b.key_as_string}: ${b.doc_count}`);
    }
  }

  return lines.join("\n");
}
