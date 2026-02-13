import { TIME_ANCHOR, DEFAULT_HOURS_BACK } from "./constants.js";
import type { OpenSearchResponse } from "../opensearch-client.js";
import { maybeSpill } from "./spill.js";

export function buildTimeRange(hoursBack: number = DEFAULT_HOURS_BACK): { gte: string; lte: string } {
  const anchor = new Date(TIME_ANCHOR);
  const halfWindow = hoursBack * 60 * 60 * 1000;
  return {
    gte: new Date(anchor.getTime() - halfWindow).toISOString(),
    lte: new Date(anchor.getTime() + halfWindow).toISOString(),
  };
}

function getTotalHits(response: OpenSearchResponse): number {
  if (!response.hits?.total) return 0;
  if (typeof response.hits.total === "number") return response.hits.total;
  return response.hits.total.value;
}

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

export function formatSearchResults(response: OpenSearchResponse, label: string = "Results"): string {
  const total = getTotalHits(response);
  const hits = response.hits?.hits ?? [];

  if (total === 0) {
    return `${label}: No results found.`;
  }

  const lines: string[] = [`${label}: ${total} total hits (showing ${hits.length})`];
  lines.push("---");

  for (const hit of hits) {
    const src = hit._source;
    const timestamp = src.timestamp ?? src["@timestamp"] ?? "unknown";
    const agentName = getNestedValue(src, "agent.name") ?? "unknown";
    const agentId = getNestedValue(src, "agent.id") ?? "?";
    const ruleDesc = getNestedValue(src, "rule.description") ?? "";
    const ruleId = getNestedValue(src, "rule.id") ?? "";
    const ruleLevel = getNestedValue(src, "rule.level") ?? "";

    lines.push(`[${timestamp}] Agent: ${agentName} (${agentId})`);
    if (ruleId) lines.push(`  Rule ${ruleId} (Level ${ruleLevel}): ${ruleDesc}`);

    // Show key data fields
    const data = src.data as Record<string, unknown> | undefined;
    if (data) {
      const interesting = ["srcip", "dstip", "src_ip", "dst_ip", "url", "hostname", "command", "title"];
      for (const key of interesting) {
        if (data[key]) lines.push(`  data.${key}: ${data[key]}`);
      }
      // Windows event data
      const winEvt = data.win as Record<string, unknown> | undefined;
      const evtData = winEvt?.eventdata as Record<string, unknown> | undefined;
      if (evtData) {
        const winFields = ["image", "parentImage", "commandLine", "targetFilename",
                           "originalFileName", "sourceIp", "destinationIp", "destinationPort"];
        for (const key of winFields) {
          if (evtData[key]) lines.push(`  win.eventdata.${key}: ${evtData[key]}`);
        }
      }
    }

    const syscheck = src.syscheck as Record<string, unknown> | undefined;
    if (syscheck) {
      lines.push(`  syscheck.path: ${syscheck.path ?? "N/A"}`);
      if (syscheck.value_name) lines.push(`  syscheck.value_name: ${syscheck.value_name}`);
      if (syscheck.sha256_after) lines.push(`  syscheck.sha256: ${syscheck.sha256_after}`);
      if (syscheck.md5_after) lines.push(`  syscheck.md5: ${syscheck.md5_after}`);
      if (syscheck.event) lines.push(`  syscheck.event: ${syscheck.event}`);
      if (syscheck.changed_attributes) lines.push(`  syscheck.changed: ${(syscheck.changed_attributes as string[]).join(", ")}`);
    }

    // Show full_log for extra context (truncated)
    const fullLog = src.full_log as string | undefined;
    if (fullLog) {
      const truncated = fullLog.length > 300 ? fullLog.slice(0, 300) + "..." : fullLog;
      lines.push(`  full_log: ${truncated.replace(/\n/g, " | ")}`);
    }

    lines.push("");
  }

  const text = lines.join("\n");
  return maybeSpill(text, hits.length, "search-results");
}

export function formatAlerts(response: OpenSearchResponse): string {
  const total = getTotalHits(response);
  const hits = response.hits?.hits ?? [];

  if (total === 0) {
    return "Alerts: No alerts found matching criteria.";
  }

  const lines: string[] = [`Alerts: ${total} total (showing ${hits.length})`];
  lines.push("---");

  for (const hit of hits) {
    const src = hit._source;
    const timestamp = src.timestamp ?? src["@timestamp"] ?? "unknown";
    const agentName = getNestedValue(src, "agent.name") ?? "unknown";
    const ruleDesc = getNestedValue(src, "rule.description") ?? "";
    const ruleId = getNestedValue(src, "rule.id") ?? "";
    const ruleLevel = getNestedValue(src, "rule.level") ?? "?";
    const ruleGroups = getNestedValue(src, "rule.groups") ?? [];

    lines.push(`[Level ${ruleLevel}] ${ruleDesc}`);
    lines.push(`  Time: ${timestamp}`);
    lines.push(`  Agent: ${agentName} | Rule: ${ruleId}`);
    if (Array.isArray(ruleGroups) && ruleGroups.length > 0) {
      lines.push(`  Groups: ${ruleGroups.join(", ")}`);
    }

    const mitre = getNestedValue(src, "rule.mitre") as Record<string, unknown> | undefined;
    if (mitre) {
      const techniques = (mitre.technique as string[]) ?? [];
      const tactics = (mitre.tactic as string[]) ?? [];
      if (techniques.length > 0) lines.push(`  MITRE: ${tactics.join(", ")} -> ${techniques.join(", ")}`);
    }

    lines.push("");
  }

  const text = lines.join("\n");
  return maybeSpill(text, hits.length, "alerts");
}
