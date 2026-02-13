// Wazuh/OpenSearch connection — update these for your environment
export const OPENSEARCH_URL = process.env.WAZUH_OPENSEARCH_URL ?? "https://YOUR_WAZUH_HOST:9200";
export const OPENSEARCH_USER = process.env.WAZUH_OPENSEARCH_USER ?? "admin";
export const OPENSEARCH_PASS = process.env.WAZUH_OPENSEARCH_PASS ?? "CHANGE_ME";

// Default index patterns
export const DEFAULT_ALERTS_INDEX = "wazuh-alerts-*";
export const DEFAULT_STATS_INDEX = "wazuh-statistics-*";

// Time anchor — set to center of your investigation window (ISO 8601)
export const TIME_ANCHOR = process.env.WAZUH_TIME_ANCHOR ?? "2025-10-09T20:36:04Z";
// Default search window in hours (centered on TIME_ANCHOR)
export const DEFAULT_HOURS_BACK = Number(process.env.WAZUH_HOURS_BACK ?? "2");
export const MAX_RESULTS = 50;

// IOC type to Wazuh field mappings
export const IOC_FIELD_MAP: Record<string, string[]> = {
  ip: ["data.srcip", "data.dstip", "data.src_ip", "data.dst_ip", "agent.ip"],
  hash: [
    "syscheck.sha256_after",
    "syscheck.md5_after",
    "syscheck.sha1_after",
    "data.virustotal.source.sha256",
    "data.virustotal.source.md5",
  ],
  domain: ["data.dns.question.name", "data.url", "data.hostname"],
  url: ["data.url", "data.http.url", "data.uri"],
  filename: [
    "syscheck.path",
    "syscheck.value_name",
    "data.win.eventdata.targetFilename",
    "data.win.eventdata.image",
    "data.win.eventdata.parentImage",
    "data.file",
    "data.audit.file.name",
  ],
};

// Alert severity level ranges
export const SEVERITY_LEVELS: Record<string, { min: number; max: number }> = {
  low: { min: 0, max: 6 },
  medium: { min: 7, max: 10 },
  high: { min: 11, max: 14 },
  critical: { min: 15, max: 99 },
};
