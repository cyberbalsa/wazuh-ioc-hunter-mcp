import { OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASS } from "./lib/constants.js";

const AUTH_HEADER = "Basic " + Buffer.from(`${OPENSEARCH_USER}:${OPENSEARCH_PASS}`).toString("base64");

export interface OpenSearchResponse {
  hits?: {
    total?: { value: number } | number;
    hits?: Array<{
      _index: string;
      _id: string;
      _source: Record<string, unknown>;
      _score?: number;
    }>;
  };
  aggregations?: Record<string, unknown>;
  error?: unknown;
  status?: number;
  [key: string]: unknown;
}

export async function opensearchRequest(
  path: string,
  method: "GET" | "POST" = "GET",
  body?: unknown,
): Promise<OpenSearchResponse> {
  const url = `${OPENSEARCH_URL}${path}`;

  const headers: Record<string, string> = {
    Authorization: AUTH_HEADER,
    "Content-Type": "application/json",
  };

  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`OpenSearch ${method} ${path} failed (${response.status}): ${text}`);
  }

  return (await response.json()) as OpenSearchResponse;
}

export async function opensearchSearch(
  index: string,
  body: Record<string, unknown>,
): Promise<OpenSearchResponse> {
  return opensearchRequest(`/${encodeURIComponent(index)}/_search`, "POST", body);
}

export async function opensearchCat(endpoint: string): Promise<string> {
  const url = `${OPENSEARCH_URL}/_cat/${endpoint}?format=json&v`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: AUTH_HEADER,
    },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`OpenSearch _cat/${endpoint} failed (${response.status}): ${text}`);
  }

  return await response.text();
}
