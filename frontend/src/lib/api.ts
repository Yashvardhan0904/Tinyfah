import type { Scan, ScanRequest, WorkflowInfo } from "./types";

const getApiBase = () => {
  if (typeof window !== "undefined") {
    // In browser, relative URLs proxy via Next.js rewrites or direct env
    return process.env.NEXT_PUBLIC_API_URL || "";
  }
  return process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
};

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const base = getApiBase();
  const url = `${base}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!res.ok) {
    let errorDetail = `API Error ${res.status}: ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorDetail = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      const errText = await res.text();
      if (errText) errorDetail = errText;
    }
    throw new Error(errorDetail);
  }

  return res.json() as Promise<T>;
}

export async function createScan(payload: ScanRequest): Promise<Scan> {
  return fetchJSON<Scan>("/api/scans", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getScan(id: number | string): Promise<Scan> {
  return fetchJSON<Scan>(`/api/scans/${id}`);
}

export async function listScans(): Promise<Scan[]> {
  return fetchJSON<Scan[]>("/api/scans");
}

export async function getWorkflows(): Promise<{ workflows: WorkflowInfo[] }> {
  try {
    return await fetchJSON<{ workflows: WorkflowInfo[] }>("/api/harness/v1/workflows");
  } catch {
    // Fallback default workflow specs if backend harness endpoint is unreachable
    return {
      workflows: [
        {
          id: "v1",
          name: "Deterministic Chapter V1 Harness",
          type: "deterministic",
          description: "Active canary probes, browser workflows, and deterministic grading for ASVS Chapter V1.",
          supported_suites: ["v1", "chapter_v1"],
        },
        {
          id: "langgraph",
          name: "LangGraph Multi-Agent Security Loop",
          type: "multi_agent_graph",
          description: "Recon, Supervisor, 6 Domain Specialists, Universal ASVS Standards Evaluator across all 17 chapters (345 requirements).",
          supported_suites: ["langgraph", "full"],
        },
      ],
    };
  }
}

export async function getASVSTests(suite: string): Promise<{
  suite: string;
  count: number;
  tests: unknown[];
  chapter?: string;
}> {
  return fetchJSON(`/asvs/tests?suite=${encodeURIComponent(suite)}`);
}

export function getSSEStreamUrl(scanId: number | string): string {
  const base = getApiBase();
  return `${base}/api/scans/${scanId}/stream`;
}
