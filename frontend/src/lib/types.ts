export type ScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "not_assessed";

export type Grade = "A" | "B" | "C" | "D" | "F" | "NOT_ASSESSED";

export type SuiteType =
  | "v1"
  | "chapter_v1"
  | "langgraph"
  | "chapter_sample"
  | "first_five"
  | "full";

export interface AgentStep {
  step: number;
  tool: string;
  reason: string;
  observation_preview?: string;
  status: "running" | "completed" | "failed" | "pending";
  screenshot?: string | null;
  timestamp?: string;
  input?: Record<string, unknown> | null;
}

export interface BrowserSession {
  live_view_url?: string | null;
  session_id?: string | null;
  status?: string | null;
}

export interface ASVSTestItem {
  requirement_id: string;
  chapter_code: string;
  chapter_name: string;
  status: "PASS" | "FAIL" | "MANUAL_VERIFY" | "NOT_TESTED" | "NOT_APPLICABLE" | "ERROR";
  severity: "high" | "medium" | "low" | "info";
  evidence: string;
  remediation: string;
  screenshot?: string | null;
}

export interface FindingItem {
  severity: "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  evidence: string;
  remediation: string;
  screenshot?: string | null;
}

export interface ScanResults {
  score?: number | null;
  grade?: Grade;
  summary?: string;
  scan_status?: string;
  coverage_percentage?: number;
  pass_rate_percentage?: number | null;
  agent_trace: AgentStep[];
  findings: FindingItem[];
  asvs_results: ASVSTestItem[];
  browser_session?: BrowserSession | null;
  screenshot?: string | null;
  [key: string]: unknown;
}

export interface Scan {
  id: number;
  url: string;
  status: ScanStatus;
  score: number | null;
  grade: Grade | null;
  results: ScanResults | null;
  error: string | null;
  created_at: string;
}

export interface ScanRequest {
  url: string;
  suite?: SuiteType;
  test_id?: string;
  focus_prompt?: string;
}

export interface SSEMessagePayload {
  id: number;
  url: string;
  status: ScanStatus;
  grade: Grade | null;
  score: number | null;
  browser_session: BrowserSession | null;
  trace_count: number;
  agent_trace: AgentStep[];
  latest_step: AgentStep | null;
  error: string | null;
  results?: ScanResults;
}

export interface SSEDonePayload {
  status: ScanStatus;
  grade: Grade | null;
  score: number | null;
}

export interface WorkflowInfo {
  id: string;
  name: string;
  type: string;
  description: string;
  supported_suites: string[];
}
