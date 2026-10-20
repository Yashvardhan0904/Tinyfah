"use client";

import { create } from "zustand";
import type {
  Scan,
  ScanStatus,
  Grade,
  AgentStep,
  BrowserSession,
  SSEMessagePayload,
  SSEDonePayload,
  ScanResults,
} from "@/lib/types";
import { getScan, getSSEStreamUrl } from "@/lib/api";

export type StreamStatus =
  | "idle"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "closed"
  | "error";

interface ScanState {
  // Current scan identifiers & outcomes
  scanId: number | null;
  url: string;
  status: ScanStatus;
  grade: Grade | null;
  score: number | null;
  error: string | null;

  // Execution telemetry
  agentTrace: AgentStep[];
  latestStep: AgentStep | null;
  selectedStepIndex: number | null;
  browserSession: BrowserSession | null;

  // Stream state
  streamStatus: StreamStatus;
  eventSource: EventSource | null;
  heartbeatTimestamp: number | null;

  // Raw telemetry & unparsed audit logs
  rawLogs: string[];

  // Normalized final report results
  results: ScanResults | null;

  // Real-time elapsed duration
  startTime: number | null;
  endTime: number | null;

  // Actions
  connectToStream: (scanId: number) => void;
  disconnect: () => void;
  selectStep: (index: number | null) => void;
  setScanFromFetch: (scan: Scan) => void;
  reset: () => void;
  abortScanGracefully: () => void;
}

const initialState = {
  scanId: null,
  url: "",
  status: "queued" as ScanStatus,
  grade: null,
  score: null,
  error: null,
  agentTrace: [],
  latestStep: null,
  selectedStepIndex: null,
  browserSession: null,
  streamStatus: "idle" as StreamStatus,
  eventSource: null,
  heartbeatTimestamp: null,
  rawLogs: [],
  results: null,
  startTime: null,
  endTime: null,
};

export const useScanStore = create<ScanState>((set, get) => ({
  ...initialState,

  connectToStream: (scanId: number) => {
    // Teardown existing stream if any
    const existing = get().eventSource;
    if (existing) {
      existing.close();
    }

    set({
      scanId,
      streamStatus: "connecting",
      startTime: Date.now(),
      endTime: null,
      rawLogs: [],
      agentTrace: [],
      latestStep: null,
      selectedStepIndex: null,
      results: null,
    });

    const streamUrl = getSSEStreamUrl(scanId);
    let es: EventSource;

    try {
      es = new EventSource(streamUrl);
    } catch (err) {
      set({
        streamStatus: "error",
        error: err instanceof Error ? err.message : "Failed to open stream",
      });
      return;
    }

    es.onopen = () => {
      set({ streamStatus: "connected" });
    };

    es.addEventListener("message", (event: MessageEvent) => {
      const rawText = event.data;
      try {
        const payload: SSEMessagePayload = JSON.parse(rawText);

        set((state) => {
          const newTrace = payload.agent_trace || [];
          const newLatest =
            payload.latest_step || (newTrace.length > 0 ? newTrace[newTrace.length - 1] : null);

          // If no step is selected, auto-select latest step
          const currentSelected = state.selectedStepIndex;
          const nextSelected =
            currentSelected === null ? (newTrace.length > 0 ? newTrace.length - 1 : null) : currentSelected;

          return {
            streamStatus: "connected",
            url: payload.url || state.url,
            status: payload.status || state.status,
            grade: payload.grade ?? state.grade,
            score: payload.score ?? state.score,
            error: payload.error ?? state.error,
            agentTrace: newTrace,
            latestStep: newLatest,
            selectedStepIndex: nextSelected,
            browserSession: payload.browser_session ?? state.browserSession,
            heartbeatTimestamp: Date.now(),
            rawLogs: [`[${new Date().toISOString()}] ${rawText}`, ...state.rawLogs.slice(0, 499)],
            results: payload.results ?? state.results,
          };
        });
      } catch {
        set((state) => ({
          rawLogs: [`[${new Date().toISOString()}] RAW: ${rawText}`, ...state.rawLogs.slice(0, 499)],
        }));
      }
    });

    es.addEventListener("done", (event: MessageEvent) => {
      const rawText = event.data;
      try {
        const payload: SSEDonePayload = JSON.parse(rawText);
        set((state) => ({
          status: payload.status || state.status,
          grade: payload.grade ?? state.grade,
          score: payload.score ?? state.score,
          streamStatus: "closed",
          endTime: Date.now(),
          rawLogs: [`[${new Date().toISOString()}] TERMINAL DONE: ${rawText}`, ...state.rawLogs],
        }));
      } catch {
        set({ streamStatus: "closed", endTime: Date.now() });
      }

      es.close();

      // Ensure 100% full normalized results are loaded from database
      const currentId = get().scanId;
      if (currentId) {
        getScan(currentId)
          .then((fullScan) => {
            get().setScanFromFetch(fullScan);
          })
          .catch((err) => {
            console.error("Failed to fetch full scan record upon completion", err);
          });
      }
    });

    es.addEventListener("error", () => {
      if (es.readyState === EventSource.CONNECTING) {
        set({ streamStatus: "reconnecting" });
      } else if (es.readyState === EventSource.CLOSED) {
        set({ streamStatus: "closed" });
      } else {
        set({ streamStatus: "error" });
      }
    });

    set({ eventSource: es });
  },

  disconnect: () => {
    const es = get().eventSource;
    if (es) {
      es.close();
    }
    set({ eventSource: null, streamStatus: "closed", endTime: Date.now() });
  },

  abortScanGracefully: () => {
    const es = get().eventSource;
    if (es) {
      es.close();
    }
    set((state) => ({
      eventSource: null,
      streamStatus: "closed",
      endTime: Date.now(),
      rawLogs: [
        `[${new Date().toISOString()}] CLIENT ABORT: Disconnected from live stream.`,
        ...state.rawLogs,
      ],
    }));
  },

  selectStep: (index) => set({ selectedStepIndex: index }),

  setScanFromFetch: (scan: Scan) => {
    const trace = scan.results?.agent_trace || [];
    set({
      scanId: scan.id,
      url: scan.url,
      status: scan.status,
      grade: scan.grade,
      score: scan.score,
      error: scan.error,
      results: scan.results,
      agentTrace: trace,
      latestStep: trace.length > 0 ? trace[trace.length - 1] : null,
      browserSession: scan.results?.browser_session ?? null,
      selectedStepIndex: trace.length > 0 ? trace.length - 1 : null,
      streamStatus: "closed",
    });
  },

  reset: () => {
    const es = get().eventSource;
    if (es) {
      es.close();
    }
    set({ ...initialState });
  },
}));
