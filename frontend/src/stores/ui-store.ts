"use client";

import { create } from "zustand";

export type MobileTab = "tasks" | "live" | "steps" | "log";

interface UIState {
  activeMobileTab: MobileTab;
  setActiveMobileTab: (tab: MobileTab) => void;

  isDrawerOpen: boolean;
  toggleDrawer: () => void;
  setDrawerOpen: (open: boolean) => void;

  showRawJSON: boolean;
  setShowRawJSON: (show: boolean) => void;
  toggleRawJSON: () => void;

  showStopDialog: boolean;
  setShowStopDialog: (show: boolean) => void;
}

export const useUIStore = create<UIState>((set) => ({
  activeMobileTab: "tasks",
  setActiveMobileTab: (tab) => set({ activeMobileTab: tab }),

  isDrawerOpen: false,
  toggleDrawer: () => set((s) => ({ isDrawerOpen: !s.isDrawerOpen })),
  setDrawerOpen: (open) => set({ isDrawerOpen: open }),

  showRawJSON: false,
  setShowRawJSON: (show) => set({ showRawJSON: show }),
  toggleRawJSON: () => set((s) => ({ showRawJSON: !s.showRawJSON })),

  showStopDialog: false,
  setShowStopDialog: (show) => set({ showStopDialog: show }),
}));
