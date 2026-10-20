"use client";

import { useEffect } from "react";
import { useScanStore } from "@/stores/scan-store";
import { WorkspaceShell } from "@/components/workspace/workspace-shell";

interface ScanClientViewProps {
  scanId: number;
}

export function ScanClientView({ scanId }: ScanClientViewProps) {
  const connectToStream = useScanStore((s) => s.connectToStream);
  const disconnect = useScanStore((s) => s.disconnect);

  useEffect(() => {
    if (scanId && !isNaN(scanId)) {
      connectToStream(scanId);
    }

    return () => {
      disconnect();
    };
  }, [scanId, connectToStream, disconnect]);

  return <WorkspaceShell />;
}
