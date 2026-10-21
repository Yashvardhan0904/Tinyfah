"use client";

import { useUIStore, type MobileTab } from "@/stores/ui-store";
import { cn } from "@/lib/utils";
import { ListOrdered, Monitor, Eye, Terminal } from "lucide-react";

export function MobileTabs() {
  const activeTab = useUIStore((s) => s.activeMobileTab);
  const setActiveTab = useUIStore((s) => s.setActiveMobileTab);

  const tabs: { id: MobileTab; label: string; icon: React.ReactNode }[] = [
    { id: "tasks", label: "Tasks", icon: <ListOrdered className="h-4 w-4" /> },
    { id: "live", label: "Live View", icon: <Monitor className="h-4 w-4" /> },
    { id: "steps", label: "Inspector", icon: <Eye className="h-4 w-4" /> },
    { id: "log", label: "SSE Log", icon: <Terminal className="h-4 w-4" /> },
  ];

  return (
    <div className="lg:hidden flex items-center justify-around bg-[#ffffff] border-t border-[#dfe5ec] py-2 px-1 shrink-0">
      {tabs.map((tab) => {
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              "flex flex-col items-center gap-1 px-3 py-1 rounded-md text-[11px] font-mono transition-colors",
              isActive
                ? "text-[#ea7336] bg-[#f5f7fa] border border-[#dfe5ec]"
                : "text-[#5d6b7b] hover:text-[#15202b]"
            )}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        );
      })}
    </div>
  );
}
