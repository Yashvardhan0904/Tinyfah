"use client";

import { SegmentedControl, type SegmentOption } from "@/components/ui/segmented-control";
import { CheckSquare, Bot } from "lucide-react";
import type { SuiteType } from "@/lib/types";

interface ModeToggleProps {
  value: SuiteType;
  onChange: (val: SuiteType) => void;
}

export function ModeToggle({ value, onChange }: ModeToggleProps) {
  const options: SegmentOption<SuiteType>[] = [
    {
      value: "v1",
      label: "Quick verification",
      icon: <CheckSquare className="h-3.5 w-3.5 text-[#ea7336]" />,
      activeColorClass: "text-[#ea7336] border-[#ea7336]/40",
      badge: "Fast",
    },
    {
      value: "langgraph",
      label: "Deep AI audit",
      icon: <Bot className="h-3.5 w-3.5 text-[#748294]" />,
      activeColorClass: "text-[#15202b] border-[#dfe5ec]",
      badge: "ASVS",
    },
  ];

  return <SegmentedControl value={value} onChange={onChange} options={options} />;
}
