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
      icon: <CheckSquare className="h-3.5 w-3.5 text-[#18a66b]" />,
      activeColorClass: "text-[#18a66b] border-[#18a66b]/40",
      badge: "Fast",
    },
    {
      value: "langgraph",
      label: "Deep AI audit",
      icon: <Bot className="h-3.5 w-3.5 text-[#6d4aca]" />,
      activeColorClass: "text-[#6d4aca] border-[#6d4aca]/40",
      badge: "ASVS",
    },
  ];

  return <SegmentedControl value={value} onChange={onChange} options={options} />;
}
