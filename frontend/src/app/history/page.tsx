"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { listScans } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { GradeBadge } from "@/components/report/grade-badge";
import { Button } from "@/components/ui/button";
import { formatDate } from "@/lib/utils";
import { Navbar } from "@/components/layout/navbar";
import { Footer } from "@/components/layout/footer";
import { Search, Radio, FileText, Calendar } from "lucide-react";

export default function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    let ignore = false;
    listScans()
      .then((data) => {
        if (!ignore) setScans(data);
      })
      .catch(() => {
        if (!ignore) setScans([]);
      });

    return () => {
      ignore = true;
    };
  }, []);

  const filteredScans = scans.filter((s) => {
    return (
      s.url?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.id?.toString().includes(searchTerm) ||
      s.status?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (s.grade && s.grade.toLowerCase().includes(searchTerm.toLowerCase()))
    );
  });

  return (
    <div className="min-h-screen bg-[#f7f9fc] text-[#15202b] flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar />

      {/* Main Content */}
      <main className="flex-1 max-w-7xl mx-auto w-full p-6 sm:p-10 space-y-7">
        <div>
          <p className="text-xs font-mono uppercase tracking-[0.18em] text-[#ea7336]">Workspace</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[#0f1c28]">Assessment history</h1>
          <p className="mt-2 text-sm text-[#5d6b7b]">Review every run, its evidence, and the current security posture of your targets.</p>
        </div>
        {/* Controls */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="absolute left-3 top-3 h-3.5 w-3.5 text-[#748294]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by URL, scan ID, or status..."
              className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-[#ffffff] border border-[#cbd5e1] text-sm text-[#15202b] placeholder-[#748294] focus:outline-none focus:border-[#ea7336] focus:ring-2 focus:ring-[#ea7336]/10"
            />
          </div>

          <div className="text-xs font-mono text-[#748294]">
            Showing {filteredScans.length} of {scans.length} runs
          </div>
        </div>

        {/* Scans Table / Cards */}
        {loading ? (
          <div className="p-12 text-center text-xs font-mono text-[#748294]">
            <div className="h-5 w-5 border-2 border-[#ea7336] border-t-transparent rounded-full animate-spin mx-auto mb-2" />
            <span>Fetching historical scans...</span>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="p-12 rounded-xl bg-[#ffffff] border border-dashed border-[#cbd5e1] text-center text-sm text-[#748294]">
            No assessment runs found.
          </div>
        ) : (
          <div className="rounded-xl bg-[#ffffff] border border-[#dfe5ec] overflow-hidden divide-y divide-[#dfe5ec]">
            {filteredScans.map((scan) => (
              <div
                key={scan.id}
                className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-[#fff0e6] transition-colors"
              >
                <div className="space-y-1.5 min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-mono font-bold text-[#ea7336]">
                      #{scan.id}
                    </span>
                    <Chip status={scan.status as ChipStatus} dot />
                    {scan.grade && <GradeBadge grade={scan.grade} size="sm" />}
                    {scan.score !== null && scan.score !== undefined && (
                      <span className="text-xs font-mono text-[#243342] px-1.5 py-0.2 rounded bg-[#f3f6f9] border border-[#cbd5e1]">
                        {scan.score}/100
                      </span>
                    )}
                  </div>

                  <div className="text-sm font-semibold text-[#243342] truncate">
                    {scan.url}
                  </div>

                  <div className="flex items-center gap-1.5 text-xs font-mono text-[#748294]">
                    <Calendar className="h-3 w-3" />
                    <span>{formatDate(scan.created_at)}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0">
                  <Link href={`/scan/${scan.id}`}>
                    <Button variant="neutral" size="sm" className="gap-1.5 font-mono text-xs">
                      <Radio className="h-3 w-3 text-blue-500" />
                      <span>Workspace</span>
                    </Button>
                  </Link>

                  <Link href={`/scan/${scan.id}/report`}>
                    <Button variant="primary" size="sm" className="gap-1.5 font-mono text-xs">
                      <FileText className="h-3 w-3" />
                      <span>Report</span>
                    </Button>
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
}
