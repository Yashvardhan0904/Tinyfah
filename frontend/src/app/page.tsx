"use client";

import { useEffect, useRef, useState, type PointerEvent } from "react";
import Link from "next/link";
import { ArrowUpRight, CheckCircle2, Clock3, Layers3, Shield, Sparkles } from "lucide-react";
import { MissionComposer } from "@/components/composer/mission-composer";
import { Navbar } from "@/components/layout/navbar";
import { Footer } from "@/components/layout/footer";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { listScans } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { formatDate } from "@/lib/utils";

const capabilities = [
  { icon: Shield, title: "Evidence, not guesses", text: "Every result is backed by browser telemetry, screenshots, and reproducible steps." },
  { icon: Layers3, title: "ASVS coverage", text: "Map your surface against 17 OWASP chapters and 345 verification requirements." },
  { icon: Sparkles, title: "Actionable output", text: "Get a clear grade, prioritized findings, and remediation guidance your team can use." },
];

export default function HomePage() {
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const heroRef = useRef<HTMLElement>(null);

  const handleHeroPointerMove = (event: PointerEvent<HTMLElement>) => {
    const hero = heroRef.current;
    if (!hero || event.pointerType === "touch") return;

    const bounds = hero.getBoundingClientRect();
    const x = ((event.clientX - bounds.left) / bounds.width) * 100;
    const y = ((event.clientY - bounds.top) / bounds.height) * 100;
    hero.style.setProperty("--mouse-x", `${x}%`);
    hero.style.setProperty("--mouse-y", `${y}%`);
  };

  const resetHeroPointer = () => {
    heroRef.current?.style.setProperty("--mouse-x", "50%");
    heroRef.current?.style.setProperty("--mouse-y", "18%");
  };

  useEffect(() => {
    listScans()
      .then((scans) => setRecentScans(scans.slice(0, 4)))
      .catch(() => setRecentScans([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="min-h-screen bg-[#f7f9fc] text-[#15202b] flex flex-col">
      <Navbar />
      <main className="flex-1">
        <section
          ref={heroRef}
          onPointerMove={handleHeroPointerMove}
          onPointerLeave={resetHeroPointer}
          className="hero-section relative overflow-hidden px-4 pb-20 pt-16 sm:px-8 sm:pt-24"
        >
          <div className="hero-grid absolute inset-0 -z-10" />
          <div className="hero-orb hero-orb-primary absolute -z-10" />
          <div className="hero-orb hero-orb-secondary absolute -z-10" />
          <div className="hero-pointer-glow pointer-events-none absolute inset-0 -z-10" />
          <div className="mx-auto max-w-7xl">
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="hero-heading text-4xl font-semibold tracking-[-0.04em] text-[#0f1c28] sm:text-6xl">
                Know exactly how secure<br className="hidden sm:block" /> your product really is.
              </h1>
              <p className="hero-copy mx-auto mt-6 max-w-2xl text-base leading-7 text-[#5d6b7b] sm:text-lg">
                Tinyfah runs deterministic browser checks and autonomous AI verification against the OWASP ASVS standard, then turns the evidence into a report your team can act on.
              </p>
            </div>
            <div className="mt-12">
              <MissionComposer />
            </div>
            <div className="mx-auto mt-10 flex max-w-3xl flex-wrap items-center justify-center gap-x-7 gap-y-3 text-xs text-[#748294]">
              <span className="inline-flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-[#ea7336]" /> No setup required</span>
              <span className="inline-flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-[#ea7336]" /> Evidence-backed findings</span>
              <span className="inline-flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-[#ea7336]" /> ASVS v5.0.0 aligned</span>
            </div>
          </div>
        </section>

        <section id="features" className="border-y border-[#dfe5ec] bg-[#ffffff] px-4 py-14 sm:px-8">
          <div className="mx-auto grid max-w-7xl gap-4 md:grid-cols-3">
            {capabilities.map(({ icon: Icon, title, text }) => (
              <div key={title} className="rounded-xl border border-[#dfe5ec] bg-[#ffffff] p-5">
                <Icon className="h-5 w-5 text-[#ea7336]" />
                <h2 className="mt-5 text-sm font-semibold text-[#15202b]">{title}</h2>
                <p className="mt-2 text-sm leading-6 text-[#5d6b7b]">{text}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mx-auto w-full max-w-7xl px-4 py-16 sm:px-8">
          <div className="mb-5 flex items-end justify-between">
            <div>
              <p className="text-xs font-mono uppercase tracking-[0.18em] text-[#ea7336]">Workspace</p>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight">Recent assessments</h2>
            </div>
            <Link href="/history" className="inline-flex items-center gap-1.5 text-sm text-[#5d6b7b] hover:text-[#ea7336]">
              View history <ArrowUpRight className="h-4 w-4" />
            </Link>
          </div>
          {loading ? (
            <div className="rounded-xl border border-[#dfe5ec] bg-[#ffffff] p-10 text-center text-sm text-[#748294]">Loading your assessment history…</div>
          ) : recentScans.length === 0 ? (
            <div className="rounded-xl border border-dashed border-[#516273] bg-[#ffffff] p-10 text-center">
              <Clock3 className="mx-auto h-6 w-6 text-[#748294]" />
              <p className="mt-3 text-sm font-medium text-[#516273]">Your assessment history will appear here.</p>
              <p className="mt-1 text-xs text-[#748294]">Launch your first scan above to start building your security baseline.</p>
            </div>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {recentScans.map((scan) => (
                <Link key={scan.id} href={`/scan/${scan.id}`} className="group flex items-center justify-between rounded-xl border border-[#dfe5ec] bg-[#ffffff] p-4 transition hover:border-[#fca87d] hover:bg-[#fff0e6]">
                  <div className="min-w-0">
                    <div className="mb-2 flex items-center gap-2"><span className="font-mono text-xs text-[#ea7336]">RUN #{scan.id}</span><Chip status={(scan.status as ChipStatus) || "queued"} dot /></div>
                    <p className="truncate text-sm font-medium text-[#243342] group-hover:text-[#15202b]">{scan.url}</p>
                    <p className="mt-1 text-xs text-[#748294]">{formatDate(scan.created_at)}</p>
                  </div>
                  <ArrowUpRight className="ml-4 h-4 w-4 shrink-0 text-[#748294] group-hover:text-[#ea7336]" />
                </Link>
              ))}
            </div>
          )}
        </section>
      </main>
      <Footer />
    </div>
  );
}
