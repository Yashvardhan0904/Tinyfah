"use client";

import { useCallback, useEffect, useRef, useState, type PointerEvent, type ReactNode } from "react";
import Link from "next/link";
import { ArrowUpRight, Check, Clock3, RefreshCw, X } from "lucide-react";
import { MissionComposer } from "@/components/composer/mission-composer";
import { Navbar } from "@/components/layout/navbar";
import { Footer } from "@/components/layout/footer";
import { Chip, type ChipStatus } from "@/components/ui/chip";
import { listScans } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { formatDate } from "@/lib/utils";

/* ------------------------------------------------------------------ */
/* Motion helpers                                                      */
/* ------------------------------------------------------------------ */

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(query.matches);
    const onChange = () => setReduced(query.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);
  return reduced;
}

function useInView<T extends HTMLElement>(threshold = 0.15, once = true) {
  const ref = useRef<T>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true);
          if (once) observer.disconnect();
        } else if (!once) {
          setInView(false);
        }
      },
      { threshold }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [threshold, once]);

  return { ref, inView };
}

const clamp01 = (n: number) => Math.min(1, Math.max(0, n));

/* 0 → 1 as the card travels up through the viewport */
function useScrollProgress<T extends HTMLElement>(disabled: boolean) {
  const ref = useRef<T>(null);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    if (disabled) {
      setProgress(1);
      return;
    }
    let raf = 0;
    const update = () => {
      raf = 0;
      const el = ref.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const vh = window.innerHeight;
      const start = vh * 0.85; // card top here  -> 0%
      const distance = Math.max(rect.height * 0.8, 1); // scrolled this far -> 100%
      setProgress(clamp01((start - rect.top) / distance));
    };
    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(update);
    };
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [disabled]);

  return { ref, progress };
}

/* Fades and lifts content in once, when it scrolls into view */
function Reveal({
  children,
  delay = 0,
  className = "",
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
}) {
  const { ref, inView } = useInView<HTMLDivElement>(0.12);
  return (
    <div
      ref={ref}
      style={{ transitionDelay: `${delay}ms` }}
      className={`transition-all duration-700 ease-[cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none ${
        inView ? "translate-y-0 opacity-100" : "translate-y-5 opacity-0 motion-reduce:translate-y-0"
      } ${className}`}
    >
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Live scan preview                                                   */
/* ------------------------------------------------------------------ */

type CheckResult = "pass" | "fail" | "warn";

const scanChecks: { name: string; ref: string; result: CheckResult; note: string }[] = [
  { name: "Security headers", ref: "V3", result: "fail", note: "No Content-Security-Policy" },
  { name: "Cookie attributes", ref: "V7", result: "fail", note: "Secure flag missing" },
  { name: "TLS configuration", ref: "V12", result: "pass", note: "TLS 1.2+ only" },
  { name: "Authentication flow", ref: "V6", result: "pass", note: "Rate limiting active" },
  { name: "Output encoding", ref: "V1", result: "pass", note: "No reflected input" },
  { name: "Error handling", ref: "V16", result: "warn", note: "Stack trace exposed" },
];

const TOTAL = scanChecks.length;
const TARGET_SCORE = 82;
const RING_R = 34;
const RING_C = 2 * Math.PI * RING_R;

const resultStyles: Record<CheckResult, { bg: string; fg: string }> = {
  pass: { bg: "#e4f4ec", fg: "#3f9e6b" },
  fail: { bg: "#fde8e4", fg: "#e5533d" },
  warn: { bg: "#fbf0d6", fg: "#c98a12" },
};

const summary = [
  { label: "Passed", count: scanChecks.filter((c) => c.result === "pass").length, color: "#3f9e6b" },
  { label: "Low", count: 1, color: "#8fa3b8" },
  { label: "Medium", count: 1, color: "#e3a72f" },
  { label: "High", count: 1, color: "#e5533d" },
];

function CheckIcon({ state, result }: { state: "pending" | "running" | "done"; result: CheckResult }) {
  if (state === "pending") {
    return <span className="h-5 w-5 rounded-full border border-[#dfe5ec] bg-[#f3f6f9]" />;
  }
  if (state === "running") {
    return (
      <span className="h-5 w-5 animate-spin rounded-full border-2 border-[#fca87d] border-t-[#ea7336] motion-reduce:animate-none" />
    );
  }
  const { bg, fg } = resultStyles[result];
  return (
    <span
      className="flex h-5 w-5 animate-[pop_0.35s_ease-out] items-center justify-center rounded-full motion-reduce:animate-none"
      style={{ backgroundColor: bg, color: fg }}
    >
      {result === "pass" && <Check className="h-3 w-3" strokeWidth={3} />}
      {result === "fail" && <X className="h-3 w-3" strokeWidth={3} />}
      {result === "warn" && <span className="text-[11px] font-bold leading-none">!</span>}
    </span>
  );
}

function ScanPreview() {
  const reduced = usePrefersReducedMotion();
  const { ref, progress } = useScrollProgress<HTMLDivElement>(reduced);

  // First 75% of the scroll runs the checks, the last 25% counts up the score
  const checkP = clamp01(progress / 0.75);
  const scoreP = clamp01((progress - 0.75) / 0.25);
  const step = Math.min(TOTAL, Math.floor(checkP * TOTAL));
  const complete = step >= TOTAL;
  const score = Math.round(TARGET_SCORE * (1 - Math.pow(1 - scoreP, 3)));

  return (
    <div ref={ref}>
      <div className="overflow-hidden rounded-2xl border border-[#dfe5ec] bg-[#ffffff] shadow-[0_24px_60px_-30px_rgba(21,32,43,0.3)]">
        {/* Header */}
        <div className="relative flex items-center justify-between px-5 py-3.5">
          <span className="truncate font-mono text-xs text-[#5d6b7b]">app.example.com</span>
          <span
            className={`inline-flex items-center gap-2 rounded-full px-2.5 py-1 text-xs font-medium transition-colors duration-200 ${
              complete ? "bg-[#e4f4ec] text-[#3f9e6b]" : "bg-[#fff0e6] text-[#ea7336]"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full bg-current ${complete ? "" : "animate-pulse motion-reduce:animate-none"}`}
            />
            {complete ? "Complete" : "Scanning"}
          </span>
          {/* Progress line: follows scroll directly, no transition */}
          <div className="absolute inset-x-0 bottom-0 h-px bg-[#dfe5ec]">
            <div className="h-full bg-[#ea7336]" style={{ width: `${checkP * 100}%` }} />
          </div>
        </div>

        {/* Checks */}
        <ul className="divide-y divide-[#f0f3f7] px-5">
          {scanChecks.map((check, i) => {
            const state = i < step ? "done" : i === step && !complete ? "running" : "pending";
            return (
              <li
                key={check.name}
                className={`flex items-center gap-3 py-3 transition-opacity duration-200 ${
                  state === "pending" ? "opacity-45" : "opacity-100"
                }`}
              >
                <CheckIcon state={state} result={check.result} />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-[#15202b]">{check.name}</p>
                  <p
                    className={`text-xs text-[#748294] transition-opacity duration-200 ${
                      state === "done" ? "opacity-100" : "opacity-0"
                    }`}
                  >
                    {check.note}
                  </p>
                </div>
                <span className="font-mono text-xs text-[#748294]">{check.ref}</span>
              </li>
            );
          })}
        </ul>

        {/* Result */}
        <div className="grid items-center gap-6 border-t border-[#dfe5ec] bg-[#f7f9fc] px-5 py-5 sm:grid-cols-[auto_1fr]">
          <div className="relative mx-auto h-[84px] w-[84px] sm:mx-0">
            <svg viewBox="0 0 84 84" className="h-full w-full -rotate-90">
              <circle cx="42" cy="42" r={RING_R} fill="none" stroke="#dfe5ec" strokeWidth="6" />
              <circle
                cx="42"
                cy="42"
                r={RING_R}
                fill="none"
                stroke="#ea7336"
                strokeWidth="6"
                strokeLinecap="round"
                strokeDasharray={RING_C}
                strokeDashoffset={RING_C * (1 - score / 100)}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-semibold tabular-nums tracking-tight text-[#15202b]">
                {complete ? score : "–"}
              </span>
              <span
                className={`text-[11px] font-medium text-[#ea7336] transition-opacity duration-200 ${
                  complete && score === TARGET_SCORE ? "opacity-100" : "opacity-0"
                }`}
              >
                Grade B+
              </span>
            </div>
          </div>

          <div className="space-y-2">
            {summary.map((row) => (
              <div key={row.label} className="flex items-center gap-3 text-xs">
                <span className="w-14 text-[#5d6b7b]">{row.label}</span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[#e8edf3]">
                  <div
                    className="h-full rounded-full transition-[width] duration-300 ease-out motion-reduce:transition-none"
                    style={{
                      width: complete ? `${(row.count / TOTAL) * 100}%` : "0%",
                      backgroundColor: row.color,
                    }}
                  />
                </div>
                <span className="w-4 text-right font-mono text-[#15202b]">{complete ? row.count : 0}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      <p className="mt-3 text-center text-xs text-[#748294]">Illustrative example of a scan and its report.</p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

const steps = [
  { title: "Enter a URL", text: "Describe what to test, or just point us at your app." },
  { title: "We verify it", text: "Browser checks and an AI agent test it against ASVS." },
  { title: "Read the report", text: "A grade and findings, each with evidence." },
];

export default function HomePage() {
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
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

  const refreshScans = useCallback(async (showLoading = false) => {
    if (showLoading) setIsRefreshing(true);
    try {
      const scans = await listScans();
      setRecentScans(scans.slice(0, 4));
    } catch {
      if (showLoading) setRecentScans([]);
    } finally {
      setLoading(false);
      if (showLoading) setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const initialRefresh = window.setTimeout(() => void refreshScans(true), 0);
    const refreshInterval = window.setInterval(() => void refreshScans(), 10000);
    return () => {
      window.clearTimeout(initialRefresh);
      window.clearInterval(refreshInterval);
    };
  }, [refreshScans]);

  const handleScanCreated = (scan: Scan) => {
    setRecentScans((current) => [scan, ...current.filter((item) => item.id !== scan.id)].slice(0, 4));
  };

  return (
    <div className="flex min-h-screen flex-col bg-[#f7f9fc] text-[#15202b]">
      {/* Keyframe used by the scan preview status icons */}
      <style>{`@keyframes pop{0%{transform:scale(.5);opacity:0}70%{transform:scale(1.15)}100%{transform:scale(1);opacity:1}}`}</style>

      <Navbar />
      <main className="flex-1">
        {/* Hero: background, pointer glow and composer unchanged */}
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
              <Reveal>
                <h1 className="hero-heading text-4xl font-semibold tracking-[-0.04em] text-[#0f1c28] sm:text-6xl">
                  Know how secure your product really is.
                </h1>
              </Reveal>
              <Reveal delay={120}>
                <p className="hero-copy mx-auto mt-5 max-w-xl text-base leading-7 text-[#5d6b7b] sm:text-lg">
                  Automated security testing against OWASP ASVS, with evidence for every finding.
                </p>
              </Reveal>
            </div>
            <Reveal delay={260} className="mt-12">
              <MissionComposer onScanCreated={handleScanCreated} />
            </Reveal>
          </div>
        </section>

        {/* How it works + live scan preview */}
        <section id="features" className="border-y border-[#dfe5ec] bg-[#ffffff] px-4 py-20 sm:px-8">
          <div className="mx-auto grid max-w-7xl items-center gap-12 lg:grid-cols-[1fr_1.1fr] lg:gap-20">
            <div>
              <Reveal>
                <h2 className="text-3xl font-semibold tracking-[-0.03em] text-[#0f1c28] sm:text-4xl">
                  From URL to report in three steps.
                </h2>
              </Reveal>
              <ol className="mt-10 space-y-7">
                {steps.map((step, i) => (
                  <li key={step.title} className="relative">
                    {i < steps.length - 1 && (
                      <span className="absolute -bottom-7 left-[15px] top-10 w-px bg-[#dfe5ec]" aria-hidden="true" />
                    )}
                    <Reveal delay={150 + i * 130} className="flex gap-4">
                      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-[#dfe5ec] bg-[#f3f6f9] font-mono text-xs text-[#ea7336]">
                        {i + 1}
                      </span>
                      <div>
                        <h3 className="text-base font-semibold text-[#15202b]">{step.title}</h3>
                        <p className="mt-1 text-sm leading-6 text-[#5d6b7b]">{step.text}</p>
                      </div>
                    </Reveal>
                  </li>
                ))}
              </ol>
            </div>
            <Reveal delay={200}>
              <ScanPreview />
            </Reveal>
          </div>
        </section>

        {/* Recent assessments */}
        <section className="mx-auto w-full max-w-7xl px-4 py-20 sm:px-8">
          <Reveal className="mb-5 flex items-end justify-between">
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-2xl font-semibold tracking-tight">Recent assessments</h2>
                <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.14em] text-[#748294]">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#3f9e6b] motion-reduce:animate-none" />
                  Live
                </span>
              </div>
              <p className="mt-1 text-sm text-[#748294]">Your latest security checks, updated automatically.</p>
            </div>
            <Link
              href="/history"
              className="inline-flex items-center gap-1.5 text-sm text-[#5d6b7b] transition-colors hover:text-[#ea7336]"
            >
              {isRefreshing && <RefreshCw className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none" />}
              View all <ArrowUpRight className="h-4 w-4" />
            </Link>
          </Reveal>

          {loading ? (
            <div className="rounded-xl border border-[#dfe5ec] bg-[#ffffff] p-10 text-center text-sm text-[#748294]">
              Loading…
            </div>
          ) : recentScans.length === 0 ? (
            <Reveal>
              <div className="rounded-xl border border-dashed border-[#dfe5ec] bg-[#ffffff] p-10 text-center">
                <Clock3 className="mx-auto h-5 w-5 text-[#748294]" />
                <p className="mt-3 text-sm font-medium text-[#15202b]">No assessments yet</p>
                <p className="mt-1 text-sm text-[#748294]">Start a scan above and it will show up here.</p>
              </div>
            </Reveal>
          ) : (
            <ul className="divide-y divide-[#dfe5ec] overflow-hidden rounded-xl border border-[#dfe5ec] bg-[#ffffff]">
              {recentScans.map((scan, i) => (
                <li key={scan.id}>
                  <Reveal delay={i * 90}>
                    <Link
                      href={`/scan/${scan.id}`}
                      className="group flex items-center gap-4 px-5 py-4 transition-colors duration-200 hover:bg-[#fff0e6]"
                    >
                      <Chip status={(scan.status as ChipStatus) || "queued"} dot />
                      <p className="min-w-0 flex-1 truncate text-sm font-medium text-[#243342] group-hover:text-[#15202b]">
                        {scan.url}
                      </p>
                      <span className="hidden text-xs text-[#748294] sm:block">{formatDate(scan.created_at)}</span>
                      <ArrowUpRight className="h-4 w-4 shrink-0 text-[#748294] transition-all duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-[#ea7336]" />
                    </Link>
                  </Reveal>
                </li>
              ))}
            </ul>
          )}
        </section>
      </main>
      <Footer />
    </div>
  );
}