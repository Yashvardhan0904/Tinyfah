import { ArrowRight, ShieldCheck } from "lucide-react";

export function HeroSection() {
  return (
    <section className="relative py-20 sm:py-28 px-4 text-center overflow-hidden">
      {/* Subtle background pattern */}
      <div
        className="absolute inset-0 -z-10 pointer-events-none"
        style={{
          backgroundImage:
            "radial-gradient(ellipse 80% 50% at 50% -20%, rgba(16,185,129,0.08) 0%, transparent 70%)",
        }}
      />

      {/* Badge */}
      <div className="inline-flex items-center gap-1.5 px-3 py-1 mb-6 rounded-full bg-emerald-50 border border-emerald-200 text-xs font-mono text-emerald-700">
        <ShieldCheck className="h-3.5 w-3.5" />
        OWASP ASVS v5.0.0 · 17 Chapters · 345 Requirements
      </div>

      {/* Headline */}
      <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight text-gray-900 leading-tight max-w-4xl mx-auto">
        Autonomous{" "}
        <span className="text-emerald-500">Web Security</span>{" "}
        Verification
      </h1>

      {/* Subtitle */}
      <p className="mt-5 text-base sm:text-lg text-gray-500 max-w-2xl mx-auto leading-relaxed">
        Deterministic browser canary tests and multi-agent AI verification against all 17 OWASP ASVS chapters.
        Get actionable security grades with full remediation guidance.
      </p>

      {/* CTAs */}
      <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-3">
        <a
          href="#composer"
          className="inline-flex items-center gap-2 px-6 py-3 text-sm font-semibold text-white bg-emerald-500 hover:bg-emerald-600 rounded-lg shadow-sm transition-colors"
        >
          Start Free Assessment
          <ArrowRight className="h-4 w-4" />
        </a>
        <a
          href="#features"
          className="inline-flex items-center gap-2 px-6 py-3 text-sm font-medium text-gray-600 bg-white border border-gray-200 hover:bg-gray-50 rounded-lg shadow-sm transition-colors"
        >
          See How It Works
        </a>
      </div>
    </section>
  );
}
