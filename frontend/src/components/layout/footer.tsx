import Link from "next/link";
import { Shield } from "lucide-react";

export function Footer() {
  return (
    <footer className="bg-[#ffffff] border-t border-[#dfe5ec]">
      <div className="max-w-7xl mx-auto px-4 sm:px-8 py-10">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-8">
          {/* Brand */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-[#18a66b]">
              <Shield className="h-4 w-4" />
              <span className="font-mono text-sm font-bold text-[#15202b]">TINYFAH</span>
            </div>
            <p className="text-xs text-[#5d6b7b] leading-relaxed max-w-xs">
              Autonomous web security verification platform powered by deterministic testing and multi-agent AI.
            </p>
          </div>

          {/* Quick links */}
          <div className="space-y-2">
            <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-[#748294]">
              Navigation
            </h4>
            <ul className="space-y-1.5 text-sm">
              <li>
                <Link href="/" className="text-[#5d6b7b] hover:text-[#18a66b] transition-colors">
                  Home
                </Link>
              </li>
              <li>
                <Link href="/#features" className="text-[#5d6b7b] hover:text-[#18a66b] transition-colors">
                  Features
                </Link>
              </li>
              <li>
                <Link href="/history" className="text-[#5d6b7b] hover:text-[#18a66b] transition-colors">
                  Scan History
                </Link>
              </li>
            </ul>
          </div>

          {/* Standards */}
          <div className="space-y-2">
            <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-[#748294]">
              Standards
            </h4>
            <ul className="space-y-1.5 text-xs font-mono text-[#5d6b7b]">
              <li>OWASP ASVS v5.0.0</li>
              <li>17 Security Chapters</li>
              <li>345 Requirements</li>
              <li>LangGraph Multi-Agent</li>
            </ul>
          </div>
        </div>

        <div className="mt-8 pt-4 border-t border-[#dfe5ec] text-xs text-center text-[#748294] font-mono">
          Tinyfah Autonomous Security Platform • OWASP ASVS v5.0.0
        </div>
      </div>
    </footer>
  );
}
