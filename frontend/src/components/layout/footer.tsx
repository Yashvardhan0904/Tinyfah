import Link from "next/link";
import { GitFork, Mail, Phone, ArrowUpRight } from "lucide-react";
import { LogoMark } from "@/components/ui/logo-mark";

export function Footer() {
  return (
    <footer className="border-t border-[#dfe5ec] bg-[#ffffff]">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-8">
        <div className="grid grid-cols-1 gap-10 sm:grid-cols-2 lg:grid-cols-[1.4fr_0.8fr_0.8fr_1.2fr]">
          {/* Brand */}
          <div className="space-y-4">
            <Link
              href="/"
              aria-label="Tinyfah home"
              className="group inline-flex items-center gap-2.5 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#ea7336]/50"
            >
              <LogoMark />
              <span className="text-[19px] leading-none tracking-[-0.04em] text-[#15202b]">
                <span className="font-medium">tiny</span>
                <span className="font-extrabold">fah</span>
              </span>
            </Link>
            <p className="max-w-xs text-sm leading-6 text-[#5d6b7b]">
              Autonomous web security verification for teams that want clear answers, useful evidence, and fewer blind spots.
            </p>
            <span className="inline-flex items-center rounded-full border border-[#dfe5ec] bg-[#f3f6f9] px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-[#748294]">
              Built for safer releases
            </span>
          </div>

          {/* Quick links */}
          <div className="space-y-3">
            <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-[#748294]">
              Navigation
            </h4>
            <ul className="space-y-2 text-sm">
              <li>
                <Link href="/" className="text-[#5d6b7b] transition-colors hover:text-[#ea7336]">
                  Home
                </Link>
              </li>
              <li>
                <Link href="/#features" className="text-[#5d6b7b] transition-colors hover:text-[#ea7336]">
                  Features
                </Link>
              </li>
              <li>
                <Link href="/history" className="text-[#5d6b7b] transition-colors hover:text-[#ea7336]">
                  Scan History
                </Link>
              </li>
              <li>
                <a href="https://github.com/Yashvardhan0904/Tinyfah" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[#5d6b7b] transition-colors hover:text-[#ea7336]">
                  Contribute on GitHub <ArrowUpRight className="h-3.5 w-3.5" />
                </a>
              </li>
            </ul>
          </div>

          {/* Standards */}
          <div className="space-y-3">
            <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-[#748294]">
              Standards
            </h4>
            <ul className="space-y-2 font-mono text-xs text-[#5d6b7b]">
              <li>OWASP ASVS v5.0.0</li>
              <li>17 Security Chapters</li>
              <li>345 Requirements</li>
              <li>LangGraph Multi-Agent</li>
            </ul>
          </div>

          {/* Contact */}
          <div className="space-y-3">
            <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-[#748294]">
              Contact us
            </h4>
            <p className="text-sm leading-6 text-[#5d6b7b]">
              Questions, feedback, or ideas for the next release? Reach out directly.
            </p>
            <div className="space-y-2 text-sm">
              <a href="mailto:yashvardhansingh0904@gmail.com" className="flex items-center gap-2 text-[#5d6b7b] transition-colors hover:text-[#ea7336]">
                <Mail className="h-4 w-4 text-[#ea7336]" />
                yashvardhansingh0904@gmail.com
              </a>
              <a href="tel:+918076723395" className="flex items-center gap-2 text-[#5d6b7b] transition-colors hover:text-[#ea7336]">
                <Phone className="h-4 w-4 text-[#ea7336]" />
                +91 80767 23395
              </a>
              <a href="https://github.com/Yashvardhan0904/Tinyfah/issues" target="_blank" rel="noreferrer" className="flex items-center gap-2 text-[#5d6b7b] transition-colors hover:text-[#ea7336]">
                <GitFork className="h-4 w-4 text-[#ea7336]" />
                Report an issue
              </a>
            </div>
          </div>
        </div>

        <div className="mt-10 flex flex-col gap-2 border-t border-[#dfe5ec] pt-5 text-xs text-[#748294] sm:flex-row sm:items-center sm:justify-between">
          <span className="font-mono">Tinyfah Autonomous Security Platform</span>
          <span>© Tinyfah. Built for safer releases.</span>
        </div>
      </div>
    </footer>
  );
}
