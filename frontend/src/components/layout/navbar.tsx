"use client";

import Link from "next/link";
import { useState } from "react";
import { Shield, Menu, X, History } from "lucide-react";
import { ThemeToggle } from "./theme-toggle";

export function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="theme-navbar sticky top-0 z-50 bg-[#ffffff]/90 backdrop-blur-xl border-b border-[#dfe5ec]">
      <div className="max-w-7xl mx-auto px-4 sm:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 shrink-0">
            <div className="flex items-center gap-2 text-[#ea7336]">
              <Shield className="h-5 w-5" />
              <span className="theme-navbar-brand font-mono text-base font-bold tracking-tight text-[#15202b]">
                TINYFAH
              </span>
            </div>
            <span className="theme-navbar-pill hidden sm:inline text-[11px] font-mono text-[#5d6b7b] px-2 py-0.5 rounded bg-[#f3f6f9] border border-[#dfe5ec]">
              OWASP ASVS
            </span>
          </Link>

          {/* Desktop nav */}
          <nav className="hidden md:flex items-center gap-1">
            <Link
              href="/"
              className="px-3 py-1.5 text-sm text-[#5d6b7b] hover:text-[#15202b] hover:bg-[#f3f6f9] rounded-md transition-colors"
            >
              Home
            </Link>
            <Link
              href="/#features"
              className="px-3 py-1.5 text-sm text-[#5d6b7b] hover:text-[#15202b] hover:bg-[#f3f6f9] rounded-md transition-colors"
            >
              Features
            </Link>
            <Link
              href="/history"
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#5d6b7b] hover:text-[#15202b] hover:bg-[#f3f6f9] rounded-md transition-colors"
            >
              <History className="h-3.5 w-3.5" />
              History
            </Link>
          </nav>

          {/* CTA + Mobile toggle */}
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <button
              className="md:hidden p-2 text-[#5d6b7b] hover:text-[#15202b] hover:bg-[#f3f6f9] rounded-md"
              onClick={() => setMobileOpen(!mobileOpen)}
              aria-label="Toggle menu"
            >
              {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileOpen && (
          <div className="md:hidden border-t border-[#dfe5ec] py-3 space-y-1">
            <Link
              href="/"
              className="block px-3 py-2 text-sm text-[#5d6b7b] hover:text-[#15202b] hover:bg-[#f3f6f9] rounded-md"
              onClick={() => setMobileOpen(false)}
            >
              Home
            </Link>
            <Link
              href="/#features"
              className="block px-3 py-2 text-sm text-[#5d6b7b] hover:text-[#15202b] hover:bg-[#f3f6f9] rounded-md"
              onClick={() => setMobileOpen(false)}
            >
              Features
            </Link>
            <Link
              href="/history"
              className="flex items-center gap-1.5 px-3 py-2 text-sm text-[#5d6b7b] hover:text-[#15202b] hover:bg-[#f3f6f9] rounded-md"
              onClick={() => setMobileOpen(false)}
            >
              <History className="h-3.5 w-3.5" />
              History
            </Link>
          </div>
        )}
      </div>
    </header>
  );
}
