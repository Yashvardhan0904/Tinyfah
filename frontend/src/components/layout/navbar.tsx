"use client";

import Link from "next/link";
import { useState } from "react";
import { Menu, X, History } from "lucide-react";
import { ThemeToggle } from "./theme-toggle";

/* Logo mark: a rounded tile with a "T" built purely from CSS shapes */
function LogoMark() {
  return (
    <span
      aria-hidden="true"
      className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-[#ea7336] shadow-[inset_0_1px_0_rgba(255,255,255,0.35),0_1px_2px_rgba(234,115,54,0.35)] transition-transform duration-200 group-hover:-rotate-3"
    >
      {/* T top bar */}
      <span className="absolute left-[7px] top-[8px] h-[4px] w-[18px] rounded-full bg-white" />
      {/* T stem */}
      <span className="absolute left-[14px] top-[8px] h-[16px] w-[4px] rounded-full bg-white" />
      {/* small "pixel" accent for the "tiny" idea */}
      <span className="absolute bottom-[8px] right-[7px] h-[4px] w-[4px] rounded-[1px] bg-white/70" />
    </span>
  );
}

const linkBase =
  "rounded-lg text-sm font-medium text-[#5d6b7b] transition-colors hover:text-[#15202b] hover:bg-[#f3f6f9] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#ea7336]/50";

export function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="theme-navbar sticky top-0 z-50 border-b border-[#dfe5ec] bg-[#ffffff]/80 backdrop-blur-xl">
      <div className="mx-auto max-w-7xl px-4 sm:px-8">
        <div className="flex h-16 items-center justify-between md:grid md:grid-cols-[1fr_auto_1fr]">
          {/* Left: logo */}
          <Link
            href="/"
            aria-label="TinyFah home"
            className="group flex shrink-0 items-center gap-2.5 justify-self-start rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#ea7336]/50"
          >
            <LogoMark />
            <span className="theme-navbar-brand text-[19px] leading-none tracking-[-0.04em] text-[#15202b]">
              <span className="font-medium">tiny</span>
              <span className="font-extrabold">fah</span>
            </span>
          </Link>

          {/* Center: desktop nav */}
          <nav className="hidden items-center justify-center gap-1 md:flex">
            <Link href="/" className={`${linkBase} px-3.5 py-1.5`}>
              Home
            </Link>
            <Link href="/#features" className={`${linkBase} px-3.5 py-1.5`}>
              Features
            </Link>
            <Link
              href="/history"
              className={`${linkBase} flex items-center gap-1.5 px-3.5 py-1.5`}
            >
              <History className="h-3.5 w-3.5" />
              History
            </Link>
          </nav>

          {/* Right: theme toggle + mobile toggle */}
          <div className="flex items-center gap-2 justify-self-end">
            <ThemeToggle />
            <button
              className={`${linkBase} p-2 md:hidden`}
              onClick={() => setMobileOpen(!mobileOpen)}
              aria-label="Toggle menu"
              aria-expanded={mobileOpen}
            >
              {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileOpen && (
          <div className="space-y-1 border-t border-[#dfe5ec] py-3 md:hidden">
            <Link
              href="/"
              className={`${linkBase} block px-3 py-2.5`}
              onClick={() => setMobileOpen(false)}
            >
              Home
            </Link>
            <Link
              href="/#features"
              className={`${linkBase} block px-3 py-2.5`}
              onClick={() => setMobileOpen(false)}
            >
              Features
            </Link>
            <Link
              href="/history"
              className={`${linkBase} flex items-center gap-1.5 px-3 py-2.5`}
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