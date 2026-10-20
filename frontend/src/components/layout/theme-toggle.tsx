"use client";

import { Moon, Sun } from "lucide-react";
import { useEffect, useSyncExternalStore } from "react";

type Theme = "light" | "dark";

export function ThemeToggle() {
  const theme = useSyncExternalStore(
    (onStoreChange) => {
      window.addEventListener("storage", onStoreChange);
      window.addEventListener("tinyfah-theme-change", onStoreChange);
      return () => {
        window.removeEventListener("storage", onStoreChange);
        window.removeEventListener("tinyfah-theme-change", onStoreChange);
      };
    },
    () => (window.localStorage.getItem("tinyfah-theme") === "dark" ? "dark" : "light"),
    () => "light"
  );

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const toggleTheme = () => {
    const nextTheme: Theme = theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = nextTheme;
    window.localStorage.setItem("tinyfah-theme", nextTheme);
    window.dispatchEvent(new Event("tinyfah-theme-change"));
  };

  const isDark = theme === "dark";

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={`Switch to ${isDark ? "light" : "dark"} theme`}
      title={`Switch to ${isDark ? "light" : "dark"} theme`}
      className="relative flex h-9 w-16 items-center rounded-full border border-[#dfe5ec] bg-[#f3f6f9] p-1 text-[#5d6b7b] shadow-sm transition-colors hover:border-[#b8c5d1] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#18a66b]/40"
    >
      <span
        className={`absolute flex h-7 w-7 items-center justify-center rounded-full bg-white shadow-[0_2px_6px_rgba(21,32,43,0.16)] transition-transform duration-300 ease-out ${
          isDark ? "translate-x-7" : "translate-x-0"
        }`}
      >
        {isDark ? <Moon className="h-3.5 w-3.5 text-[#6d4aca]" /> : <Sun className="h-3.5 w-3.5 text-[#b7791f]" />}
      </span>
      <span className="flex w-full items-center justify-between px-1">
        <Sun className={`h-3.5 w-3.5 transition-opacity ${isDark ? "opacity-40" : "opacity-0"}`} />
        <Moon className={`h-3.5 w-3.5 transition-opacity ${isDark ? "opacity-0" : "opacity-40"}`} />
      </span>
    </button>
  );
}
