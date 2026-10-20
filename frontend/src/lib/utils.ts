import { clsx, type ClassValue } from "clsx";

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function formatElapsed(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
}

export function extractUrls(text: string): string[] {
  if (!text) return [];
  // Match standard URLs with http or https protocol
  const fullUrlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  const matches = text.match(fullUrlRegex) || [];
  if (matches.length > 0) {
    return Array.from(new Set(matches));
  }

  // Also support bare domains like example.com or app.local
  const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:\/[^\s<>"{}|\\^`[\]]*)?/gi;
  const domainMatches = text.match(domainRegex) || [];
  return Array.from(
    new Set(
      domainMatches.map((d) => (d.startsWith("http") ? d : `https://${d}`))
    )
  );
}

export function formatDate(isoString: string): string {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return isoString;
  }
}
