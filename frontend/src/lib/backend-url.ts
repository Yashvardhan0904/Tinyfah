const LOCAL_BACKEND_URL = "http://localhost:8000";
const PRODUCTION_BACKEND_URL = "https://tracepoint-backend.onrender.com";

function normalize(url: string): string {
  return url.replace(/\/+$/, "");
}

export function getBackendUrl(): string {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return normalize(process.env.NEXT_PUBLIC_API_URL);
  }
  if (typeof window !== "undefined") {
    const { hostname } = window.location;
    if (hostname !== "localhost" && hostname !== "127.0.0.1") {
      return PRODUCTION_BACKEND_URL;
    }
  }
  return process.env.NODE_ENV === "production"
    ? PRODUCTION_BACKEND_URL
    : LOCAL_BACKEND_URL;
}
