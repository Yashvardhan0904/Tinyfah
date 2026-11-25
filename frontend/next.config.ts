import type { NextConfig } from "next";

const backendUrl =
  process.env.NEXT_PUBLIC_API_URL ||
  (process.env.NODE_ENV === "production"
    ? "https://tinyfah-backend.onrender.com"
    : "http://localhost:8000");

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`,
      },
      {
        source: "/asvs/:path*",
        destination: `${backendUrl}/asvs/:path*`,
      },
      {
        source: "/screenshots/:path*",
        destination: `${backendUrl}/screenshots/:path*`,
      },
    ];
  },
};

export default nextConfig;
