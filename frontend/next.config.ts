import type { NextConfig } from "next";

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
    const backendUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
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
