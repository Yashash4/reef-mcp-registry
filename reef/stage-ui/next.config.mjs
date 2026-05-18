/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Emit a self-contained server.js + node_modules under .next/standalone
  // so the Docker image can run `node server.js` without the full project
  // tree.
  output: "standalone",
  // The Stage UI talks to several local services (Atlas :8080, Policy Bus
  // admin :50052, DAST-A :8083, Quote :8082, victim :3001). All of those
  // endpoints set permissive CORS headers; the Stage UI uses them via
  // browser fetch directly without a Next rewrite proxy, so config stays
  // minimal here.
};

export default nextConfig;
