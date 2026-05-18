/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The Stage UI talks to several local services (Atlas :8080, Policy Bus
  // admin :50052, DAST-A :8083, Quote :8082, victim :3001). All of those
  // endpoints set permissive CORS headers; the Stage UI uses them via
  // browser fetch directly without a Next rewrite proxy, so config stays
  // minimal here.
};

export default nextConfig;
