/** @type {import('next').NextConfig} */
const nextConfig = {
  // Emit a self-contained server.js + node_modules under .next/standalone
  // so the Docker image can run `node server.js` without the full project
  // tree. See https://nextjs.org/docs/pages/api-reference/next-config-js/output
  output: "standalone",
};

export default nextConfig;
