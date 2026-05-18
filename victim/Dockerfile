# Reef victim Copilot-clone — Next.js 14.2.30 inbox + Gemini summarizer that
# reproduces the EchoLeak attack as the demo target.
#
# Multi-stage build using Next.js standalone output (next.config.mjs sets
# output: "standalone"). Pinned exactly to Next 14.2.30 per D-016.
FROM node:20-alpine AS deps

WORKDIR /app

RUN apk add --no-cache libc6-compat && \
    corepack enable && \
    corepack prepare pnpm@10.33.0 --activate

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

FROM node:20-alpine AS build

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm build

FROM node:20-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3001

# Pull the standalone tree + the static assets. There is no /public dir in
# this app — Next handles that gracefully.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static

EXPOSE 3001

CMD ["node", "server.js"]
