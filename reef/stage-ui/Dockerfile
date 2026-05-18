# Reef Stage UI — Next.js 14.2.30 Public Safety Page + 5 OBS-capturable
# demo scenes. Renders the live 49-dot fleet propagation, MCP supply-chain
# block beat, DAST-A shark, Gemini Pro/Flash duo, and the 6-section RIA
# reveal animation.
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
# Build-time NEXT_PUBLIC_* envs get baked into the bundle. The defaults
# here point at the docker-compose service names so the in-cluster fetches
# resolve; the browser still hits localhost:<port> on the host. The browser
# fetches go through Next-generated HTML which is built with these values
# so we override at runtime only via NEXT_PUBLIC_* (see docker-compose).
ARG NEXT_PUBLIC_REEF_ATLAS_URL=http://localhost:8080
ARG NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_URL=http://localhost:50052
ARG NEXT_PUBLIC_REEF_DAST_A_URL=http://localhost:8083
ARG NEXT_PUBLIC_REEF_QUOTE_URL=http://localhost:8082
ARG NEXT_PUBLIC_REEF_VICTIM_URL=http://localhost:3001
ARG NEXT_PUBLIC_REEF_FLEET_ID=prod-fleet

ENV NEXT_PUBLIC_REEF_ATLAS_URL=$NEXT_PUBLIC_REEF_ATLAS_URL \
    NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_URL=$NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_URL \
    NEXT_PUBLIC_REEF_DAST_A_URL=$NEXT_PUBLIC_REEF_DAST_A_URL \
    NEXT_PUBLIC_REEF_QUOTE_URL=$NEXT_PUBLIC_REEF_QUOTE_URL \
    NEXT_PUBLIC_REEF_VICTIM_URL=$NEXT_PUBLIC_REEF_VICTIM_URL \
    NEXT_PUBLIC_REEF_FLEET_ID=$NEXT_PUBLIC_REEF_FLEET_ID \
    NEXT_OUTPUT_STANDALONE=1

RUN pnpm build

FROM node:20-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000

COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static

EXPOSE 3000

CMD ["node", "server.js"]
