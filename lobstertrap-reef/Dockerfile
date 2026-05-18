# Lobster Trap + Reef — Go fork of Veea Lobster Trap with the 4 missing
# actions (MODIFY/REDIRECT/QUARANTINE/HUMAN_REVIEW), SVID JWT identity,
# Sigstore-style cosign-signed policy bundles, Merkle audit, MCP signature
# registry pre-ingress hook, and the gRPC policy bus client.
#
# Multi-stage build: golang:1.23 for build, distroless static for runtime.
FROM golang:1.23-alpine AS build

WORKDIR /src

# Cache deps separately from sources for faster incremental builds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static, stripped binary so it works on distroless / scratch.
ENV CGO_ENABLED=0 \
    GOOS=linux

RUN go build -trimpath -ldflags="-s -w" -o /out/lobstertrap .

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy the binary + the default policy config the demo ships with.
COPY --from=build /out/lobstertrap /app/lobstertrap
COPY configs /app/configs

USER nonroot:nonroot

# Lobster Trap proxy listens on 8765 by default (vanilla upstream) and
# 9099 for the dashboard. The serve subcommand accepts --enable-reef to
# turn on Reef-owned actions + SVID + Merkle + MCP signature registry.
EXPOSE 8765 9099

ENTRYPOINT ["/app/lobstertrap"]
CMD ["serve", "--enable-reef", "--policy", "/app/configs/default_policy.yaml"]
