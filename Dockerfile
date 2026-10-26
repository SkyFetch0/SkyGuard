# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.24-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
# Pure-Go SQLite driver: no cgo, fully static binary.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o /out/skyguard ./cmd/skyguard

# ── Runtime stage ──────────────────────────────────────────────────────────────
# Debian ships both iptables-legacy and iptables-nft. SkyGuard picks whichever
# backend the host already uses (analysis.auto_ban.iptables_backend: auto);
# rules written with the wrong one are invisible to the host's tooling.
# ufw is intentionally not installed: inside a container it would only edit
# the container's own copy of the rules, never the host's.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates iptables tzdata \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/skyguard /usr/local/bin/skyguard
RUN mkdir -p /data /etc/skyguard

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/skyguard", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/skyguard"]
CMD ["-config", "/etc/skyguard/skyguard.yaml"]
