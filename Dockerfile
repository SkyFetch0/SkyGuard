# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux \
    go build -a -installsuffix cgo \
    -ldflags="-w -s" \
    -o skyguard ./cmd/skyguard

# ── Final stage ─────────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates iptables ip6tables ufw tzdata

WORKDIR /app

COPY --from=builder /build/skyguard .

RUN mkdir -p /data /etc/skyguard

VOLUME ["/data"]

EXPOSE 22 21 3306 80 8080 9911 9090

ENTRYPOINT ["/app/skyguard"]
CMD ["-config", "/etc/skyguard/skyguard.yaml"]