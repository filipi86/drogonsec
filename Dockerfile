# DragonSec Security Scanner - Dockerfile
# Multi-stage build for minimal final image

# ============ BUILD STAGE ============
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates make

WORKDIR /build

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -ldflags="-w -s -extldflags '-static'" \
    -o /build/drogonsec \
    ./cmd/drogonsec/main.go

# ============ FINAL STAGE ============
FROM alpine:3.19

# Security: don't run as root
RUN addgroup -g 1001 drogonsec && \
    adduser -D -u 1001 -G drogonsec drogonsec

# Install CA certificates for HTTPS calls (OSV API, AI endpoint)
RUN apk add --no-cache ca-certificates git

# Copy binary from builder
COPY --from=builder /build/drogonsec /usr/local/bin/drogonsec

# Set working directory for scan target
WORKDIR /scan

# Run as non-root user
USER drogonsec

# Default: scan the mounted directory
ENTRYPOINT ["drogonsec"]
CMD ["scan", "."]

# Usage:
#   docker run --rm -v $(pwd):/scan drogonsec-scanner:latest
#   docker run --rm -v $(pwd):/scan drogonsec-scanner:latest scan . --format json
#   docker run --rm -v $(pwd):/scan -e AI_API_KEY=... drogonsec-scanner:latest scan . --enable-ai
