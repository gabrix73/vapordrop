# VaporDrop - Multi-stage Docker Build
# Stack: Go + Tor + X25519 + XChaCha20 + BLAKE3

# =============================================================================
# STAGE 1: Build
# =============================================================================
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy source files
COPY go.mod ./
COPY main.go ./

# Download dependencies and build with security flags
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -trimpath \
    -ldflags="-w -s -buildid=" \
    -buildvcs=false \
    -o vapordrop \
    main.go

# =============================================================================
# STAGE 2: Runtime
# =============================================================================
FROM alpine:3.19

# Install Tor and minimal deps
RUN apk add --no-cache \
    tor \
    ca-certificates \
    tzdata \
    && rm -rf /var/cache/apk/* \
    && mkdir -p /app/static /app/file_storage /app/.tor

# Create non-root user
RUN addgroup -g 1000 vapor && \
    adduser -u 1000 -G vapor -h /app -D vapor

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/vapordrop /app/vapordrop

# Copy static files
COPY static/ /app/static/

# Set ownership
RUN chown -R vapor:vapor /app

# Switch to non-root
USER vapor

EXPOSE 80

ENTRYPOINT ["/app/vapordrop"]
