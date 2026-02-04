# =============================================================================
# VAPORDROP - DOCKERFILE HARDENED
# Multi-stage build per minimizzare attack surface
# =============================================================================

# -----------------------------------------------------------------------------
# STAGE 1: Build
# -----------------------------------------------------------------------------
FROM golang:1.22-alpine AS builder

# Build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache dipendenze
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

# Copia sorgenti
COPY main.go .

# Init module se non esiste
RUN [ -f go.mod ] || go mod init vapordrop

# Scarica dipendenze
RUN go mod tidy

# Compilazione statica senza CGO
# -ldflags: strip symbols, disable DWARF
# -trimpath: rimuove path locali dal binario
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -o vapordrop \
    main.go

# Verifica binario
RUN ./vapordrop --help 2>&1 || true

# -----------------------------------------------------------------------------
# STAGE 2: Runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

# Labels
LABEL maintainer="VaporDrop"
LABEL description="Ephemeral messaging over Tor"
LABEL security.privileged="false"

# Variabili ambiente per Tor
ENV TOR_SKIP_LAUNCH=1
ENV HOME=/app

# Installa solo il necessario
RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/*

# Crea utente non-root
RUN groupadd -g 1000 vapor && useradd -r -s /bin/false -d /app -u 1000 -g 1000 vapor

# Directory applicazione
WORKDIR /app

# Copia binario
COPY --from=builder /build/vapordrop /app/vapordrop

# Copia static files (se presenti)
COPY static/ /app/static/

# Permessi
RUN chown -R vapor:vapor /app && \
    chmod 500 /app/vapordrop && \
    chmod 400 /app/static/* 2>/dev/null || true

# Directory temporanea per Tor (in RAM via tmpfs in docker-compose)
RUN mkdir -p /tmp/tor && chown vapor:vapor /tmp/tor

# Switch a utente non privilegiato
USER vapor

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD test -f /tmp/tor/.tor_is_ready || exit 1

# Espone porta Tor (non necessario per hidden service, ma utile per debug)
EXPOSE 9050

# Entry point
ENTRYPOINT ["/app/vapordrop"]

