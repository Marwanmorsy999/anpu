# syntax=docker/dockerfile:1

# --- build stage: the anpu binary (pure Go, no C toolchain) ---
# Go 1.27.3+ is required: earlier stdlib releases carry the net/http,
# net/http/internal/http2, crypto/tls and mime/multipart advisories that
# govulncheck reports as affecting reachable code (CI gate), and Go 1.27.2
# still carries crypto/x509 GO-2026-6809.
# Base image pinned by digest for supply-chain integrity.
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /src

# Copy the whole module; `go mod download` runs inside the build and is
# cached by Docker layer caching.
COPY . .

# Pure-Go SQLite (modernc.org/sqlite) means no C toolchain is required.
RUN CGO_ENABLED=0 go build -trimpath -o /out/anpu ./cmd/anpu

# --- nuclei stage: only built for the anpu:nuclei target ---
# `go install` compiles the real nuclei binary so standard/deep profiles get
# full template coverage in-container. Skipped entirely for the default
# anpu target (it is not in that target's dependency graph).
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS nuclei
RUN CGO_ENABLED=0 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# --- shared runtime base ---
# Base image pinned by digest for supply-chain integrity.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 anpu
USER anpu
WORKDIR /home/anpu

COPY --from=build /out/anpu /usr/local/bin/anpu

ENTRYPOINT ["anpu"]
CMD ["--help"]

# --- optional target: anpu:nuclei ---
# Build with: docker build --target anpu-nuclei -t anpu:nuclei .
# Adds the real nuclei binary so advanced/ultra (standard/deep) profiles run
# their full template set instead of the embedded fallback.
FROM runtime AS anpu-nuclei
USER root
COPY --from=nuclei /go/bin/nuclei /usr/local/bin/nuclei
USER anpu

# --- default target: anpu (no nuclei) ---
# This is the last stage, so `docker build -t anpu .` produces the small
# nuclei-free image. ANPU works fully without nuclei; the embedded fallback
# covers the Nuclei stage with a warning.
FROM runtime AS anpu
