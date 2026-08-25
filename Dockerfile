# syntax=docker/dockerfile:1

# Keep in sync with go.mod. CI workflows derive their toolchain from
# `go-version-file: go.mod`, so bump both together to avoid drift.
ARG GO_VERSION=1.25

# --- build stage ---
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

# Copy the module manifests first and download dependencies so Docker
# layer caching skips the (slow) dependency fetch when only source
# files change.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the module.
COPY . .

# Pure-Go SQLite (modernc.org/sqlite) means no C toolchain is required.
RUN CGO_ENABLED=0 go build -trimpath -o /out/anpu ./cmd/anpu

# --- runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Optional: install nuclei if you want the Nuclei integration available
# inside the container. Left out by default to keep the image small and
# because ANPU works fully without it (see internal/integrations/nuclei.go).

RUN useradd -m -u 10001 anpu
USER anpu
WORKDIR /home/anpu

COPY --from=build /out/anpu /usr/local/bin/anpu

ENTRYPOINT ["anpu"]
CMD ["--help"]
