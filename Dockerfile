# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.26-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build
WORKDIR /src

# Copy the whole module; `go mod download` runs inside the build and is
# cached by Docker layer caching.
COPY . .

# Pure-Go SQLite (modernc.org/sqlite) means no C toolchain is required.
RUN CGO_ENABLED=0 go build -trimpath -o /out/anpu ./cmd/anpu

# --- runtime stage ---
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
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
