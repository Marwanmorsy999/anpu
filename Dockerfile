# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.22-bookworm AS build
WORKDIR /src

# Copy the whole module (including vendored third_party/) — ANPU builds
# fully offline, so no separate `go mod download` layer is needed.
COPY . .

RUN CGO_ENABLED=1 go build -trimpath -o /out/anpu ./cmd/anpu

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
