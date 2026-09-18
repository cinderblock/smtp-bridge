# syntax=docker/dockerfile:1

# smtp-bridge — SMTP submission → HTTP webhook bridge. Built by CI and
# published to GHCR; which image runs on firefly is pinned in the ops repo at
# servers/firefly/stacks/smtp-bridge/pin.json.

# --- Build: static binary ---------------------------------------------------
FROM golang:1.26-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO off so the result runs on a distroless base with no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/smtp-bridge ./cmd/smtp-bridge

# --- Runtime ----------------------------------------------------------------
# The app obtains its own TLS certificates via ACME DNS-01 (Cloudflare), so it
# needs a CA bundle and correct time — but no shell, no package manager and no
# Go toolchain. A static binary on distroless is the whole runtime.
#
# The root variant, not :nonroot: the persistent data volume carries over from
# the previous deployment with its existing ownership, and this process binds
# :25 inside the container. Nothing else is in here with it.
FROM gcr.io/distroless/static-debian12 AS runtime

COPY --from=build /out/smtp-bridge /usr/local/bin/smtp-bridge

# The ops-managed config is bind-mounted read-only at /etc/smtp-bridge; the
# SQLite DB and the ACME cert cache live on the app volume under
# /srv/smtp-bridge/data.
#
# Ports, for documentation and so a mismatch with ops' compose is visible:
#   25   STARTTLS (optional)     465  implicit TLS (SMTPS)
#   587  STARTTLS (submission)   2525 STARTTLS      5465 implicit TLS
#   8025 read-only status UI (no auth — loopback publish only)
EXPOSE 25 465 587 2525 5465 8025

ENTRYPOINT ["/usr/local/bin/smtp-bridge", "-config", "/etc/smtp-bridge/config.yaml"]
