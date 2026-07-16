# smtp-bridge

A small, self-hostable **SMTP → HTTP bridge**. It is an SMTP endpoint that
authenticated senders can submit mail to; each message is converted into an HTTP
webhook `POST` to a configured web app. It does **not** relay mail onward — it is
an escape hatch *out* of SMTP into HTTP.

Ships as a single static binary (pure Go, no cgo) you can run on your own
hardware. Optional (opt-out) message logging to a local SQLite database.

## Why not Cloudflare Workers?

Workers (and edge runtimes generally) can't do the core job: their TCP socket API
is **outbound-only**, so nothing on the edge can bind port 25/2525 and accept an
inbound SMTP conversation from arbitrary senders. Cloudflare Email Routing +
Email Workers is the adjacent managed feature, but it only works for domains on
Cloudflare's MX and isn't something anyone can run on their own hardware. So the
bridge is a normal long-running daemon. (Cloudflare D1 remains a possible
*optional* remote log sink in the future.)

## How it works

```
sender ──SMTP (AUTH + optional STARTTLS)──▶ smtp-bridge
                                              │  parse envelope + MIME
                                              │  match recipient ▶ route
                        ┌─────────────────────┼─────────────────────┐
                     sync route            async route         no route
                   POST inline;         enqueue ▶ durable      reject at
                  250 only on 2xx       retry worker           RCPT (550)
                                              │
                                        HTTP POST JSON + HMAC signature
```

- **AUTH is mandatory** — the server never acts as an open relay. PLAIN and LOGIN
  SASL mechanisms are supported. **Credentials are per-route:** each route carries
  its own username + password (plaintext or bcrypt); a sender authenticates *as* a
  route and may only deliver to routes that credential owns. Generate a hash with
  `smtp-bridge hash '<password>'`.
- **Capture-only routes** — a route with no webhook accepts and stores matching
  mail (view it with `smtp-bridge messages`) without forwarding, so you can point a
  sender at it before you have an endpoint, then add the webhook later.
- **Multiple listeners**, each with its own TLS mode — `none` (plaintext),
  `starttls` (explicit upgrade, ports 587/25/2525), or `implicit` (TLS from the
  first byte, a.k.a. SMTPS, port 465). All share one auth/routing backend.
- **TLS certificate** from one of three sources (`tls.mode`): `none`, static
  `files`, or `auto` — automatic ACME **DNS-01** issuance + renewal via Cloudflare
  (built on certmagic), which needs no inbound HTTP port.
- **Routing** matches each recipient by exact address, domain, or local-part
  (ignoring any `+tag` subaddress), scoped to the authenticated user's routes.
  A recipient with no matching route for that user is rejected at `RCPT`.
- **Two delivery modes, selectable per route:**
  - `sync` — POST inline; the SMTP transaction only returns `250 OK` if the
    webhook responds `2xx`, giving the sender real backpressure.
  - `async` — accept immediately, persist to a durable SQLite-backed queue, and
    deliver in the background with exponential-backoff retries.
- **Signed payloads** — when a route sets a `secret`, each request carries
  `X-SMTP-Bridge-Signature: sha256=<hmac>` over the raw body so the receiver can
  verify authenticity.

## Quick start

```sh
go build -o smtp-bridge ./cmd/smtp-bridge
cp config.example.yaml config.yaml
# edit config.yaml: set a user password and your webhook URL
./smtp-bridge -config config.yaml
```

Send a test message (with [swaks](https://github.com/jetmore/swaks)):

```sh
swaks --server localhost:2525 --auth PLAIN --auth-user alice --auth-password change-me \
      --from you@example.com --to myapp@hooks.example.com \
      --header "Subject: hello" --body "it works"
```

## Debugging rejected requests

Every request the server refuses is **logged to stderr** at `WARN` with full
context and **persisted** (envelope metadata only — no bodies) so you can see at
a glance when a sender is misconfigured. Rejections are captured at each stage:

| stage     | example reason                          |
|-----------|-----------------------------------------|
| `connect` | source IP not in `auth.allow_ips`       |
| `auth`    | bad username/password                   |
| `mail`    | `MAIL FROM` issued before `AUTH`        |
| `rcpt`    | recipient matched no route (SMTP 550)   |
| `data`    | sync webhook returned non-2xx / enqueue failed |

Dump the most recent ones (oldest-first, so a tail reads naturally):

```sh
smtp-bridge rejections -config config.yaml        # last 50
smtp-bridge rejections -config config.yaml -n 200 # last 200
```

```
2026-07-14T14:43:28-07:00  port=587 stage=rcpt  code=550  ip=203.0.113.9:51002 user="alice" from="a@x.com" rcpt="typo@wrong.example" reason="no route configured for recipient"
```

Reading works while the server is running (WAL allows concurrent readers).
Disable DB persistence with `logging.log_rejections: false` (stderr logs remain),
and set `logging.rejection_retention_days` to auto-purge rejections older than N
days (0 = keep forever). The status web UI can also select and bulk-delete
rejections (and messages).

## Status web UI (optional)

Set `web.listen` to run a small **unauthenticated** web view of stored messages
and rejections — handy for eyeballing captured mail without the CLI:

```yaml
web:
  listen: "127.0.0.1:8025"
```

It lets you view messages and select/bulk-delete captured ones (it never edits
config) and shows message bodies as escaped source (never executes untrusted
HTML). Because it has **no auth**, bind it to loopback only. In a container, bind `:8025` inside and publish
it to the host loopback (`127.0.0.1:8025:8025`), then reach it via an SSH tunnel:

```sh
ssh -L 8025:localhost:8025 your-host    # then open http://localhost:8025
```

## Webhook payload

`POST` with `Content-Type: application/json`:

```json
{
  "message_id": "…",
  "received_at": "2026-07-14T12:00:00Z",
  "route": "myapp",
  "from": "you@example.com",
  "rcpt": ["myapp@hooks.example.com"],
  "subject": "hello",
  "headers": { "Subject": "hello", "From": "you@example.com" },
  "text": "it works",
  "html": "",
  "attachments": [
    { "filename": "a.pdf", "content_type": "application/pdf", "size": 1234, "content_b64": "…" }
  ],
  "raw_eml_b64": "…"
}
```

Extra headers on every request: `X-SMTP-Bridge-Route`, and `X-SMTP-Bridge-Signature`
when signing is enabled. `text`/`html`/`attachments`/`raw_eml_b64` are included
per the route's `include` rules.

### Verifying the signature (example, Node)

```js
import { createHmac, timingSafeEqual } from "node:crypto";
function verify(rawBody, header, secret) {
  const expected = "sha256=" + createHmac("sha256", secret).update(rawBody).digest("hex");
  const a = Buffer.from(header || ""), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
```

## Configuration

See [`config.example.yaml`](config.example.yaml) for the full annotated schema:
listener, TLS, users, IP allowlist, logging, delivery defaults, and routes.

## Build / distribute

Pure Go with no cgo, so cross-compilation is trivial:

```sh
GOOS=linux   GOARCH=amd64 go build -o dist/smtp-bridge-linux-amd64   ./cmd/smtp-bridge
GOOS=linux   GOARCH=arm64 go build -o dist/smtp-bridge-linux-arm64   ./cmd/smtp-bridge
GOOS=darwin  GOARCH=arm64 go build -o dist/smtp-bridge-darwin-arm64  ./cmd/smtp-bridge
GOOS=windows GOARCH=amd64 go build -o dist/smtp-bridge-windows-amd64.exe ./cmd/smtp-bridge
```

## Status / roadmap

Working: mandatory AUTH, multi-listener (none/starttls/implicit), TLS via static
files or automatic ACME DNS-01 (Cloudflare), routing, sync + async delivery,
retries, HMAC signing, SQLite logging + durable queue, rejected-request logging +
`rejections` viewer. Planned: Dockerfile / goreleaser, systemd unit, optional D1
remote log sink, metrics.
