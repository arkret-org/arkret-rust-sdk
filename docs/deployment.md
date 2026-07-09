# Deployment

This guide covers running a Arkret service implemented with the SDK in a
production environment. The SDK ships protocol request/response types and the
Salvo OAPI-ready DTO types; host applications own HTTP routing.

## Build matrix

| Feature flag      | What it pulls in                                                  |
| ----------------- | ----------------------------------------------------------------- |
| (default)         | Client + MLS + full sync/timeline/applet runtimes                 |
| `client` (subset) | HTTP client only — no server, no MLS                              |
| `server`          | Protocol request/response enums                                   |
| `salvo`           | Activates `server` plus Salvo OAPI derives on DTO types           |

For a server binary, enable `server`. Enable `salvo` only if the host
application uses Salvo OAPI derives for its own handlers.

## Minimal HTTP binding

The host framework should parse an inbound request into the appropriate
`ServerRequest`, call an `EndpointHandler`, and serialize the returned
`ServerResponse`. Authentication, idempotency, CORS and rate limiting live in
the host service stack.

## TLS termination

The Arkret client (`crates/http-client/src/lib.rs::ClientBuilder`) rejects
non-HTTPS base URLs unless the caller opts into
`allow_insecure_localhost()`. So every production server must terminate TLS
somewhere. Two patterns are common:

- **Reverse proxy** (recommended). Terminate TLS in nginx, Caddy, Traefik
  or a cloud load balancer and forward plain HTTP to the Arkret binary
  bound on `127.0.0.1`. The proxy handles cert rotation, OCSP stapling,
  HTTP/2 negotiation, request body limits and access logging.
- **Runtime-native TLS**. Use the TLS support from the chosen HTTP runtime.
  Acceptable for small deployments; production should still front it with a
  CDN or LB for DDoS / WAF capabilities.

The SDK never embeds TLS configuration in published types — TLS is an
operational concern.

## CORS

Browsers calling a Arkret service from a different origin need CORS. The
SDK does not include a CORS layer; configure it in the chosen HTTP runtime:

```rust,ignore
allow_origin("https://app.example");
allow_methods(["GET", "POST", "PUT", "HEAD"]);
allow_headers([
    "authorization",
    "content-type",
    "idempotency-key",
    "x-arkret-request-id",
    "x-arkret-wait-for",
]);
```

The allowlisted headers should match what the client SDK sends — see
`HEADER_REQUEST_ID`, `HEADER_IDEMPOTENCY_KEY`, `HEADER_WAIT_FOR` in
`crates/http-client/src/lib.rs`.

## Request limits & rate limiting

- **Body size**. Configure the chosen runtime's body size limit explicitly if
  your callers upload large blobs through the `ck.self.blob.upload.create` path. Reject
  oversized uploads with a 413 carrying the standard
  `ck.error.payload_too_large` error code.
- **Rate limit metadata**. The SDK exposes `service::RateLimitMetadata` and
  `service::QuotaMetadata` so the server can advertise its limits in
  `GET /_arkret/describe`. Use runtime middleware or a fronting tier
  (e.g. nginx `limit_req_zone`) to enforce them. Match the advertised window
  to the enforcement.

## Health and readiness

Operate the standard `GET /_arkret/describe` endpoint as the health
check — it returns the service identity and capability advertisement. For
load balancers that require a tiny dedicated path, add a runtime-specific
`/healthz` handler that returns 200 once the service has finished startup
verification (DID resolved, key store loaded, MLS state ready).

## Observability

- The SDK gates all `tracing` calls on the `tracing` feature flag, off by
  default. Enable it in the binary when you wire in a `tracing-subscriber`.
- Log redaction: use `redact_log_value()` (re-exported from `arkret`) on any
  structured field that may contain DIDs, tokens, signatures or proof
  references. The push-payload validator and TURN credential validator do
  this automatically; manual log sites must opt in.
- Surface `X-Arkret-Request-Id` from inbound requests into log fields and
  echo it on outbound responses so client traces line up with server traces.

## Running with systemd

A minimal `arkret.service` unit for a binary built into `/usr/local/bin/`:

```ini
[Unit]
Description=Arkret v1 service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/arkret-service --listen 127.0.0.1:8080
Restart=on-failure
RestartSec=2s
Environment=RUST_LOG=info,arkret=info
DynamicUser=yes
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Adjust `--listen`, `Environment` and the service name to match the binary
crate you build. Reverse-proxy TLS termination handles cert lifecycle on
behalf of the unit.

## Production hardening checklist

- HTTPS everywhere; `ClientBuilder::allow_insecure_localhost()` is for
  development and integration tests only.
- Pin the SDK by minor version; track local CHANGELOG updates and
  `cargo audit` notifications.
- Run `cargo deny check --config .deny.toml --all-features` in CI of any
  downstream binary that depends on the SDK.
- Persist MLS group state in a durable, encrypted-at-rest store. The
  in-memory implementations under `crates/sdk/src` are conformance facades,
  not production back ends.
- Front the service with a reverse proxy or CDN that enforces request
  body size limits, HTTP/2 keep-alive timeouts, and basic rate limiting.
- Subscribe to the Arkret specification repository so capability and
  schema changes can be tracked alongside the SDK release notes.
