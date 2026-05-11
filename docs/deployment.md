# Deployment

This guide covers running a Contrix service implemented with the SDK in a
production environment. The SDK ships with a framework-independent endpoint
registry and an optional Salvo adapter; everything below assumes the Salvo
adapter, but the same principles apply when binding to another HTTP runtime.

## Build matrix

| Feature flag      | What it pulls in                                                  |
| ----------------- | ----------------------------------------------------------------- |
| (default)         | Client + MLS + full sync/timeline/applet runtimes                 |
| `client` (subset) | HTTP client only — no server, no MLS                              |
| `server`          | Framework-independent endpoint registry, no HTTP runtime          |
| `salvo`           | Activates `server` and adds the Salvo router + OpenAPI generation |

For a server binary, enable `salvo`. The SDK keeps the Salvo dependency
optional so client-only callers don't pay the compile cost.

## Minimal Salvo binary

See the runnable example at
[`crates/sdk/examples/salvo_server.rs`](../crates/sdk/examples/salvo_server.rs).
It builds the `contrix_router` and reports the registered route count. To
actually serve, enable salvo's `server` feature in your binary crate and bind
a TCP listener:

```rust,ignore
use salvo::prelude::*;
use contrix::salvo_adapter::contrix_router;

#[tokio::main]
async fn main() {
    let router = contrix_router(/* your RoutedEndpointService */);
    let acceptor = TcpListener::new("0.0.0.0:8080").bind().await;
    Server::new(acceptor).serve(router).await;
}
```

## TLS termination

The Contrix client (`crates/http-client/src/lib.rs::ClientBuilder`) rejects
non-HTTPS base URLs unless the caller opts into
`allow_insecure_localhost()`. So every production server must terminate TLS
somewhere. Two patterns are common:

- **Reverse proxy** (recommended). Terminate TLS in nginx, Caddy, Traefik
  or a cloud load balancer and forward plain HTTP to the Contrix binary
  bound on `127.0.0.1`. The proxy handles cert rotation, OCSP stapling,
  HTTP/2 negotiation, request body limits and access logging.
- **Salvo native TLS**. Enable salvo's `rustls` or `native-tls` feature in
  your binary and use `TcpListener::new(...).rustls(...)`. Acceptable for
  small deployments; production should still front it with a CDN or LB for
  DDoS / WAF capabilities.

The SDK never embeds TLS configuration in published types — TLS is an
operational concern.

## CORS

Browsers calling a Contrix service from a different origin need CORS. The
SDK does not include a CORS layer; use Salvo's built-in CORS middleware:

```rust,ignore
use salvo::cors::Cors;
use salvo::http::Method;

let cors = Cors::new()
    .allow_origin(["https://app.example"])
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::HEAD])
    .allow_headers([
        "authorization",
        "content-type",
        "idempotency-key",
        "x-contrix-request-id",
        "x-contrix-wait-for",
    ])
    .into_handler();

let service = Service::new(router).hoop(cors);
```

The allowlisted headers should match what the client SDK sends — see
`HEADER_REQUEST_ID`, `HEADER_IDEMPOTENCY_KEY`, `HEADER_WAIT_FOR` in
`crates/http-client/src/lib.rs`.

## Request limits & rate limiting

- **Body size**. Salvo's default body size limit is conservative; raise it
  explicitly if your callers upload large blobs through the `cx.blob.upload`
  path. Configure via `salvo::http::body::set_global_max_size(...)` or per-
  route handlers. Reject oversized uploads with a 413 carrying the standard
  `cx.error.payload_too_large` error code.
- **Rate limit metadata**. The SDK exposes `service::RateLimitMetadata` and
  `service::QuotaMetadata` so the server can advertise its limits in
  `GET /api/v1/server/describe`. Use a Salvo middleware
  (`salvo::rate_limiter`) or a fronting tier (e.g. nginx `limit_req_zone`)
  to enforce them. Match the advertised window to the enforcement.

## Health and readiness

Operate the standard `GET /api/v1/server/describe` endpoint as the health
check — it returns the service identity and capability advertisement. For
load balancers that require a tiny dedicated path, add a Salvo handler at
`/healthz` that returns 200 once the service has finished startup
verification (DID resolved, key store loaded, MLS state ready).

## Observability

- The SDK gates all `tracing` calls on the `tracing` feature flag, off by
  default. Enable it in the binary when you wire in a `tracing-subscriber`.
- Log redaction: use `redact_log_value()` (re-exported from `contrix`) on any
  structured field that may contain DIDs, tokens, signatures or proof
  references. The push-payload validator and TURN credential validator do
  this automatically; manual log sites must opt in.
- Surface `X-Contrix-Request-Id` from inbound requests into log fields and
  echo it on outbound responses so client traces line up with server traces.

## Running with systemd

A minimal `contrix.service` unit for a binary built into `/usr/local/bin/`:

```ini
[Unit]
Description=Contrix v1 service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/contrix-service --listen 127.0.0.1:8080
Restart=on-failure
RestartSec=2s
Environment=RUST_LOG=info,contrix=info
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
- Pin the SDK by minor version; subscribe to GitHub releases or
  `cargo audit` notifications.
- Run `cargo deny check --config .deny.toml --all-features` in CI of any
  downstream binary that depends on the SDK.
- Persist MLS group state in a durable, encrypted-at-rest store. The
  in-memory implementations under `crates/sdk/src` are conformance facades,
  not production back ends.
- Front the service with a reverse proxy or CDN that enforces request
  body size limits, HTTP/2 keep-alive timeouts, and basic rate limiting.
- Subscribe to the Contrix specification repository so capability and
  schema changes can be tracked alongside the SDK release notes.

