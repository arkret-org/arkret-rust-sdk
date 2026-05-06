//! Minimal Salvo-backed Contrix server.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example salvo_server --features salvo
//! ```
//!
//! The example builds a Salvo `Router` from the framework-independent
//! `RoutedEndpointService` shape via [`contrix::salvo_adapter::contrix_router`]
//! and reports the number of routes that would be exposed on a real
//! listener. It does not bind a TCP socket: actual `Server::new(...)` setup
//! is the host application's responsibility (TLS termination, listener
//! configuration and graceful shutdown vary by deployment).
//!
//! The commented-out block at the bottom shows the canonical bind+serve
//! shape under salvo with the `server` feature enabled.

use std::collections::BTreeMap;

#[cfg(feature = "salvo")]
fn main() -> contrix::Result<()> {
    use contrix::salvo_adapter::contrix_router;
    use contrix::{HttpAdapterResponse, RoutedHttpAdapterRequest};

    // The host application supplies a `RoutedEndpointService`. In a real
    // deployment this is where you run authentication, look up the service
    // implementation for the routed endpoint, and execute the protocol
    // operation. Here we return a placeholder 501 so the wiring is visible
    // without a backing service.
    let service = |request: RoutedHttpAdapterRequest| -> contrix::Result<HttpAdapterResponse> {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        let body = format!(
            r#"{{"errcode":"cx.error.not_implemented","error":"operation {operation_id} not wired"}}"#,
            operation_id = request.operation_id
        );
        Ok(HttpAdapterResponse { status: 501, headers, body: body.into_bytes() })
    };

    let router = contrix_router(service);
    let route_count = router.routers().len();
    // The +1 accounts for the catch-all `{**contrix_rest}` route the
    // adapter installs so unknown Contrix paths return the SDK's standard
    // error envelope instead of Salvo's default 404 body.
    println!("Salvo router built with {route_count} routes (incl. catch-all).");

    // To actually serve the router under salvo, enable salvo's `server`
    // feature in your binary crate and use:
    //
    // ```rust,ignore
    // use salvo::prelude::*;
    //
    // let acceptor = TcpListener::new("0.0.0.0:8080").bind().await;
    // Server::new(acceptor).serve(router).await;
    // ```
    //
    // For TLS termination prefer a fronting reverse proxy (nginx, Caddy,
    // Traefik) or salvo's `rustls` / `native-tls` features. Never expose
    // a Contrix service over plain HTTP outside `127.0.0.1`; the client
    // SDK rejects non-localhost HTTP base URLs by default.

    Ok(())
}

#[cfg(not(feature = "salvo"))]
fn main() {
    eprintln!("enable the `salvo` feature to run this example");
    std::process::exit(1);
}
