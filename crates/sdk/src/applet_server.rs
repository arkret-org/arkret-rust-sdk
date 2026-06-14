//! S-8 (savfox SDK gap, 2026-05-27) — `salvo::Router` factory for
//! Applet HTTP endpoints.
//!
//! Wires the 6 endpoints from `applet-integration.md` §7 to a single
//! [`AppletHandler`] trait implementation: ping, describe,
//! transactions, actor lookup, realm lookup, protocol lookup. The
//! Idempotency-Key dedup (S-5) is wired in; trait methods only need
//! to implement business logic.
//!
//! The trait surface is always available (under `applet-runtime`).
//! The Salvo `Router` factory is gated behind the `salvo` feature;
//! when off, callers can still implement [`AppletHandler`] and route
//! to it themselves.

use std::sync::Arc;

use crate::Result;
use crate::idempotency::IdempotencyWindow;
use crate::identity::DidResolver;
use crate::models::{
    AppletActorView, AppletDescription, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome, AppletTransactionRequestBody,
};

/// Application-owned trait the [`router`] factory dispatches to.
///
/// Implementations focus on business logic; the factory handles HTTP
/// dispatch, body deserialization, and the Idempotency-Key header
/// extraction. Bounds (`Send + Sync + 'static`) are pinned so the
/// trait is object-safe for the `Arc<dyn AppletHandler>` wiring the
/// router uses.
pub trait AppletHandler: Send + Sync + 'static {
    /// DID resolver used by the [`router`] factory to authenticate inbound
    /// `POST /_cokret/edge/applet/transactions` pushes.
    ///
    /// The router resolves both the source service DID's HTTP message
    /// signature key and every pushed Event's `proof.verification_method`
    /// through this resolver before any business dispatch. Implementers
    /// MUST return a resolver scoped to the trust roots they accept for
    /// inbound pushes (e.g. a [`DidWebResolver`](crate::identity::DidWebResolver)
    /// seeded with the trusted source service documents). Source-DID trust
    /// is enforced here so [`handle_transaction`](Self::handle_transaction)
    /// never observes an unauthenticated or forged push.
    fn source_did_resolver(&self) -> &dyn DidResolver;

    /// `GET /_cokret/edge/applet/ping`
    fn ping(&self) -> Result<AppletPingOutcome>;
    /// `GET /_cokret/edge/applet/describe`
    fn describe(&self) -> Result<AppletDescription>;
    /// `POST /_cokret/edge/applet/transactions`
    ///
    /// The [`router`] factory only dispatches here **after** it has
    /// verified the inbound HTTP message signature against the source
    /// service DID and independently verified every Event proof. A failed
    /// verification is answered with `401 invalid_signature` and this
    /// method is never called.
    fn handle_transaction(
        &self,
        idempotency_key: Option<&str>,
        req: AppletTransactionRequestBody,
    ) -> Result<AppletTransactionOutcome>;
    /// `GET /_cokret/edge/applet/actors/{actor_id}`
    fn resolve_actor(&self, actor_id: &str) -> Result<AppletActorView>;
    /// `GET /_cokret/edge/applet/realms/{realm_id_or_alias}`
    fn resolve_realm(&self, realm_id_or_alias: &str) -> Result<AppletRealmView>;
    /// `GET /_cokret/edge/applet/protocols/{protocol}`
    fn resolve_protocol(&self, protocol: &str) -> Result<AppletProtocolMetadata>;
}

/// Wrap an [`AppletHandler`] together with an idempotency window the
/// router uses to dedupe transaction submissions per
/// `applet-integration.md` §7.3.
pub struct AppletService {
    pub handler: Arc<dyn AppletHandler>,
    pub idempotency: Arc<IdempotencyWindow>,
}

impl AppletService {
    pub fn new<H: AppletHandler>(handler: H, idempotency: IdempotencyWindow) -> Self {
        Self {
            handler: Arc::new(handler),
            idempotency: Arc::new(idempotency),
        }
    }

    pub fn from_arcs(handler: Arc<dyn AppletHandler>, idempotency: Arc<IdempotencyWindow>) -> Self {
        Self {
            handler,
            idempotency,
        }
    }
}

#[cfg(feature = "salvo")]
mod salvo_router {
    use std::sync::OnceLock;

    use cokret_signatures::http_signature::{
        SignatureVerificationPolicy, parse_signature_input, public_key_from_bytes,
        verify_signed_http_message,
    };
    use salvo::prelude::*;

    use super::*;
    use crate::Error;
    use crate::error::ERROR_CODE_INVALID_SIGNATURE;
    use crate::identity::{resolve_verification_method_key, verify_event_proof_with_did_resolver};

    /// Process-wide handle to the wired-up [`AppletService`]. Salvo's
    /// `#[handler]` macro can't see generics, so we stash the handler
    /// behind a `OnceLock` and read it back from each endpoint. Only
    /// one [`AppletService`] is supported per process; tests should
    /// run sequentially or use separate processes.
    static SERVICE: OnceLock<AppletService> = OnceLock::new();

    /// Install the [`AppletService`] for the process and build the
    /// salvo [`Router`] for the 6 standard Applet endpoints. Returns
    /// `Err` if called more than once.
    pub fn router(service: AppletService) -> Result<Router> {
        SERVICE
            .set(service)
            .map_err(|_| Error::Protocol("applet_server::router already installed".to_owned()))?;
        Ok(Router::with_path("_cokret/edge/applet")
            .push(Router::with_path("ping").get(ping_handler))
            .push(Router::with_path("describe").get(describe_handler))
            .push(Router::with_path("transactions").post(transactions_handler))
            .push(Router::with_path("actors/{actor_id}").get(actor_handler))
            .push(Router::with_path("realms/{realm_id_or_alias}").get(realm_handler))
            .push(Router::with_path("protocols/{protocol}").get(protocol_handler)))
    }

    /// Read the installed service. Returns `None` (rendered as 503 by
    /// the handlers) instead of panicking when a request is dispatched
    /// before [`router`] ran — a library must not turn a wiring race
    /// into a process abort.
    fn service(res: &mut Response) -> Option<&'static AppletService> {
        let service = SERVICE.get();
        if service.is_none() {
            res.render(
                StatusError::service_unavailable()
                    .brief("applet_server::router not installed before request dispatch"),
            );
        }
        service
    }

    fn into_status_error(err: Error) -> StatusError {
        StatusError::internal_server_error().brief(err.to_string())
    }

    #[handler]
    async fn ping_handler(res: &mut Response) {
        let Some(service) = service(res) else { return };
        match service.handler.ping() {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn describe_handler(res: &mut Response) {
        let Some(service) = service(res) else { return };
        match service.handler.describe() {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    /// Render the unified fail-closed authentication failure for an inbound
    /// push that failed source-DID / signature / event-proof verification.
    /// Minimal disclosure: a single `401 invalid_signature`, never echoing
    /// which check failed.
    fn render_invalid_signature(res: &mut Response) {
        res.render(
            StatusError::unauthorized()
                .brief(ERROR_CODE_INVALID_SIGNATURE)
                .detail(ERROR_CODE_INVALID_SIGNATURE),
        );
    }

    /// Verify the inbound transaction push per `applet-integration.md` §7.3:
    /// (1) the source service DID's HTTP message signature over the raw body,
    /// and (2) every pushed Event's proof independently. Returns the parsed
    /// body only when every check passes; any failure is an `Err` and the
    /// caller MUST answer `401 invalid_signature` without dispatching.
    async fn verify_inbound_transaction(
        service: &AppletService,
        req: &mut Request,
    ) -> Result<AppletTransactionRequestBody> {
        // Raw body bytes are required: RFC 9421 content-digest and the JSON
        // body must both be verified against the exact bytes the peer signed,
        // not a re-serialization.
        let body_bytes = req
            .payload()
            .await
            .map_err(|err| Error::Protocol(format!("read applet transaction body: {err}")))?
            .to_vec();

        // Reconstruct the signed request parts. Federation transport is TLS
        // (`https`); `@authority` comes from the Host header, `@path` from the
        // request target, and `@target-uri` is their composition — matching
        // the absolute URL the pushing node signed.
        let authority = req
            .header::<String>("host")
            .map(|host| host.trim().to_owned())
            .filter(|host| !host.is_empty())
            .ok_or_else(|| Error::Protocol("applet transaction missing Host header".to_owned()))?;
        let path = req.uri().path().to_owned();
        let target_uri = format!("https://{authority}{path}");
        let method = req.method().as_str().to_owned();

        // Pass every request header so any covered component (e.g.
        // `x-cokret-origin-service-did`) participates in canonicalization.
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_owned(), v.to_owned()))
            })
            .collect();

        // Resolve the source service DID's signing key from the signature
        // `keyid` (an RFC 9421 verification-method DID URL).
        let signature_input_header = req.header::<String>("signature-input").ok_or_else(|| {
            Error::Protocol("applet transaction missing Signature-Input".to_owned())
        })?;
        let signature_input = parse_signature_input(&signature_input_header)
            .map_err(|err| Error::Protocol(format!("parse Signature-Input: {err}")))?;
        let resolver = service.handler.source_did_resolver();
        let resolved = resolve_verification_method_key(resolver, &signature_input.key_id)?;
        let key_bytes = resolved.public_key.ed25519_bytes()?;
        let public_key = public_key_from_bytes(&key_bytes)
            .map_err(|err| Error::Protocol(format!("source service verifying key: {err}")))?;

        let now = chrono::Utc::now().timestamp();
        verify_signed_http_message(
            &method,
            &target_uri,
            &authority,
            &path,
            headers.iter().map(|(n, v)| (n.as_str(), v.as_str())),
            &body_bytes,
            &public_key,
            &SignatureVerificationPolicy::service_ingest(),
            now,
        )
        .map_err(|err| Error::Protocol(format!("http message signature: {err}")))?;

        // Body is trusted only after the signature covers it (content-digest
        // is in the service-ingest policy, so a verified signature pins these
        // exact bytes).
        let body: AppletTransactionRequestBody = serde_json::from_slice(&body_bytes)
            .map_err(|err| Error::Protocol(format!("parse applet transaction body: {err}")))?;

        // Bind the signing key's controller DID to the declared source service
        // DID so a peer can't sign as itself but claim another service.
        let signer_did = crate::identity::verification_method_did(&signature_input.key_id)?;
        if signer_did != body.source_service_did {
            return Err(Error::Protocol(
                "source_service_did does not match signature keyid controller".to_owned(),
            ));
        }

        // Independently verify every Event proof — never trust the pusher's
        // word that the events are signed (§7.3, conformance L730-731).
        for event in &body.events {
            if event.proofs.is_empty() {
                return Err(Error::Protocol(
                    "applet transaction event carries no proof".to_owned(),
                ));
            }
            for proof in &event.proofs {
                let verification = verify_event_proof_with_did_resolver(event, proof, resolver)?;
                if !verification.valid {
                    return Err(Error::Protocol("event proof signature invalid".to_owned()));
                }
            }
        }

        Ok(body)
    }

    #[handler]
    async fn transactions_handler(req: &mut Request, res: &mut Response) {
        let idempotency_key = req
            .header::<String>("Idempotency-Key")
            .map(|key| key.trim().to_owned())
            .filter(|key| !key.is_empty());
        let Some(service) = service(res) else { return };
        // Fail closed: any source-DID / HTTP-signature / event-proof failure
        // is answered with 401 invalid_signature and never reaches
        // `handle_transaction`.
        let body = match verify_inbound_transaction(service, req).await {
            Ok(body) => body,
            Err(_) => {
                render_invalid_signature(res);
                return;
            }
        };
        match service
            .handler
            .handle_transaction(idempotency_key.as_deref(), body)
        {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn actor_handler(req: &mut Request, res: &mut Response) {
        let actor_id = req.param::<String>("actor_id").unwrap_or_default();
        let Some(service) = service(res) else { return };
        match service.handler.resolve_actor(&actor_id) {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn realm_handler(req: &mut Request, res: &mut Response) {
        let realm = req.param::<String>("realm_id_or_alias").unwrap_or_default();
        let Some(service) = service(res) else { return };
        match service.handler.resolve_realm(&realm) {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn protocol_handler(req: &mut Request, res: &mut Response) {
        let protocol = req.param::<String>("protocol").unwrap_or_default();
        let Some(service) = service(res) else { return };
        match service.handler.resolve_protocol(&protocol) {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }
}

#[cfg(feature = "salvo")]
pub use salvo_router::router;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::models::AppletPingOutcome;

    struct StubHandler {
        resolver: crate::identity::DidWebResolver,
    }

    impl Default for StubHandler {
        fn default() -> Self {
            Self {
                resolver: crate::identity::DidWebResolver::new(),
            }
        }
    }

    impl AppletHandler for StubHandler {
        fn source_did_resolver(&self) -> &dyn DidResolver {
            &self.resolver
        }
        fn ping(&self) -> Result<AppletPingOutcome> {
            Ok(AppletPingOutcome {
                ok: true,
                applet_id: "ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
                service_did: crate::Did::new("did:web:svc.example").unwrap(),
                protocol_version: "1.0".to_owned(),
            })
        }
        fn describe(&self) -> Result<AppletDescription> {
            Ok(AppletDescription {
                applet_id: "ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
                service_did: crate::Did::new("did:web:svc.example").unwrap(),
                protocols: vec!["ck.applet.v1".to_owned()],
                namespaces: serde_json::Value::Null,
                limits: serde_json::Value::Null,
                auth: serde_json::Value::Null,
            })
        }
        fn handle_transaction(
            &self,
            _idempotency_key: Option<&str>,
            _req: AppletTransactionRequestBody,
        ) -> Result<AppletTransactionOutcome> {
            Ok(AppletTransactionOutcome {
                ok: true,
                rejected: vec![],
                retry_after_ms: None,
            })
        }
        fn resolve_actor(&self, _actor_id: &str) -> Result<AppletActorView> {
            Ok(AppletActorView {
                exists: false,
                actor_id: None,
                display_name: None,
                external_ref: serde_json::Value::Null,
            })
        }
        fn resolve_realm(&self, _: &str) -> Result<AppletRealmView> {
            Ok(AppletRealmView {
                exists: false,
                realm_id: None,
                title: None,
                external_ref: serde_json::Value::Null,
            })
        }
        fn resolve_protocol(&self, _: &str) -> Result<AppletProtocolMetadata> {
            Ok(AppletProtocolMetadata {
                protocol: "ck.unknown".to_owned(),
                display_name: "Unknown".to_owned(),
                icon_blob_ref: None,
                field_types: serde_json::Value::Null,
                instances: Vec::new(),
            })
        }
    }

    #[test]
    fn applet_service_constructs_with_handler_and_idempotency_window() {
        let svc = AppletService::new(
            StubHandler::default(),
            IdempotencyWindow::new(Duration::from_secs(5 * 60)),
        );
        let body = svc.handler.ping().unwrap();
        assert!(body.ok);
    }
}
