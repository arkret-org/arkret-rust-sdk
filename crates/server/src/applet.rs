//! S-8 (savfox SDK gap, 2026-05-27) — `salvo::Router` factory for
//! Applet HTTP endpoints.
//!
//! Wires the 6 endpoints from `applet-integration.md` §7 to a single
//! [`AppletHandler`] trait implementation: ping, describe,
//! transactions, actor lookup, realm lookup, protocol lookup. The
//! transactions endpoint routes every verified delivery through the
//! Idempotency-Key window (S-5) via [`AppletService::dispatch_transaction`]:
//! exact duplicates replay the cached outcome without re-executing side
//! effects, and conflicting duplicates fail closed with
//! `duplicate_conflict` (`applet-integration.md` §7.3).
//!
//! The trait surface is always available (under `applet-runtime`).
//! The Salvo `Router` factory is gated behind the `salvo` feature;
//! when off, callers can still implement [`AppletHandler`], route to it
//! themselves, and reuse [`AppletService::dispatch_transaction`] for the
//! same idempotency semantics.

use std::sync::Arc;

use arkret_core::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome, AppletTransactionRequestBody, Error, Hash, Result, ServiceDescribe,
};
use arkret_signatures::VerificationMethodDocument;

use crate::idempotency::{IdempotencyClaim, IdempotencyIdentity, IdempotencyWindow};

/// One standard Applet service route exposed by [`service_routes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceRoute {
    pub method: &'static str,
    pub path: &'static str,
    pub operation_id: &'static str,
}

const SERVICE_ROUTES: [ServiceRoute; 6] = [
    ServiceRoute {
        method: "GET",
        path: "/_arkret/edge/applet/ping",
        operation_id: "ak.edge.applet.query.ping",
    },
    ServiceRoute {
        method: "GET",
        path: "/_arkret/edge/applet/describe",
        operation_id: "ak.edge.applet.query.describe",
    },
    ServiceRoute {
        method: "POST",
        path: "/_arkret/edge/applet/transactions",
        operation_id: "ak.edge.applet.command.transaction",
    },
    ServiceRoute {
        method: "GET",
        path: "/_arkret/edge/applet/actors/{actor_id}",
        operation_id: "ak.edge.applet.actor.query.resolve",
    },
    ServiceRoute {
        method: "GET",
        path: "/_arkret/edge/applet/realms/{realm_id_or_alias}",
        operation_id: "ak.edge.applet.realm.query.resolve",
    },
    ServiceRoute {
        method: "GET",
        path: "/_arkret/edge/applet/protocols/{protocol}",
        operation_id: "ak.edge.applet.query.protocol_metadata",
    },
];

/// Return the complete standard Applet service route surface.
pub const fn service_routes() -> &'static [ServiceRoute] {
    &SERVICE_ROUTES
}

/// Application-owned trait the [`router`] factory dispatches to.
///
/// Implementations focus on business logic; the factory handles HTTP
/// dispatch, body deserialization, Idempotency-Key extraction and
/// deduplication. Bounds (`Send + Sync + 'static`) are pinned so the
/// trait is object-safe for the `Arc<dyn AppletHandler>` wiring the
/// router uses.
pub trait AppletHandler: Send + Sync + 'static {
    /// Resolve one DID verification method used by the [`router`] factory to authenticate inbound
    /// `POST /_arkret/edge/applet/transactions` pushes.
    ///
    /// The router resolves both the source service DID's HTTP message
    /// signature key and every pushed Event's `proof.verification_method`
    /// through this hook before any business dispatch. Implementers
    /// MUST resolve only keys scoped to the trust roots they accept for
    /// inbound pushes. Source-DID trust
    /// is enforced here so [`handle_transaction`](Self::handle_transaction)
    /// never observes an unauthenticated or forged push.
    fn resolve_verification_method(
        &self,
        verification_method: &str,
    ) -> Result<VerificationMethodDocument>;

    /// `GET /_arkret/edge/applet/ping`
    fn ping(&self) -> Result<AppletPingOutcome>;
    /// `GET /_arkret/edge/applet/describe`
    fn describe(&self) -> Result<ServiceDescribe>;
    /// `POST /_arkret/edge/applet/transactions`
    ///
    /// The [`router`] factory only dispatches here **after** it has
    /// verified the inbound HTTP message signature against the source
    /// service DID, independently verified every Event proof, and claimed
    /// the idempotency window for this delivery. A failed verification is
    /// answered with `401 invalid_signature`, a duplicate delivery is
    /// answered from the cached outcome, and a conflicting duplicate with
    /// `409 duplicate_conflict` — this method is never called in any of
    /// those cases. `Idempotency-Key` is mandatory on the wire
    /// (`applet-integration.md` §7.3), so it arrives here non-optional.
    fn handle_transaction(
        &self,
        idempotency_key: &str,
        req: AppletTransactionRequestBody,
    ) -> Result<AppletTransactionOutcome>;
    /// `GET /_arkret/edge/applet/actors/{actor_id}`
    fn resolve_actor(&self, actor_id: &str) -> Result<AppletActorView>;
    /// `GET /_arkret/edge/applet/realms/{realm_id_or_alias}`
    fn resolve_realm(&self, realm_id_or_alias: &str) -> Result<AppletRealmView>;
    /// `GET /_arkret/edge/applet/protocols/{protocol}`
    fn resolve_protocol(&self, protocol: &str) -> Result<AppletProtocolMetadata>;
}

/// Wrap an [`AppletHandler`] together with an idempotency window the
/// router uses to dedupe transaction submissions per
/// `applet-integration.md` §7.3.
#[derive(Clone)]
pub struct AppletService {
    pub handler: Arc<dyn AppletHandler>,
    pub idempotency: Arc<IdempotencyWindow<AppletTransactionOutcome>>,
}

/// Result of routing one *verified* transaction delivery through the
/// idempotency window ([`AppletService::dispatch_transaction`]).
#[derive(Debug)]
pub enum TransactionDispatch {
    /// Fresh delivery: the handler executed and the outcome was recorded
    /// for future duplicates.
    Executed(AppletTransactionOutcome),
    /// Exact duplicate of a completed delivery: the cached outcome is
    /// replayed and the handler was NOT invoked (`applet-integration.md`
    /// §7.3 forbids re-executing side effects).
    Replayed(AppletTransactionOutcome),
    /// Same idempotency identity but a different canonical body digest or
    /// `source_signature_anchor`: fail closed with `duplicate_conflict`.
    DuplicateConflict,
    /// The same delivery is currently being processed by another request.
    /// Answer with a retryable signal; the retry will observe the settled
    /// outcome.
    InFlight,
    /// The handler failed. The claim was released so the peer can retry.
    Failed(Error),
}

impl AppletService {
    pub fn new<H: AppletHandler>(
        handler: H,
        idempotency: IdempotencyWindow<AppletTransactionOutcome>,
    ) -> Self {
        Self {
            handler: Arc::new(handler),
            idempotency: Arc::new(idempotency),
        }
    }

    pub fn from_arcs(
        handler: Arc<dyn AppletHandler>,
        idempotency: Arc<IdempotencyWindow<AppletTransactionOutcome>>,
    ) -> Self {
        Self {
            handler,
            idempotency,
        }
    }

    /// Route one verified transaction delivery through the idempotency
    /// window, per `applet-integration.md` §7.3.
    ///
    /// The claim persists the idempotency record *before* the handler runs
    /// (spec ordering: persist first, side effects second), duplicates are
    /// answered from the cached outcome without invoking the handler, and
    /// conflicting duplicates fail closed. Callers MUST pass the canonical
    /// body digest of the exact signed bytes and the per-delivery
    /// `source_signature_anchor` formed during verification (§7.3.1).
    pub fn dispatch_transaction(
        &self,
        identity: &IdempotencyIdentity,
        body_digest: &Hash,
        source_signature_anchor: &str,
        body: AppletTransactionRequestBody,
    ) -> TransactionDispatch {
        match self
            .idempotency
            .claim(identity, body_digest, source_signature_anchor)
        {
            IdempotencyClaim::Fresh => {
                // The idempotency record is already persisted; only now may
                // external side effects run.
                match self
                    .handler
                    .handle_transaction(&identity.idempotency_key, body)
                {
                    Ok(outcome) => {
                        self.idempotency.complete(identity, outcome.clone());
                        TransactionDispatch::Executed(outcome)
                    }
                    Err(err) => {
                        // Release the claim so a retry of the same delivery
                        // is not answered as a duplicate of a failure.
                        self.idempotency.release(identity);
                        TransactionDispatch::Failed(err)
                    }
                }
            }
            IdempotencyClaim::Duplicate { outcome, .. } => TransactionDispatch::Replayed(outcome),
            IdempotencyClaim::DuplicateConflict { .. } => TransactionDispatch::DuplicateConflict,
            IdempotencyClaim::InFlight { .. } => TransactionDispatch::InFlight,
        }
    }
}

#[cfg(feature = "salvo")]
mod salvo_router {
    use arkret_canonical::canonical;
    use arkret_core::{ERROR_CODE_DUPLICATE_CONFLICT, ERROR_CODE_INVALID_SIGNATURE};
    use arkret_signatures::http_signature::{
        SignatureVerificationPolicy, parse_signature_input, public_key_from_bytes,
        verify_signed_http_message,
    };
    use arkret_signatures::{
        DidVerificationMethodResolver, EventProofBuilder, ProofVerificationContext,
        PublicKeyMaterial, VerificationMethodDocument, verify_eddsa_detached_jws_proof,
        verify_proof_with_resolver,
    };
    use salvo::affix_state;
    use salvo::prelude::*;

    use super::*;
    use crate::idempotency::IdempotencyDirection;

    /// Build the Salvo [`Router`] for the six standard Applet endpoints.
    pub fn router(service: AppletService) -> Result<Router> {
        Ok(Router::with_path("_arkret/edge/applet")
            .hoop(affix_state::inject(service))
            .push(Router::with_path("ping").get(ping_handler))
            .push(Router::with_path("describe").get(describe_handler))
            .push(Router::with_path("transactions").post(transactions_handler))
            .push(Router::with_path("actors/{actor_id}").get(actor_handler))
            .push(Router::with_path("realms/{realm_id_or_alias}").get(realm_handler))
            .push(Router::with_path("protocols/{protocol}").get(protocol_handler)))
    }

    fn service(depot: &Depot, res: &mut Response) -> Option<AppletService> {
        let service = depot.get_typed::<AppletService>().ok().cloned();
        if service.is_none() {
            res.render(
                StatusError::service_unavailable()
                    .brief("AppletService is not installed in the request depot"),
            );
        }
        service
    }

    fn into_status_error(err: Error) -> StatusError {
        StatusError::internal_server_error().brief(err.to_string())
    }

    #[handler]
    async fn ping_handler(depot: &mut Depot, res: &mut Response) {
        let Some(service) = service(depot, res) else {
            return;
        };
        match service.handler.ping() {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn describe_handler(depot: &mut Depot, res: &mut Response) {
        let Some(service) = service(depot, res) else {
            return;
        };
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

    /// Owned snapshot of the inbound request, so signature verification can
    /// run off the async worker (the DID resolver may block on network I/O).
    struct InboundTransactionParts {
        method: String,
        authority: String,
        path: String,
        headers: Vec<(String, String)>,
        body_bytes: Vec<u8>,
        idempotency_key: String,
        destination_service_id: String,
    }

    /// Successfully verified delivery plus the idempotency evidence the
    /// window records (`applet-integration.md` §7.3.1).
    struct VerifiedInboundTransaction {
        body: AppletTransactionRequestBody,
        body_digest: Hash,
        source_signature_anchor: String,
    }

    struct HandlerResolver<'a>(&'a dyn AppletHandler);

    impl DidVerificationMethodResolver for HandlerResolver<'_> {
        fn resolve_verification_method(
            &self,
            verification_method: &str,
        ) -> Result<VerificationMethodDocument> {
            self.0.resolve_verification_method(verification_method)
        }
    }

    fn public_key_material(value: &str) -> Result<PublicKeyMaterial> {
        if value.trim_start().starts_with('{') {
            return Ok(PublicKeyMaterial::Jwk {
                value: serde_json::from_str(value)?,
            });
        }
        Ok(PublicKeyMaterial::Ed25519Multibase {
            value: value
                .trim()
                .strip_prefix("did:key:")
                .unwrap_or(value.trim())
                .to_owned(),
        })
    }

    fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Verify the inbound transaction push per `applet-integration.md` §7.3:
    /// (1) the source service DID's HTTP message signature over the raw body,
    /// and (2) every pushed Event's proof independently. Returns the parsed
    /// body (plus the canonical body digest and `source_signature_anchor`)
    /// only when every check passes; any failure is an `Err` and the caller
    /// MUST answer `401 invalid_signature` without dispatching.
    ///
    /// Synchronous by design: the DID resolver behind
    /// [`AppletHandler::resolve_verification_method`] may block on network fetches,
    /// so the async handler runs this on the blocking pool.
    fn verify_inbound_transaction(
        service: &AppletService,
        parts: &InboundTransactionParts,
    ) -> Result<VerifiedInboundTransaction> {
        // Federation transport is TLS (`https`); `@authority` comes from the
        // Host header, `@path` from the request target, and `@target-uri` is
        // their composition — matching the absolute URL the pushing node
        // signed.
        let target_uri = format!("https://{}{}", parts.authority, parts.path);

        // Resolve the source service DID's signing key from the signature
        // `keyid` (an RFC 9421 verification-method DID URL).
        let signature_input_header =
            header_value(&parts.headers, "signature-input").ok_or_else(|| {
                Error::Protocol("applet transaction missing Signature-Input".to_owned())
            })?;
        let signature_input = parse_signature_input(signature_input_header)
            .map_err(|err| Error::Protocol(format!("parse Signature-Input: {err}")))?;
        let resolver = HandlerResolver(service.handler.as_ref());
        let resolved = resolver.resolve_verification_method(&signature_input.key_id)?;
        let key_bytes = public_key_material(&resolved.public_key_multibase)?.ed25519_bytes()?;
        let public_key = public_key_from_bytes(&key_bytes)
            .map_err(|err| Error::Protocol(format!("source service verifying key: {err}")))?;

        let now = chrono::Utc::now().timestamp();
        verify_signed_http_message(
            &parts.method,
            &target_uri,
            &parts.authority,
            &parts.path,
            parts.headers.iter().map(|(n, v)| (n.as_str(), v.as_str())),
            &parts.body_bytes,
            &public_key,
            &SignatureVerificationPolicy::service_ingest(),
            now,
        )
        .map_err(|err| Error::Protocol(format!("http message signature: {err}")))?;

        // Body is trusted only after the signature covers it (content-digest
        // is in the service-ingest policy, so a verified signature pins these
        // exact bytes).
        let body: AppletTransactionRequestBody = serde_json::from_slice(&parts.body_bytes)
            .map_err(|err| Error::Protocol(format!("parse applet transaction body: {err}")))?;

        // Bind the signing key's controller DID to the declared source service
        // DID so a peer can't sign as itself but claim another service.
        let signer_did = resolved.controller.as_ref().unwrap_or(&resolved.did);
        if signer_did != &body.source_service_id {
            return Err(Error::Protocol(
                "source_service_id does not match signature keyid controller".to_owned(),
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
                let builder = EventProofBuilder::new();
                let canonical_bytes = builder.envelope_bytes(event)?;
                let expected_digest = Hash::new(canonical::sha256_digest(&canonical_bytes))?;
                let signing_actor = event
                    .executed_by
                    .clone()
                    .unwrap_or_else(|| event.actor_id.clone());
                let context = ProofVerificationContext::new(signing_actor, expected_digest);
                let verification =
                    verify_proof_with_resolver(proof, &context, &resolver, |method, proof| {
                        let public_key = public_key_material(&method.public_key_multibase)?;
                        verify_eddsa_detached_jws_proof(
                            proof,
                            &canonical_bytes,
                            &event.actor_id,
                            &public_key,
                        )
                        .map_err(Error::from)?;
                        Ok(true)
                    })?;
                if !verification.valid {
                    return Err(Error::Protocol("event proof signature invalid".to_owned()));
                }
            }
        }

        // Canonical digest of the exact signed bytes (what Content-Digest
        // pins) — this is what the idempotency record compares duplicates
        // against.
        let body_digest = Hash::new(canonical::sha256_digest(&parts.body_bytes))?;

        // Unforgeable per-delivery source-signature anchor (§7.3.1): a
        // canonical tuple over the *verified* signature evidence. Stored with
        // the idempotency record so a rotated key or a different signer can
        // never replay an old Idempotency-Key as a benign duplicate.
        // `params_value` is the byte-exact `@signature-params` suffix, which
        // pins the covered component set together with `created` / `expires`
        // / `keyid` / `alg`; the explicit fields are repeated for auditability.
        let anchor_tuple = serde_json::json!({
            "operation_id": crate::idempotency::APPLET_TRANSACTION_OPERATION_ID,
            "direction": IdempotencyDirection::NodeToApplet.as_str(),
            "source_service_id": body.source_service_id,
            "destination_service_id": parts.destination_service_id,
            "verification_method": signature_input.key_id,
            "algorithm": signature_input.algorithm,
            "idempotency_key": parts.idempotency_key,
            "content_digest": body_digest,
            "signature_params": signature_input.params_value,
            "created": signature_input.created,
            "expires": signature_input.expires,
        });
        let source_signature_anchor = canonical::canonical_json_string(&anchor_tuple)?;

        Ok(VerifiedInboundTransaction {
            body,
            body_digest,
            source_signature_anchor,
        })
    }

    #[handler]
    async fn transactions_handler(req: &mut Request, depot: &mut Depot, res: &mut Response) {
        let Some(service) = service(depot, res) else {
            return;
        };

        // Idempotency-Key is mandatory for transaction pushes and MUST be a
        // covered signature component (`applet-integration.md` §7.3 /
        // §7.3.1); a delivery without it cannot be answered idempotently, so
        // fail closed with the unified authentication failure.
        let Some(idempotency_key) = req
            .header::<String>("Idempotency-Key")
            .map(|key| key.trim().to_owned())
            .filter(|key| !key.is_empty())
        else {
            render_invalid_signature(res);
            return;
        };
        // Destination-Service-ID is likewise a mandatory covered component
        // and an idempotency identity field (§7.3.1).
        let Some(destination_service_id) = req
            .header::<String>("Destination-Service-ID")
            .map(|did| did.trim().to_owned())
            .filter(|did| !did.is_empty())
        else {
            render_invalid_signature(res);
            return;
        };
        let Some(authority) = req
            .header::<String>("host")
            .map(|host| host.trim().to_owned())
            .filter(|host| !host.is_empty())
        else {
            render_invalid_signature(res);
            return;
        };

        // Raw body bytes are required: RFC 9421 content-digest and the JSON
        // body must both be verified against the exact bytes the peer signed,
        // not a re-serialization.
        let body_bytes = match req.payload().await {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => {
                render_invalid_signature(res);
                return;
            }
        };

        // Pass every request header so any covered component (e.g.
        // `x-arkret-origin-service-id`) participates in canonicalization.
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

        let parts = InboundTransactionParts {
            method: req.method().as_str().to_owned(),
            authority,
            path: req.uri().path().to_owned(),
            headers,
            body_bytes,
            idempotency_key: idempotency_key.clone(),
            destination_service_id: destination_service_id.clone(),
        };

        // Fail closed: any source-DID / HTTP-signature / event-proof failure
        // is answered with 401 invalid_signature and never reaches
        // `handle_transaction`. Verification resolves DIDs through the
        // handler's resolver, which may block on network I/O — run it on the
        // blocking pool so runtime workers stay free to drive I/O (`SERVICE`
        // hands out `&'static AppletService`, so the move is borrow-free).
        let verification_service = service.clone();
        let verified = tokio::task::spawn_blocking(move || {
            verify_inbound_transaction(&verification_service, &parts)
        })
        .await;
        let verified = match verified {
            Ok(Ok(verified)) => verified,
            Ok(Err(_)) | Err(_) => {
                render_invalid_signature(res);
                return;
            }
        };

        let identity = IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            verified.body.source_service_id.to_string(),
            destination_service_id,
            idempotency_key,
        );
        match service.dispatch_transaction(
            &identity,
            &verified.body_digest,
            &verified.source_signature_anchor,
            verified.body,
        ) {
            TransactionDispatch::Executed(outcome) | TransactionDispatch::Replayed(outcome) => {
                res.render(Json(outcome));
            }
            TransactionDispatch::DuplicateConflict => {
                // §7.3: same idempotency identity with a different canonical
                // body digest or source_signature_anchor MUST fail closed
                // with `duplicate_conflict` once authentication passed.
                res.render(
                    StatusError::conflict()
                        .brief(ERROR_CODE_DUPLICATE_CONFLICT)
                        .detail(ERROR_CODE_DUPLICATE_CONFLICT),
                );
            }
            TransactionDispatch::InFlight => {
                // The same delivery is still being processed; signal a
                // retryable condition — the retry observes the settled
                // outcome as a Duplicate.
                res.render(
                    StatusError::service_unavailable()
                        .brief("duplicate delivery in flight; retry to receive the outcome"),
                );
            }
            TransactionDispatch::Failed(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn actor_handler(req: &mut Request, depot: &mut Depot, res: &mut Response) {
        let actor_id = req.param::<String>("actor_id").unwrap_or_default();
        let Some(service) = service(depot, res) else {
            return;
        };
        match service.handler.resolve_actor(&actor_id) {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn realm_handler(req: &mut Request, depot: &mut Depot, res: &mut Response) {
        let realm = req.param::<String>("realm_id_or_alias").unwrap_or_default();
        let Some(service) = service(depot, res) else {
            return;
        };
        match service.handler.resolve_realm(&realm) {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn protocol_handler(req: &mut Request, depot: &mut Depot, res: &mut Response) {
        let protocol = req.param::<String>("protocol").unwrap_or_default();
        let Some(service) = service(depot, res) else {
            return;
        };
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use arkret_core::{AppletPingOutcome, Did, TypedTrustDomainId};
    use arkret_signatures::{
        DidVerificationMethodResolver, StaticDidVerificationMethodResolver,
        VerificationMethodDocument,
    };

    use super::*;
    use crate::idempotency::IdempotencyDirection;

    struct StubHandler {
        resolver: StaticDidVerificationMethodResolver,
        transaction_calls: AtomicUsize,
        fail_next_transaction: AtomicBool,
    }

    impl Default for StubHandler {
        fn default() -> Self {
            Self {
                resolver: StaticDidVerificationMethodResolver::default(),
                transaction_calls: AtomicUsize::new(0),
                fail_next_transaction: AtomicBool::new(false),
            }
        }
    }

    impl AppletHandler for StubHandler {
        fn resolve_verification_method(
            &self,
            verification_method: &str,
        ) -> Result<VerificationMethodDocument> {
            self.resolver
                .resolve_verification_method(verification_method)
        }
        fn ping(&self) -> Result<AppletPingOutcome> {
            Ok(AppletPingOutcome {
                ok: true,
                applet_id: "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
                service_id: Did::new("did:webvh:QmSvc:svc.example").unwrap(),
                protocol_version: "1.0".to_owned(),
            })
        }
        fn describe(&self) -> Result<ServiceDescribe> {
            let mut description = ServiceDescribe::development(
                Did::new("did:webvh:QmSvc:svc.example").unwrap(),
                TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
                "applet_service",
            );
            description.supported_profiles = vec!["ak.profile.applet.v1".to_owned()];
            description.supported_operations = vec!["ak.edge.applet.query.describe".to_owned()];
            Ok(description)
        }
        fn handle_transaction(
            &self,
            _idempotency_key: &str,
            _req: AppletTransactionRequestBody,
        ) -> Result<AppletTransactionOutcome> {
            let call = self.transaction_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_next_transaction.swap(false, Ordering::SeqCst) {
                return Err(Error::Protocol("simulated handler failure".to_owned()));
            }
            Ok(AppletTransactionOutcome {
                ok: true,
                // Tag the outcome with the call ordinal so replay tests can
                // prove the cached outcome (not a re-execution) is returned.
                rejected: vec![arkret_core::RejectedItem {
                    event_id: None,
                    reason_code: format!("call_{call}"),
                    retry_after_ms: None,
                }],
                retry_after_ms: None,
            })
        }
        fn resolve_actor(&self, _actor_id: &str) -> Result<AppletActorView> {
            Ok(AppletActorView {
                exists: false,
                actor_id: None,
                display_name: None,
                external_ref: None,
            })
        }
        fn resolve_realm(&self, _: &str) -> Result<AppletRealmView> {
            Ok(AppletRealmView {
                exists: false,
                realm_id: None,
                title: None,
                external_ref: None,
            })
        }
        fn resolve_protocol(&self, _: &str) -> Result<AppletProtocolMetadata> {
            Ok(AppletProtocolMetadata {
                protocol: "ak.unknown".to_owned(),
                display_name: "Unknown".to_owned(),
                icon_blob_ref: None,
                field_types: Default::default(),
                instances: Vec::new(),
            })
        }
    }

    fn service() -> AppletService {
        AppletService::new(
            StubHandler::default(),
            IdempotencyWindow::new(Duration::from_secs(5 * 60)),
        )
    }

    fn body() -> AppletTransactionRequestBody {
        AppletTransactionRequestBody {
            source_service_id: Did::new("did:webvh:QmSrc:source.example").unwrap(),
            events: Vec::new(),
            ephemeral: None,
        }
    }

    fn identity(key: &str) -> IdempotencyIdentity {
        IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            "did:webvh:QmSrc:source.example",
            "did:webvh:QmDst:applet.example",
            key,
        )
    }

    fn digest_of(bytes: &[u8]) -> Hash {
        Hash::new(arkret_canonical::canonical::sha256_digest(bytes)).unwrap()
    }

    #[test]
    fn applet_service_constructs_with_handler_and_idempotency_window() {
        let svc = service();
        let body = svc.handler.ping().unwrap();
        assert!(body.ok);
    }

    #[test]
    fn dispatch_replays_duplicates_and_fails_closed_on_conflicts() {
        let handler = Arc::new(StubHandler::default());
        let svc = AppletService::from_arcs(
            handler.clone(),
            Arc::new(IdempotencyWindow::new(Duration::from_secs(5 * 60))),
        );
        let digest = digest_of(b"payload-v1");

        // Fresh delivery executes the handler once.
        let first = match svc.dispatch_transaction(&identity("key-1"), &digest, "anchor-a", body())
        {
            TransactionDispatch::Executed(outcome) => outcome,
            other => panic!("expected Executed, got {other:?}"),
        };
        assert_eq!(handler.transaction_calls.load(Ordering::SeqCst), 1);

        // Exact duplicate replays the ORIGINAL outcome without re-executing
        // side effects (`applet-integration.md` §7.3).
        match svc.dispatch_transaction(&identity("key-1"), &digest, "anchor-a", body()) {
            TransactionDispatch::Replayed(outcome) => assert_eq!(outcome, first),
            other => panic!("expected Replayed, got {other:?}"),
        }
        assert_eq!(handler.transaction_calls.load(Ordering::SeqCst), 1);

        // Same identity, different body digest → duplicate_conflict, handler
        // untouched.
        match svc.dispatch_transaction(
            &identity("key-1"),
            &digest_of(b"payload-v2"),
            "anchor-a",
            body(),
        ) {
            TransactionDispatch::DuplicateConflict => {}
            other => panic!("expected DuplicateConflict, got {other:?}"),
        }
        // Same identity + body, different source_signature_anchor (e.g. key
        // rotated between deliveries) → also duplicate_conflict.
        match svc.dispatch_transaction(&identity("key-1"), &digest, "anchor-b", body()) {
            TransactionDispatch::DuplicateConflict => {}
            other => panic!("expected DuplicateConflict, got {other:?}"),
        }
        assert_eq!(handler.transaction_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dispatch_releases_claim_on_handler_failure_so_retry_executes() {
        let handler = Arc::new(StubHandler::default());
        handler.fail_next_transaction.store(true, Ordering::SeqCst);
        let svc = AppletService::from_arcs(
            handler.clone(),
            Arc::new(IdempotencyWindow::new(Duration::from_secs(5 * 60))),
        );
        let digest = digest_of(b"payload-v1");

        match svc.dispatch_transaction(&identity("key-1"), &digest, "anchor-a", body()) {
            TransactionDispatch::Failed(_) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(handler.transaction_calls.load(Ordering::SeqCst), 1);

        // The failed claim was released: the retry executes again instead of
        // replaying a failure.
        match svc.dispatch_transaction(&identity("key-1"), &digest, "anchor-a", body()) {
            TransactionDispatch::Executed(_) => {}
            other => panic!("expected Executed on retry, got {other:?}"),
        }
        assert_eq!(handler.transaction_calls.load(Ordering::SeqCst), 2);
    }
}
