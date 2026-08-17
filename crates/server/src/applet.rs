//! Framework-independent Applet service contracts.
//!
//! Maps the 6 operations from `applet-integration.md` §7 to a single
//! [`AppletHandler`] trait implementation: ping, describe,
//! transactions, actor lookup, realm lookup, protocol lookup. The
//! transactions endpoint routes every verified delivery through the
//! Idempotency-Key window (S-5) via [`AppletService::dispatch_transaction`]:
//! exact duplicates replay the cached outcome without re-executing side
//! effects, and conflicting duplicates fail closed with
//! `duplicate_conflict` (`applet-integration.md` §7.3).
//!
//! Host applications implement [`AppletHandler`], bind it to their HTTP
//! framework and reuse [`AppletService::dispatch_transaction`] for the same
//! idempotency semantics.

use std::sync::Arc;

use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
use arkret_models_discovery::service_description::ServiceDescribe;
use arkret_models_integration::applet_models::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome,
};
use arkret_signatures::VerificationMethodDocument;
use arkret_wire::{DidUrl, Error, Hash, Result};

use crate::idempotency::{
    IdempotencyIdentity, IdempotencyWindow, TransactionClaim, TransactionIdempotencyStore,
};

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
        operation_id: arkret_wire::ServiceOperationId::EDGE_APPLET_READ_PING,
    },
    ServiceRoute {
        method: "GET",
        path: "/_arkret/edge/applet/describe",
        operation_id: arkret_wire::ServiceOperationId::EDGE_APPLET_READ_DESCRIBE,
    },
    ServiceRoute {
        method: "POST",
        path: "/_arkret/edge/applet/transactions",
        operation_id: arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION,
    },
    ServiceRoute {
        method: "GET",
        path: "/_arkret/edge/applet/actors/{actor_id}",
        operation_id: arkret_wire::ServiceOperationId::EDGE_APPLET_ACTOR_READ_RESOLVE,
    },
    ServiceRoute {
        method: "GET",
        path: "/_arkret/edge/applet/realms/{realm_id_or_alias}",
        operation_id: arkret_wire::ServiceOperationId::EDGE_APPLET_REALM_READ_RESOLVE,
    },
    ServiceRoute {
        method: "GET",
        path: "/_arkret/edge/applet/protocols/{protocol}",
        operation_id: arkret_wire::ServiceOperationId::EDGE_APPLET_READ_PROTOCOL_METADATA,
    },
];

/// Return the complete standard Applet service route surface.
pub const fn service_routes() -> &'static [ServiceRoute] {
    &SERVICE_ROUTES
}

/// Application-owned trait the `router` factory dispatches to.
///
/// Implementations focus on business logic; the factory handles HTTP
/// dispatch, body deserialization, Idempotency-Key extraction and
/// deduplication. Bounds (`Send + Sync + 'static`) are pinned so the
/// trait is object-safe for the `Arc<dyn AppletHandler>` wiring the
/// router uses.
pub trait AppletHandler: Send + Sync + 'static {
    /// Resolve one DID verification method used by the `router` factory to authenticate inbound
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
        verification_method: &DidUrl,
    ) -> Result<VerificationMethodDocument>;

    /// `GET /_arkret/edge/applet/ping`
    fn ping(&self) -> Result<AppletPingOutcome>;
    /// `GET /_arkret/edge/applet/describe`
    fn describe(&self) -> Result<ServiceDescribe>;
    /// `POST /_arkret/edge/applet/transactions`
    ///
    /// The `router` factory only dispatches here **after** it has
    /// verified the inbound HTTP message signature against the source
    /// service DID, independently verified every Event proof, and claimed
    /// the idempotency window for this delivery. A failed verification is
    /// answered with `401 signature_invalid`, a duplicate delivery is
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
    pub idempotency: Arc<dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = Error>>,
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
    /// `delivery_authentication_record_digest`: fail closed with `duplicate_conflict`.
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
        idempotency: Arc<dyn TransactionIdempotencyStore<AppletTransactionOutcome, Error = Error>>,
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
    /// `delivery_authentication_record_digest` formed during verification (§7.3.1).
    pub fn dispatch_transaction(
        &self,
        identity: &IdempotencyIdentity,
        body_digest: &Hash,
        delivery_authentication_record_digest: &str,
        body: AppletTransactionRequestBody,
    ) -> TransactionDispatch {
        match self.idempotency.claim(
            identity,
            body_digest.as_str(),
            delivery_authentication_record_digest,
        ) {
            Ok(TransactionClaim::Claimed) => {
                // The idempotency record is already persisted; only now may
                // external side effects run.
                match self
                    .handler
                    .handle_transaction(&identity.idempotency_key, body)
                {
                    Ok(outcome) => {
                        match self.idempotency.record(
                            identity,
                            body_digest.as_str(),
                            delivery_authentication_record_digest,
                            &outcome,
                        ) {
                            Ok(()) => TransactionDispatch::Executed(outcome),
                            Err(error) => TransactionDispatch::Failed(error),
                        }
                    }
                    Err(err) => {
                        // Release the claim so a retry of the same delivery
                        // is not answered as a duplicate of a failure.
                        let _ = self.idempotency.release(
                            identity,
                            body_digest.as_str(),
                            delivery_authentication_record_digest,
                        );
                        TransactionDispatch::Failed(err)
                    }
                }
            }
            Ok(TransactionClaim::Duplicate(outcome)) => TransactionDispatch::Replayed(outcome),
            Ok(TransactionClaim::Conflict) => TransactionDispatch::DuplicateConflict,
            Ok(TransactionClaim::Pending) => TransactionDispatch::InFlight,
            Err(error) => TransactionDispatch::Failed(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use arkret_models_integration::applet_models::AppletPingOutcome;
    use arkret_signatures::{
        DidVerificationMethodResolver, StaticDidVerificationMethodResolver,
        VerificationMethodDocument,
    };
    use arkret_wire::{DidCoreId, DidFullId, TrustDomainId};

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
            verification_method: &DidUrl,
        ) -> Result<VerificationMethodDocument> {
            self.resolver
                .resolve_verification_method(verification_method)
                .map_err(|err| Error::Protocol(err.to_string()))
        }
        fn ping(&self) -> Result<AppletPingOutcome> {
            Ok(AppletPingOutcome {
                ok: true,
                applet_id: "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
                service_id: DidCoreId::new("ak:did_core:webvh:QmSvc").unwrap(),
                protocol_version: "1.0".to_owned(),
            })
        }
        fn describe(&self) -> Result<ServiceDescribe> {
            let mut description = ServiceDescribe::development(
                DidFullId::new("did:webvh:QmSvc:svc.example").unwrap(),
                TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
                arkret_wire::ServiceKind::AppletService,
            );
            description.supported_profiles = vec!["ak.profile.applet.v1".to_owned()];
            description.supported_operations = vec!["ak.edge.applet.read.describe".to_owned()];
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
                rejected: vec![arkret_models_integration::artifacts_applet::RejectedItem {
                    event_id: None,
                    reason_code: arkret_wire::ReasonCode::from_wire(&format!("call_{call}")),
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
                field_definitions: Default::default(),
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
            source_service_id: DidCoreId::new("ak:did_core:webvh:QmSrc").unwrap(),
            events: Vec::new(),
            signals: None,
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
        // Same identity + body, different delivery_authentication_record_digest (e.g. key
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
