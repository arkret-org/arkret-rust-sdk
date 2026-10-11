//! Framework-independent Applet service contract.
//!
//! Maps the 6 operations from `applet-integration.md` §7 to a single
//! [`AppletHandler`] trait implementation: ping, describe,
//! transactions, actor lookup, realm lookup, protocol lookup.
//!
//! Host applications implement [`AppletHandler`] and bind it to their HTTP
//! framework; the transactions endpoint requires the Idempotency-Key window
//! (S-5): exact duplicates replay the cached outcome without re-executing
//! side effects, and conflicting duplicates fail closed with
//! `duplicate_conflict` (`applet-integration.md` §7.3).

use arkret_models_discovery::service_description::ServiceDescribe;
use arkret_models_integration::applet_models::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome, AppletTransactionRequestBody,
};
use arkret_signatures::VerificationMethodDocument;
use arkret_wire::{DidUrl, Result};

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

    /// `ak.edge.applet.read.ping.v1` — `GET /_arkret/edge/applet/ping`
    fn ping(&self) -> Result<AppletPingOutcome>;
    /// `ak.edge.applet.read.describe.v1` — `GET /_arkret/edge/applet/describe`
    fn describe(&self) -> Result<ServiceDescribe>;
    /// `ak.edge.applet.command.transaction.v1` — `POST /_arkret/edge/applet/transactions`
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
    /// `ak.edge.applet.actor.read.resolve.v1` — `GET /_arkret/edge/applet/actors/{actor_id}`
    fn resolve_actor(&self, actor_id: &str) -> Result<AppletActorView>;
    /// `ak.edge.applet.realm.read.resolve.v1` — `GET
    /// /_arkret/edge/applet/realms/{realm_id_or_alias}`
    fn resolve_realm(&self, realm_id_or_alias: &str) -> Result<AppletRealmView>;
    /// `ak.edge.applet.read.protocol_metadata.v1` — `GET /_arkret/edge/applet/protocols/{protocol}`
    fn resolve_protocol(&self, protocol: &str) -> Result<AppletProtocolMetadata>;
}
