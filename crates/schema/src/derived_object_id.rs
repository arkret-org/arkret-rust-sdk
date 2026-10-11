//! Create-once object identity derived from the create Event.
//!
//! Object ids are not chosen by the caller. For every create Event kind whose
//! `contract-registry.json` row declares `id_source = "event_derived"`, the
//! object id is the create Event's own `event_id` retyped into the target id
//! kind: both spellings share one 33-octet token and differ only in the typed
//! prefix (`zh/models/common-fields.md` section 6.0).
//!
//! The kind-to-target table is not written here. It is read from the
//! `id-kind-registry.json` / `event-kind-registry.json` data already generated
//! into [`crate::generated::EVENT_RUNTIME_CONTRACTS`], and the set of prefixes
//! that may legally be produced is read from
//! [`arkret_wire::EVENT_DERIVED_ID_KIND_PREFIXES`], which the same registry
//! `id_form` column produces. A second hand-written table could disagree with
//! the registry; there is none.

use arkret_wire::{EVENT_DERIVED_ID_KIND_PREFIXES, EventId};

use crate::generated::{EventIdSource, event_runtime_contract};

/// The sole object id this Event kind derives, for a receiver that has the
/// envelope's `kind` and `event_id` but no parsed Event — a projection folding
/// raw sync JSON, for example.
///
/// Returns `None` for a kind whose registry row is not `event_derived`, for an
/// unregistered kind, and for a multi-output kind such as
/// `ak.self.moderation.report`, which retypes the same token into two distinct
/// typed namespaces and therefore has no single answer. Use
/// [`derived_object_ids_for_kind`] there.
pub fn derived_object_id_for_kind(kind: &str, event_id: &EventId) -> Option<String> {
    let mut ids = derived_object_ids_for_kind(kind, event_id);
    (ids.len() == 1).then(|| ids.pop().expect("length checked"))
}

/// Every object id this Event kind derives, in the registry-declared order.
///
/// A multi-output Event retypes the same 33-octet Event token into distinct
/// prefixes, so the full typed ids are distinct. Returns an empty vector for a
/// kind that derives nothing.
pub fn derived_object_ids_for_kind(kind: &str, event_id: &EventId) -> Vec<String> {
    event_derived_id_kinds_for_kind(kind)
        .iter()
        .filter_map(|id_kind| retype_event_id(event_id, id_kind))
        .collect()
}

/// Registry-declared object-id kinds derived by an Event kind.
///
/// This is the receiver-side source for the pre-schema check that must reject a
/// producer-carried object id before a closed payload schema reduces the error
/// to a generic additional-property failure. The target id kind is declared,
/// never inferred from the Event kind's middle segment: `ak.profile.create`
/// makes an `ak:actor_profile:`, and `ak.circle.create` says nothing about the
/// object it creates.
pub fn event_derived_id_kinds_for_kind(kind: &str) -> &'static [&'static str] {
    let Some(contract) = event_runtime_contract(kind) else {
        return &[];
    };
    if contract.id_source != Some(EventIdSource::EventDerived) {
        return &[];
    }
    contract.derived_id_kinds
}

/// Retype a create Event's `event_id` into one declared object-id kind.
///
/// The 33-octet Event token is shared verbatim; only the typed prefix changes.
/// The target kind MUST be one whose registry `id_form` is `event_derived` — a
/// producer-allocated kind can never be named this way, and accepting one would
/// silently mint an id nobody can re-derive.
fn retype_event_id(event_id: &EventId, id_kind: &str) -> Option<String> {
    let prefix = format!("ak:{id_kind}:");
    if !EVENT_DERIVED_ID_KIND_PREFIXES.contains(&prefix.as_str()) {
        return None;
    }
    let token = event_id.as_str().strip_prefix(EventId::KIND_PREFIX)?;
    Some(format!("{prefix}{token}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_id(seed: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
    }

    #[test]
    fn a_create_kind_retypes_its_own_event_token() {
        let event_id = event_id(0x51);
        let token = event_id
            .as_str()
            .strip_prefix(EventId::KIND_PREFIX)
            .expect("typed event id");

        for (kind, expected_prefix) in [
            ("ak.strand.create", "ak:strand:"),
            ("ak.realm.create", "ak:realm:"),
            ("ak.message.create", "ak:message:"),
            ("ak.profile.create", "ak:actor_profile:"),
            ("ak.capability.grant", "ak:grant:"),
            ("ak.invite.third_party", "ak:invite:"),
        ] {
            assert_eq!(
                derived_object_id_for_kind(kind, &event_id).as_deref(),
                Some(format!("{expected_prefix}{token}").as_str()),
                "{kind} derives {expected_prefix}"
            );
        }
    }

    #[test]
    fn a_kind_with_no_single_derived_object_yields_nothing() {
        let event_id = event_id(0x52);

        // Not an `event_derived` row: an update locates an object the caller
        // already names in the payload.
        assert_eq!(
            derived_object_id_for_kind("ak.strand.update", &event_id),
            None
        );
        // Unregistered kind.
        assert_eq!(
            derived_object_id_for_kind("ak.not.a.registered.kind", &event_id),
            None
        );
        // Two declared targets, so there is no single answer.
        assert_eq!(
            derived_object_id_for_kind("ak.self.moderation.report", &event_id),
            None
        );
    }

    #[test]
    fn a_multi_output_kind_retypes_one_token_into_each_declared_namespace() {
        let event_id = event_id(0x53);
        let token = event_id
            .as_str()
            .strip_prefix(EventId::KIND_PREFIX)
            .expect("typed event id");

        assert_eq!(
            derived_object_ids_for_kind("ak.self.moderation.report", &event_id),
            vec![
                format!("ak:report:{token}"),
                format!("ak:moderation_queue_item:{token}"),
            ]
        );
        assert!(derived_object_ids_for_kind("ak.strand.update", &event_id).is_empty());
    }
}
