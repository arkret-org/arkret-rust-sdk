//! Calendar RSVP authoring.
//!
//! Payload half of RSVP authoring. Building the signed Event and its
//! registry-derived cell effect needs the event-kind registry, which this
//! drafting layer deliberately does not depend on; that half lives in
//! `arkret_sdk::build_rsvp_set_event`. Clients MUST use the two together and
//! MUST NOT hand-assemble the cell effect: the registry declares
//! `effect_projection = set(payload.entry)` for
//! `ak.component.calendar.rsvp.v1`, so a hand-rolled effect that omits the
//! write, targets another cell, or carries an op value that differs from the
//! payload entry is rejected by receivers with `effects_payload_mismatch`.

use arkret_models_collaboration::objects::calendar_projection::CalendarScheduleProjection;
use arkret_models_collaboration::objects::productivity::{
    CalendarEventFields, CalendarStatus, RsvpEntry, RsvpResponse, RsvpSetPayload,
};
use arkret_wire::{Error, Hash, Result, StrandId};

/// Schedule revision frontier the responder observed, plus the response itself.
///
/// `schedule_basis_refs` is canonicalized here (deduplicated and sorted in
/// ascending byte order) so the producer cannot sign an unsorted basis, which
/// the receiver would reject with `rsvp_basis_not_causal`.
#[derive(Clone, Debug)]
pub struct RsvpAuthoring {
    pub event_ref: StrandId,
    /// `None` responds to the whole series. For a non-recurring calendar this
    /// is the only legal value, so the same event never has both a series and
    /// a base-instance cell.
    pub occurrence: Option<String>,
    pub schedule_basis_refs: Vec<Hash>,
    pub response: RsvpResponseBranch,
}

/// Which response branch to author. The choice is decided by the target
/// Strand's effective scope encryption floor, never by a Calendar-specific
/// toggle: an `e2ee_required` floor admits only the encrypted branch.
#[derive(Clone, Debug)]
pub enum RsvpResponseBranch {
    Plaintext(RsvpResponse),
    Encrypted(Box<arkret_models_crypto::encrypted_envelope::EncryptedEnvelope>),
}

impl RsvpAuthoring {
    /// Builds the validated payload without touching the envelope.
    ///
    /// `calendar` is the schedule subtree of the target Strand; it is used to
    /// canonicalize `occurrence`, so a caller cannot accidentally sign a
    /// non-canonical instance key and address a different cell.
    pub fn into_payload(
        self,
        calendar: &CalendarEventFields,
        schedule: &CalendarScheduleProjection,
    ) -> Result<RsvpSetPayload> {
        calendar.validate()?;
        if calendar.status == CalendarStatus::Cancelled {
            return Err(Error::Protocol(
                "calendar_event_cancelled: cannot author a new RSVP for a cancelled event"
                    .to_owned(),
            ));
        }
        if !schedule.is_settled() {
            return Err(Error::Protocol(
                "calendar_schedule_unsettled: cannot author an RSVP against conflicting or unreadable schedule heads"
                    .to_owned(),
            ));
        }
        if schedule.schedule_revision_heads.is_empty() {
            return Err(Error::Protocol(
                "calendar_schedule_unsettled: the observed schedule frontier is empty".to_owned(),
            ));
        }
        if schedule.schedule_revision_heads.len() > 128 {
            return Err(Error::Protocol(
                "schedule_frontier_too_large: resolve the schedule frontier before responding"
                    .to_owned(),
            ));
        }
        let occurrence = calendar.canonical_occurrence_key(self.occurrence.as_deref())?;
        if occurrence.is_some() && calendar.recurrence.is_none() {
            return Err(Error::Protocol(
                "a non-recurring calendar event only accepts a series RSVP with occurrence=null"
                    .to_owned(),
            ));
        }
        let mut schedule_basis_refs = self.schedule_basis_refs;
        schedule_basis_refs.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        schedule_basis_refs.dedup_by(|left, right| left.as_str() == right.as_str());
        if schedule_basis_refs != schedule.schedule_revision_heads {
            return Err(Error::Protocol(
                "rsvp schedule_basis_refs must equal the complete observed schedule frontier"
                    .to_owned(),
            ));
        }
        let (response, encrypted_response) = match self.response {
            RsvpResponseBranch::Plaintext(response) => (Some(response), None),
            RsvpResponseBranch::Encrypted(envelope) => (None, Some(envelope)),
        };
        let payload = RsvpSetPayload {
            event_ref: self.event_ref,
            occurrence,
            entry: RsvpEntry {
                schedule_basis_refs,
                response,
                encrypted_response,
            },
        };
        payload.validate()?;
        Ok(payload)
    }
}
