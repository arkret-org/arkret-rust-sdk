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
use arkret_wire::{Hash, Result, StrandId, WireError};

/// Schedule revision winner the responder observed, plus the response itself.
///
/// The wire field remains an array, but it MUST contain exactly the one
/// deterministic schedule winner and that winner MUST also be causally carried
/// by the Event envelope.
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
            return Err(WireError::Protocol(
                "calendar_event_cancelled: cannot author a new RSVP for a cancelled event"
                    .to_owned(),
            ));
        }
        if !schedule.is_available() {
            return Err(WireError::Protocol(
                "calendar_schedule_unavailable: cannot author an RSVP against an unreadable schedule winner"
                    .to_owned(),
            ));
        }
        let occurrence = calendar.canonical_occurrence_key(self.occurrence.as_deref())?;
        if occurrence.is_some() && calendar.recurrence.is_none() {
            return Err(WireError::Protocol(
                "a non-recurring calendar event only accepts a series RSVP with occurrence=null"
                    .to_owned(),
            ));
        }
        let schedule_basis_refs = self.schedule_basis_refs;
        if schedule_basis_refs.as_slice() != [schedule.schedule_revision_source.clone()] {
            return Err(WireError::Protocol(
                "rsvp schedule_basis_refs must contain exactly the deterministic schedule winner"
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
