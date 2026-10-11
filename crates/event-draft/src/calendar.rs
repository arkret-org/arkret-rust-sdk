//! Calendar RSVP authoring.
//!
//! This layer validates the RSVP payload before it is placed in the minimal
//! producer Event envelope. Schedule dependencies name exact committed Events;
//! authority ordering is assigned later by the current governance Station.

use arkret_models_collaboration::objects::calendar_projection::CalendarScheduleProjection;
use arkret_models_collaboration::objects::productivity::{
    CalendarEventFields, CalendarStatus, RsvpEntry, RsvpResponse, RsvpSetPayload,
};
use arkret_wire::{EventId, Result, StrandId, WireError};

/// Schedule revision winner the responder observed, plus the response itself.
///
/// The wire field remains an array, but it MUST contain exactly the committed
/// Event ID for the deterministic schedule winner.
#[derive(Clone, Debug)]
pub struct RsvpAuthoring {
    pub event_ref: StrandId,
    /// `None` responds to the whole series. For a non-recurring calendar this
    /// is the only legal value, so the same event never has both a series and
    /// a base-instance response key.
    pub occurrence: Option<String>,
    pub schedule_basis_refs: Vec<EventId>,
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
    /// non-canonical instance key and address a different response record.
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
        if schedule_basis_refs.len() != 1
            || schedule_basis_refs[0].event_digest() != schedule.schedule_revision_source
        {
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
