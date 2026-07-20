//! Moderation report bodies.
//!
//! `ModerationReportRequestBody` and its evidence-package / report-outcome
//! DTOs now live in `arkret-models-collaboration` (re-exported below);
//! `FrankingProof` migrated there as well, so nothing moderation-shaped
//! remains resident in `arkret-core`.

pub use arkret_models_collaboration::governance::moderation::*;
