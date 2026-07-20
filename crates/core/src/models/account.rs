//! Account wire models re-exported by `arkret-core`.
//!
//! The identity-face account shapes live in `arkret-models-identity`; the
//! consent-cell (`ConsentScope`), session-grant selector (`EffectiveScope`),
//! profile-patch, account-status, and handle-claim entangled shapes moved to
//! `arkret-models-collaboration` (`account_lifecycle`). Both are re-exported
//! here to keep the `arkret_core::models` account path stable.

pub use arkret_models_collaboration::account_lifecycle::*;
pub use arkret_models_identity::account::*;
