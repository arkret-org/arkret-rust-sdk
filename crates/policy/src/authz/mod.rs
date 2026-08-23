//! Capability-based authorization: constraints, evaluation primitives, the
//! grant authority-chain helpers, and owner-authority shortcuts.

use crate::{Result, WireError};

pub mod authority;
mod constraints;
mod grants;
mod owner_authority;

pub use constraints::*;
pub use grants::*;
pub use owner_authority::*;
