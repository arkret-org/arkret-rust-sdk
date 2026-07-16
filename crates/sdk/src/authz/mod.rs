//! Authorization engine for Arkret v1 capability-based authorization.
//!
//! This module implements:
//! - Resource selector matching
//! - Constraint evaluation
//! - Grant validation and enforcement
//! - Delegation tracking

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::Facet;
use crate::{Did, Error, RealmId, Result};

mod approval;
pub mod delegation;
mod engine;
mod grants;

pub use approval::*;
pub use arkret_core::authz::*;
pub use engine::*;
pub use grants::*;
