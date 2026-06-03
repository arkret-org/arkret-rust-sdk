//! Authorization engine for Cokret v1 capability-based authorization.
//!
//! This module implements:
//! - Resource selector matching
//! - Constraint evaluation
//! - Grant validation and enforcement
//! - Delegation tracking

use chrono::{
    DateTime, Datelike, FixedOffset, LocalResult, NaiveDate, NaiveTime, TimeZone, Utc, Weekday,
};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{Did, Error, RealmId, Result, model::Facet};

mod approval;
mod constraints;
pub mod delegation;
mod engine;
mod grants;
mod protocol;
mod selectors;
#[cfg(test)]
mod tests;

pub use approval::*;
pub use constraints::*;
pub use engine::*;
pub use grants::*;
pub use protocol::*;
pub use selectors::*;
