//! HTTP wrappers that remain outside the public Realm directory DTO surface.

use serde::{Deserialize, Serialize};

use crate::service_description::ServiceDescribe;

/// Transparent wrapper over `ServiceDescribe` for
/// `ak.gate.service.read.describe` HTTP bindings.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerDescribeOutcome(pub ServiceDescribe);
