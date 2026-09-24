//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/contract-registry.json; version=2026-09-24.2;
//! sha256=6f43b967676819bc1e9c91e4d25e66225b6ebdbd62e781521c1b4689d6603c19
//! Entries: http_signature_scenarios=5, freshness_profile=ak.http_signature.freshness.v1

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HttpSignatureScenario {
    ServiceToServiceV1,
    SignalRelayV1,
    AppletTransactionV1,
    ClientSessionPopV1,
    MimiProviderV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpSignatureConditionalComponentDescriptor {
    pub component: &'static str,
    pub condition: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpSignatureScenarioDescriptor {
    pub scenario: HttpSignatureScenario,
    pub scenario_id: &'static str,
    pub extends: Option<HttpSignatureScenario>,
    pub additional_covered_components: &'static [&'static str],
    pub conditional_covered_components: &'static [HttpSignatureConditionalComponentDescriptor],
    pub required_headers: &'static [&'static str],
    pub freshness_profile_id: &'static str,
}

pub const HTTP_SIGNATURE_FRESHNESS_PROFILE_ID: &str = "ak.http_signature.freshness.v1";
pub const HTTP_SIGNATURE_MAX_LIFETIME_SECONDS: i64 = 300;
pub const HTTP_SIGNATURE_CREATED_SKEW_SECONDS: i64 = 30;
pub const HTTP_SIGNATURE_COMMON_COVERED_COMPONENTS: &[&str] =
    &["@method", "@target-uri", "@authority", "arkret-operation"];
pub const HTTP_SIGNATURE_REQUIRED_PARAMETERS: &[&str] = &["created", "expires", "keyid", "alg"];

const SERVICE_TO_SERVICE_V1_CONDITIONAL_COMPONENTS:
    &[HttpSignatureConditionalComponentDescriptor] = &[
    HttpSignatureConditionalComponentDescriptor {
        component: "content-digest",
        condition: "the request carries a body",
    },
    HttpSignatureConditionalComponentDescriptor {
        component: "source-trust-domain",
        condition: "the transaction crosses trust domains",
    },
    HttpSignatureConditionalComponentDescriptor {
        component: "destination-trust-domain",
        condition: "the transaction crosses trust domains",
    },
    HttpSignatureConditionalComponentDescriptor {
        component: "idempotency-key",
        condition: "the request participates in idempotency or replay keying",
    },
];
const SIGNAL_RELAY_V1_CONDITIONAL_COMPONENTS: &[HttpSignatureConditionalComponentDescriptor] =
    &[HttpSignatureConditionalComponentDescriptor {
        component: "destination-service-endpoint-digest",
        condition: "the destination is reached through a shared ingress",
    }];
const APPLET_TRANSACTION_V1_CONDITIONAL_COMPONENTS:
    &[HttpSignatureConditionalComponentDescriptor] = &[];
const CLIENT_SESSION_POP_V1_CONDITIONAL_COMPONENTS:
    &[HttpSignatureConditionalComponentDescriptor] = &[
    HttpSignatureConditionalComponentDescriptor {
        component: "content-digest",
        condition: "the request carries a body",
    },
    HttpSignatureConditionalComponentDescriptor {
        component: "idempotency-key",
        condition: "the request participates in idempotency or replay keying",
    },
    HttpSignatureConditionalComponentDescriptor {
        component: "x-arkret-wait-for",
        condition: "the header is present on the request",
    },
];
const MIMI_PROVIDER_V1_CONDITIONAL_COMPONENTS: &[HttpSignatureConditionalComponentDescriptor] =
    &[HttpSignatureConditionalComponentDescriptor {
        component: "mimi-room-uri",
        condition: "the endpoint addresses one MIMI room",
    }];

pub const HTTP_SIGNATURE_SCENARIOS: &[HttpSignatureScenarioDescriptor] = &[
    HttpSignatureScenarioDescriptor {
        scenario: HttpSignatureScenario::ServiceToServiceV1,
        scenario_id: "ak.http_signature.scenario.service_to_service.v1",
        extends: None,
        additional_covered_components: &["source-service-id", "destination-service-id"],
        conditional_covered_components: SERVICE_TO_SERVICE_V1_CONDITIONAL_COMPONENTS,
        required_headers: &[
            "Signature",
            "Signature-Input",
            "Arkret-Operation",
            "Source-Service-ID",
            "Destination-Service-ID",
        ],
        freshness_profile_id: "ak.http_signature.freshness.v1",
    },
    HttpSignatureScenarioDescriptor {
        scenario: HttpSignatureScenario::SignalRelayV1,
        scenario_id: "ak.http_signature.scenario.signal_relay.v1",
        extends: Some(HttpSignatureScenario::ServiceToServiceV1),
        additional_covered_components: &[
            "content-digest",
            "source-service-id",
            "destination-service-id",
            "source-trust-domain",
            "destination-trust-domain",
        ],
        conditional_covered_components: SIGNAL_RELAY_V1_CONDITIONAL_COMPONENTS,
        required_headers: &[
            "Signature",
            "Signature-Input",
            "Arkret-Operation",
            "Content-Digest",
            "Source-Service-ID",
            "Destination-Service-ID",
            "Source-Trust-Domain",
            "Destination-Trust-Domain",
        ],
        freshness_profile_id: "ak.http_signature.freshness.v1",
    },
    HttpSignatureScenarioDescriptor {
        scenario: HttpSignatureScenario::AppletTransactionV1,
        scenario_id: "ak.http_signature.scenario.applet_transaction.v1",
        extends: None,
        additional_covered_components: &[
            "content-digest",
            "source-service-id",
            "destination-service-id",
            "idempotency-key",
        ],
        conditional_covered_components: APPLET_TRANSACTION_V1_CONDITIONAL_COMPONENTS,
        required_headers: &[
            "Signature",
            "Signature-Input",
            "Arkret-Operation",
            "Content-Digest",
            "Source-Service-ID",
            "Destination-Service-ID",
            "Idempotency-Key",
        ],
        freshness_profile_id: "ak.http_signature.freshness.v1",
    },
    HttpSignatureScenarioDescriptor {
        scenario: HttpSignatureScenario::ClientSessionPopV1,
        scenario_id: "ak.http_signature.scenario.client_session_pop.v1",
        extends: None,
        additional_covered_components: &[],
        conditional_covered_components: CLIENT_SESSION_POP_V1_CONDITIONAL_COMPONENTS,
        required_headers: &[
            "Signature",
            "Signature-Input",
            "Arkret-Operation",
            "Authorization",
            "DPoP",
        ],
        freshness_profile_id: "ak.http_signature.freshness.v1",
    },
    HttpSignatureScenarioDescriptor {
        scenario: HttpSignatureScenario::MimiProviderV1,
        scenario_id: "ak.http_signature.scenario.mimi_provider.v1",
        extends: None,
        additional_covered_components: &[
            "content-digest",
            "source-service-id",
            "destination-service-id",
            "provider-id",
        ],
        conditional_covered_components: MIMI_PROVIDER_V1_CONDITIONAL_COMPONENTS,
        required_headers: &[
            "Signature",
            "Signature-Input",
            "Arkret-Operation",
            "Content-Digest",
            "Source-Service-ID",
            "Destination-Service-ID",
            "Provider-ID",
        ],
        freshness_profile_id: "ak.http_signature.freshness.v1",
    },
];

pub const fn http_signature_scenario_descriptor(
    scenario: HttpSignatureScenario,
) -> &'static HttpSignatureScenarioDescriptor {
    &HTTP_SIGNATURE_SCENARIOS[scenario as usize]
}
