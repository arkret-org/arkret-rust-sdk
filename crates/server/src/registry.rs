use std::collections::BTreeMap;

use arkret_wire::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceRoute {
    pub operation_id: &'static str,
    pub method: &'static str,
    pub path: &'static str,
}

/// Lower-case the registry's HTTP method for route matching.
///
/// The arm list is explicit rather than a blanket `to_ascii_lowercase` because
/// these are `&'static str`. `QUERY` (RFC 10008) joined the set when the Events
/// read operations moved to it; without an arm it fell through unchanged and no
/// longer matched the lower-cased registry side.
fn route_method(method: &'static str) -> &'static str {
    match method {
        "DELETE" => "delete",
        "GET" => "get",
        "HEAD" => "head",
        "POST" => "post",
        "PUT" => "put",
        "QUERY" => "query",
        _ => method,
    }
}

static SERVICE_ROUTES: std::sync::LazyLock<Vec<ServiceRoute>> = std::sync::LazyLock::new(|| {
    arkret_wire::SERVICE_OPERATION_DESCRIPTORS
        .iter()
        .map(|descriptor| ServiceRoute {
            operation_id: descriptor.id.as_str(),
            method: route_method(descriptor.http_method),
            path: descriptor.http_path,
        })
        .collect()
});

pub(crate) fn service_routes() -> &'static [ServiceRoute] {
    SERVICE_ROUTES.as_slice()
}

pub fn reject_query_auth(parameters: &BTreeMap<String, String>) -> Result<()> {
    for name in parameters.keys() {
        if arkret_wire::is_query_auth_parameter(name) {
            return Err(arkret_wire::Error::Protocol(
                "authentication material must be sent in headers, not query parameters".to_owned(),
            ));
        }
    }
    Ok(())
}
