use std::collections::BTreeMap;

use arkret_wire::Result;

pub fn reject_query_auth(parameters: &BTreeMap<String, String>) -> Result<()> {
    for name in parameters.keys() {
        if arkret_wire::is_query_auth_parameter(name) {
            return Err(arkret_wire::WireError::Protocol(
                "authentication material must be sent in headers, not query parameters".to_owned(),
            ));
        }
    }
    Ok(())
}
