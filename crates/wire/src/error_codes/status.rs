use super::ErrorCode;

/// Return true when code is a registered canonical error code.
pub fn is_known_error_code(code: &str) -> bool {
    ErrorCode::from_wire(code).is_some()
}

/// Return the generated HTTP status binding for a registered error code.
pub fn error_code_http_status(code: &str) -> Option<u16> {
    ErrorCode::from_wire(code).map(ErrorCode::http_status)
}
