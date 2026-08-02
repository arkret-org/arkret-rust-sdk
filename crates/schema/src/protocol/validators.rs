pub(crate) fn is_security_sensitive_extension(field: &str) -> bool {
    matches!(
        field,
        "x-authz"
            | "x-policy"
            | "x-security"
            | "x-arkret-authz"
            | "x-arkret-policy"
            | "x-arkret-security"
    ) || field.starts_with("x-authz-")
        || field.starts_with("x-policy-")
        || field.starts_with("x-security-")
        || field.starts_with("x-arkret-authz-")
        || field.starts_with("x-arkret-policy-")
        || field.starts_with("x-arkret-security-")
}
