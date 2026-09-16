//! Canonical validator for `event-payload.schema.json#/$defs/object_ref`.

use std::sync::LazyLock;

use regex::Regex;

static OBJECT_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^((?:ak:(realm|circle|space|actor_profile|strand|message|morph|relation|view|event):[A-Za-z0-9_-]{44}|ak:(policy|grant|invite|call|blob|snapshot|franking_proof|report):[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})|ak:blob:(sha256|blake3):[0-9a-f]{64}|did:[^\s]+|(sha256|blake3):[0-9a-f]{64})$",
    )
    .expect("object_ref regex compiles")
});

#[must_use]
pub fn is_object_ref(value: &str) -> bool {
    OBJECT_REF.is_match(value)
}
