//! Object-patch payload for `event-payload.schema.json#/$defs/object_patch_payload`.
//!
//! The `ak.schema.patch.v1` container grammar (`Patch` / `PatchOp` and the
//! path / semantic-safety validators) is owned by `arkret_wire::patch`, and
//! the payload-shaped `ObjectPatchPayload` migrated to
//! `arkret-models-collaboration` (`object_patch`). Both are re-exported here
//! to preserve the `arkret_core::` path.

pub use arkret_models_collaboration::object_patch::*;
pub use arkret_wire::patch::*;
