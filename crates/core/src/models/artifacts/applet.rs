//! Applet leaf artifact shapes and widget declaration shapes (`Widget`,
//! `WidgetTokenScope`) migrated to `arkret-models-integration`
//! (`artifacts_applet`), re-exported here for path stability.
//!
//! The cross-domain applet operation aggregator enums that previously lived
//! here (AppletEdgeOperations, AppletInstallOperations) had no runtime consumer
//! and were removed. Schema coverage is preserved by `arkret-schema`, which
//! mirrors the spec JSON artifacts directly.

pub use arkret_models_integration::artifacts_applet::*;
