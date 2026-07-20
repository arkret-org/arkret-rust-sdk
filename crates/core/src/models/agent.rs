//! Personal-Agent lifecycle wire models relocated to
//! `arkret-models-collaboration` (`agent_operations`). The requested-scope
//! commitment digest moved with them (the other agent-key digest helpers stay
//! in `crate::agent`). Re-exported here for `arkret_core::` path stability.

pub use arkret_models_collaboration::agent_operations::*;
