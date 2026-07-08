pub mod dpop;
pub mod login;
pub mod refresh;

pub use login::{
    AgentKeyProofLogin, DidProofLogin, HolderProofLogin, LoginKind, OidcLogin, SessionProofFields,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionHandle {
    pub access_token: String,
}
