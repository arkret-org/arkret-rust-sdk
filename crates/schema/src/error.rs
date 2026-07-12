use thiserror::Error;

pub type Result<T> = std::result::Result<T, SchemaError>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SchemaError {
    #[error("schema validation failed: {0}")]
    Protocol(String),
}

pub type Error = SchemaError;
