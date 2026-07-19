mod error_enum;

pub use arkret_wire::error_codes::*;
pub use error_enum::*;

#[cfg(test)]
mod tests;
