//! Error types for the database layer

use thiserror::Error;

/// Database error types
#[derive(Error, Debug)]
pub enum DbError {
    /// `SQLite` error from underlying driver
    #[error("SQLite error: {0}")]
    Sqlite(String),

    /// Connection pool error
    #[error("Pool error: {0}")]
    Pool(String),

    /// Record not found
    #[error("{entity} not found: {identifier}")]
    NotFound {
        entity: &'static str,
        identifier: String,
    },

    /// Duplicate record
    #[error("{entity} already exists: {identifier}")]
    Duplicate {
        entity: &'static str,
        identifier: String,
    },

    /// Invalid argument
    #[error("Invalid {field}: {message}")]
    InvalidArgument {
        field: &'static str,
        message: String,
    },

    /// Schema/migration error
    #[error("Schema error: {0}")]
    Schema(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for database operations
pub type DbResult<T> = std::result::Result<T, DbError>;

impl DbError {
    /// Create a not found error
    pub fn not_found(entity: &'static str, identifier: impl Into<String>) -> Self {
        Self::NotFound {
            entity,
            identifier: identifier.into(),
        }
    }

    /// Create a duplicate error
    pub fn duplicate(entity: &'static str, identifier: impl Into<String>) -> Self {
        Self::Duplicate {
            entity,
            identifier: identifier.into(),
        }
    }

    /// Create an invalid argument error
    pub fn invalid(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidArgument {
            field,
            message: message.into(),
        }
    }
}

impl From<serde_json::Error> for DbError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}
