//! MCP tools and resources implementation for MCP Agent Mail
//!
//! This crate provides implementations for all 35 MCP tools:
//! - Identity cluster (5 tools)
//! - Messaging cluster (5 tools)
//! - Contact cluster (4 tools)
//! - File reservation cluster (6 tools)
//! - Search cluster (2 tools)
//! - Macro cluster (4 tools)
//! - Product cluster (5 tools)
//! - Build slot cluster (3 tools)
//!
//! And 20+ MCP resources for read-only data access.

#![forbid(unsafe_code)]
#![allow(clippy::needless_pass_by_value)]

pub mod build_slots;
pub mod contacts;
pub mod identity;
pub mod macros;
pub mod messaging;
pub mod products;
pub mod reservations;
pub mod resources;
pub mod search;

// Re-export tool handlers for server registration
pub use build_slots::*;
pub use contacts::*;
pub use identity::*;
pub use macros::*;
pub use messaging::*;
pub use products::*;
pub use reservations::*;
pub use resources::*;
pub use search::*;

pub(crate) mod tool_util {
    use fastmcp::McpErrorCode;
    use fastmcp::prelude::*;
    use mcp_agent_mail_db::{DbError, DbPool, DbPoolConfig, get_or_create_pool};

    pub fn db_error_to_mcp_error(e: DbError) -> McpError {
        match e {
            DbError::InvalidArgument { field, message } => McpError::new(
                McpErrorCode::InvalidParams,
                format!("Invalid {field}: {message}"),
            ),
            DbError::NotFound { entity, identifier } => McpError::new(
                McpErrorCode::InvalidParams,
                format!("{entity} not found: {identifier}"),
            ),
            DbError::Duplicate { entity, identifier } => McpError::new(
                McpErrorCode::InvalidParams,
                format!("{entity} already exists: {identifier}"),
            ),
            other => McpError::new(McpErrorCode::InternalError, other.to_string()),
        }
    }

    pub fn db_outcome_to_mcp_result<T>(out: Outcome<T, DbError>) -> McpResult<T> {
        match out {
            Outcome::Ok(v) => Ok(v),
            Outcome::Err(e) => Err(db_error_to_mcp_error(e)),
            Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
            Outcome::Panicked(p) => Err(McpError::internal_error(format!(
                "Internal panic: {}",
                p.message()
            ))),
        }
    }

    pub fn get_db_pool() -> McpResult<DbPool> {
        let cfg = DbPoolConfig::from_env();
        get_or_create_pool(&cfg).map_err(|e| McpError::internal_error(e.to_string()))
    }

    pub async fn resolve_project(
        ctx: &McpContext,
        pool: &DbPool,
        project_key: &str,
    ) -> McpResult<mcp_agent_mail_db::ProjectRow> {
        let out = if project_key.starts_with('/') {
            mcp_agent_mail_db::queries::ensure_project(ctx.cx(), pool, project_key).await
        } else {
            mcp_agent_mail_db::queries::get_project_by_slug(ctx.cx(), pool, project_key).await
        };
        db_outcome_to_mcp_result(out)
    }

    pub async fn resolve_agent(
        ctx: &McpContext,
        pool: &DbPool,
        project_id: i64,
        agent_name: &str,
    ) -> McpResult<mcp_agent_mail_db::AgentRow> {
        let out =
            mcp_agent_mail_db::queries::get_agent(ctx.cx(), pool, project_id, agent_name).await;
        db_outcome_to_mcp_result(out)
    }
}

/// Tool cluster identifiers for grouping and RBAC
pub mod clusters {
    pub const IDENTITY: &str = "identity";
    pub const MESSAGING: &str = "messaging";
    pub const CONTACT: &str = "contact";
    pub const FILE_RESERVATIONS: &str = "file_reservations";
    pub const SEARCH: &str = "search";
    pub const MACROS: &str = "macros";
    pub const PRODUCT: &str = "product";
    pub const BUILD_SLOTS: &str = "build_slots";
}
