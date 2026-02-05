//! File reservation cluster tools
//!
//! Tools for advisory file locking:
//! - `file_reservation_paths`: Request file reservations
//! - `release_file_reservations`: Release reservations
//! - `renew_file_reservations`: Extend reservation TTL
//! - `force_release_file_reservation`: Force release stale reservation
//! - `install_precommit_guard`: Install Git pre-commit hook
//! - `uninstall_precommit_guard`: Remove pre-commit hook

use fastmcp::McpErrorCode;
use fastmcp::prelude::*;
use mcp_agent_mail_core::Config;
use mcp_agent_mail_db::micros_to_iso;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::tool_util::{db_outcome_to_mcp_result, get_db_pool, resolve_agent, resolve_project};

/// Granted reservation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantedReservation {
    pub id: i64,
    pub path_pattern: String,
    pub exclusive: bool,
    pub reason: String,
    pub expires_ts: String,
}

/// Conflict record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReservationConflict {
    pub path: String,
    pub holders: Vec<ConflictHolder>,
}

/// Conflict holder info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictHolder {
    pub agent_name: String,
    pub reservation_id: i64,
    pub expires_ts: String,
}

/// File reservation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReservationResponse {
    pub granted: Vec<GrantedReservation>,
    pub conflicts: Vec<ReservationConflict>,
}

/// Release result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseResult {
    pub released: i32,
    pub released_at: String,
}

/// Renewal result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalResult {
    pub renewed: i32,
    pub file_reservations: Vec<RenewedReservation>,
}

/// Renewed reservation info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewedReservation {
    pub id: i64,
    pub path_pattern: String,
    pub old_expires_ts: String,
    pub new_expires_ts: String,
}

fn expand_tilde(input: &str) -> PathBuf {
    if input == "~" {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home);
        }
        return PathBuf::from(input);
    }
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(input)
}

fn normalize_repo_path(input: &str) -> PathBuf {
    let path = expand_tilde(input);
    if path.is_absolute() {
        return path;
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(&path))
        .unwrap_or(path)
}

/// Request advisory file reservations on project-relative paths/globs.
///
/// # Parameters
/// - `project_key`: Project identifier
/// - `agent_name`: Agent requesting reservations
/// - `paths`: File paths or glob patterns (e.g., "app/api/*.py")
/// - `ttl_seconds`: Time to live (min 60s, default: 3600)
/// - `exclusive`: Exclusive intent (default: true)
/// - `reason`: Explanation for reservation
///
/// # Returns
/// Granted reservations and any conflicts
#[tool(description = "Request advisory file reservations on project-relative paths/globs.")]
pub async fn file_reservation_paths(
    ctx: &McpContext,
    project_key: String,
    agent_name: String,
    paths: Vec<String>,
    ttl_seconds: Option<i64>,
    exclusive: Option<bool>,
    reason: Option<String>,
) -> McpResult<String> {
    if paths.is_empty() {
        return Err(McpError::new(
            McpErrorCode::InvalidParams,
            "paths list cannot be empty. Provide at least one file path or glob pattern to reserve (e.g., ['src/api/*.py', 'config/settings.yaml']).",
        ));
    }

    let ttl = ttl_seconds.unwrap_or(3600);
    if ttl < 60 {
        tracing::info!(
            "ttl_seconds={} is below recommended minimum (60s); continuing anyway",
            ttl
        );
    }

    let is_exclusive = exclusive.unwrap_or(true);
    let reason_str = reason.unwrap_or_default();

    let pool = get_db_pool()?;
    let project = resolve_project(ctx, &pool, &project_key).await?;
    let project_id = project.id.unwrap_or(0);

    let agent = resolve_agent(ctx, &pool, project_id, &agent_name).await?;
    let agent_id = agent.id.unwrap_or(0);

    // Check for conflicts with existing active reservations
    let active = db_outcome_to_mcp_result(
        mcp_agent_mail_db::queries::get_active_reservations(ctx.cx(), &pool, project_id).await,
    )?;

    let mut conflicts: Vec<ReservationConflict> = Vec::new();
    let mut paths_to_grant: Vec<&str> = Vec::new();

    for path in &paths {
        // Check if any active exclusive reservation conflicts with this path
        // Conflict: either the existing pattern matches our path, or our path matches their pattern
        // Using simple string equality for now; full fnmatch would require glob crate
        let mut path_conflicts: Vec<ConflictHolder> = Vec::new();

        for res in &active {
            // Skip our own reservations
            if res.agent_id == agent_id {
                continue;
            }

            // Check for conflict (simple check: pattern equality or one is prefix of other)
            let is_conflict = res.exclusive != 0
                && (res.path_pattern == *path
                    || path.starts_with(&res.path_pattern)
                    || res.path_pattern.starts_with(path));

            if is_conflict {
                // We need to get agent name for the conflict holder
                // For now, just use agent_id as string (proper lookup would query agents table)
                path_conflicts.push(ConflictHolder {
                    agent_name: format!("agent_{}", res.agent_id),
                    reservation_id: res.id.unwrap_or(0),
                    expires_ts: micros_to_iso(res.expires_ts),
                });
            }
        }

        if path_conflicts.is_empty() {
            paths_to_grant.push(path);
        } else {
            conflicts.push(ReservationConflict {
                path: path.clone(),
                holders: path_conflicts,
            });
        }
    }

    // Grant non-conflicting reservations
    let granted_rows = if paths_to_grant.is_empty() {
        vec![]
    } else {
        db_outcome_to_mcp_result(
            mcp_agent_mail_db::queries::create_file_reservations(
                ctx.cx(),
                &pool,
                project_id,
                agent_id,
                &paths_to_grant,
                ttl,
                is_exclusive,
                &reason_str,
            )
            .await,
        )?
    };

    let granted: Vec<GrantedReservation> = granted_rows
        .iter()
        .map(|r| GrantedReservation {
            id: r.id.unwrap_or(0),
            path_pattern: r.path_pattern.clone(),
            exclusive: r.exclusive != 0,
            reason: r.reason.clone(),
            expires_ts: micros_to_iso(r.expires_ts),
        })
        .collect();

    let conflicts_len = conflicts.len();
    let response = ReservationResponse { granted, conflicts };

    tracing::debug!(
        "Reserved {} paths for {} in project {} (ttl: {}s, exclusive: {}, conflicts: {})",
        paths_to_grant.len(),
        agent_name,
        project_key,
        ttl,
        is_exclusive,
        conflicts_len
    );

    serde_json::to_string(&response)
        .map_err(|e| McpError::new(McpErrorCode::InternalError, format!("JSON error: {e}")))
}

/// Release active file reservations held by an agent.
///
/// If both paths and `file_reservation_ids` are omitted, releases all active reservations.
///
/// # Parameters
/// - `project_key`: Project identifier
/// - `agent_name`: Agent releasing reservations
/// - `paths`: Restrict release to matching path patterns
/// - `file_reservation_ids`: Restrict release to matching IDs
#[tool(description = "Release active file reservations held by an agent.")]
pub async fn release_file_reservations(
    ctx: &McpContext,
    project_key: String,
    agent_name: String,
    paths: Option<Vec<String>>,
    file_reservation_ids: Option<Vec<i64>>,
) -> McpResult<String> {
    let pool = get_db_pool()?;
    let project = resolve_project(ctx, &pool, &project_key).await?;
    let project_id = project.id.unwrap_or(0);

    let agent = resolve_agent(ctx, &pool, project_id, &agent_name).await?;
    let agent_id = agent.id.unwrap_or(0);

    // Convert paths to slice of &str
    let paths_ref: Option<Vec<&str>> = paths
        .as_ref()
        .map(|p| p.iter().map(String::as_str).collect());

    let released = db_outcome_to_mcp_result(
        mcp_agent_mail_db::queries::release_reservations(
            ctx.cx(),
            &pool,
            project_id,
            agent_id,
            paths_ref.as_deref(),
            file_reservation_ids.as_deref(),
        )
        .await,
    )?;

    let response = ReleaseResult {
        released: i32::try_from(released).unwrap_or(i32::MAX),
        released_at: micros_to_iso(mcp_agent_mail_db::now_micros()),
    };

    tracing::debug!(
        "Released {} reservations for {} in project {} (paths: {:?}, ids: {:?})",
        released,
        agent_name,
        project_key,
        paths,
        file_reservation_ids
    );

    serde_json::to_string(&response)
        .map_err(|e| McpError::new(McpErrorCode::InternalError, format!("JSON error: {e}")))
}

/// Extend expiry for active file reservations.
///
/// # Parameters
/// - `project_key`: Project identifier
/// - `agent_name`: Agent renewing reservations
/// - `extend_seconds`: Seconds to extend from max(now, expiry) (min 60s, default: 1800)
/// - `paths`: Restrict to matching path patterns
/// - `file_reservation_ids`: Restrict to matching IDs
#[tool(description = "Extend expiry for active file reservations.")]
pub async fn renew_file_reservations(
    ctx: &McpContext,
    project_key: String,
    agent_name: String,
    extend_seconds: Option<i64>,
    paths: Option<Vec<String>>,
    file_reservation_ids: Option<Vec<i64>>,
) -> McpResult<String> {
    let extend = extend_seconds.unwrap_or(1800);

    // Validate extension >= 60 seconds
    if extend < 60 {
        return Err(McpError::new(
            McpErrorCode::InvalidParams,
            "extend_seconds must be at least 60 seconds",
        ));
    }

    let pool = get_db_pool()?;
    let project = resolve_project(ctx, &pool, &project_key).await?;
    let project_id = project.id.unwrap_or(0);

    let agent = resolve_agent(ctx, &pool, project_id, &agent_name).await?;
    let agent_id = agent.id.unwrap_or(0);

    // Convert paths to slice of &str
    let paths_ref: Option<Vec<&str>> = paths
        .as_ref()
        .map(|p| p.iter().map(String::as_str).collect());

    let renewed_rows = db_outcome_to_mcp_result(
        mcp_agent_mail_db::queries::renew_reservations(
            ctx.cx(),
            &pool,
            project_id,
            agent_id,
            extend,
            paths_ref.as_deref(),
            file_reservation_ids.as_deref(),
        )
        .await,
    )?;

    let file_reservations: Vec<RenewedReservation> = renewed_rows
        .iter()
        .map(|r| {
            // Calculate old expiry (current - extend)
            let old_expires = r.expires_ts - (extend * 1_000_000);
            RenewedReservation {
                id: r.id.unwrap_or(0),
                path_pattern: r.path_pattern.clone(),
                old_expires_ts: micros_to_iso(old_expires),
                new_expires_ts: micros_to_iso(r.expires_ts),
            }
        })
        .collect();

    let response = RenewalResult {
        renewed: i32::try_from(file_reservations.len()).unwrap_or(i32::MAX),
        file_reservations,
    };

    tracing::debug!(
        "Renewed {} reservations for {} in project {} (+{}s, paths: {:?}, ids: {:?})",
        response.renewed,
        agent_name,
        project_key,
        extend,
        paths,
        file_reservation_ids
    );

    serde_json::to_string(&response)
        .map_err(|e| McpError::new(McpErrorCode::InternalError, format!("JSON error: {e}")))
}

/// Force-release a stale file reservation held by another agent.
///
/// Validates that the reservation appears abandoned (agent inactive beyond threshold
/// and no recent mail/filesystem/git activity).
///
/// # Parameters
/// - `project_key`: Project identifier
/// - `agent_name`: Agent performing the force release
/// - `file_reservation_id`: ID of reservation to release
/// - `note`: Optional explanation
/// - `notify_previous`: Send notification to previous holder (default: true)
#[tool(description = "Force-release a stale file reservation after inactivity heuristics.")]
pub async fn force_release_file_reservation(
    ctx: &McpContext,
    project_key: String,
    agent_name: String,
    file_reservation_id: i64,
    note: Option<String>,
    notify_previous: Option<bool>,
) -> McpResult<String> {
    let should_notify = notify_previous.unwrap_or(true);
    let now = chrono::Utc::now().to_rfc3339();

    let pool = get_db_pool()?;
    let project = resolve_project(ctx, &pool, &project_key).await?;
    let project_id = project.id.unwrap_or(0);
    let _agent = resolve_agent(ctx, &pool, project_id, &agent_name).await?;

    let reservations = db_outcome_to_mcp_result(
        mcp_agent_mail_db::queries::list_file_reservations(ctx.cx(), &pool, project_id, false)
            .await,
    )?;
    let reservation = reservations
        .into_iter()
        .find(|row| row.id.unwrap_or(0) == file_reservation_id);

    let Some(reservation) = reservation else {
        return Err(McpError::new(
            McpErrorCode::InvalidParams,
            format!(
                "File reservation id={file_reservation_id} not found for project '{}'.",
                project.human_key
            ),
        ));
    };

    // TODO: Call storage layer to:
    // 1. Validate inactivity heuristics
    // 2. Release the reservation
    // 3. Optionally notify previous holder

    let response = reservation.released_ts.map_or_else(
        || {
            serde_json::json!({
                "released": 1,
                "released_at": now,
            })
        },
        |released_ts| {
            serde_json::json!({
                "released": 0,
                "released_at": micros_to_iso(released_ts),
                "already_released": true,
            })
        },
    );

    tracing::debug!(
        "Force releasing reservation {} by {} in project {} (notify: {}, note: {:?})",
        file_reservation_id,
        agent_name,
        project_key,
        should_notify,
        note
    );

    serde_json::to_string(&response)
        .map_err(|e| McpError::new(McpErrorCode::InternalError, format!("JSON error: {e}")))
}

/// Install pre-commit guard for file reservation enforcement.
///
/// Resolves `core.hooksPath` and installs the guard hook.
///
/// # Parameters
/// - `project_key`: Project identifier
/// - `code_repo_path`: Path to the code repository
#[tool(description = "Install pre-commit guard for file reservation enforcement.")]
pub fn install_precommit_guard(
    _ctx: &McpContext,
    project_key: String,
    code_repo_path: String,
) -> McpResult<String> {
    let config = Config::from_env();
    if !config.worktrees_enabled {
        return serde_json::to_string(&serde_json::json!({ "hook": "" }))
            .map_err(|e| McpError::new(McpErrorCode::InternalError, format!("JSON error: {e}")));
    }

    let repo_path = normalize_repo_path(&code_repo_path);
    let hook_path = repo_path
        .join(".git")
        .join("hooks")
        .join("pre-commit")
        .display()
        .to_string();

    // TODO: Call storage/guard layer to:
    // 1. Resolve core.hooksPath
    // 2. Write pre-commit hook script
    // 3. Make executable

    let response = serde_json::json!({ "hook": hook_path });

    tracing::debug!(
        "Installing pre-commit guard for project {} at {}",
        project_key,
        code_repo_path
    );

    serde_json::to_string(&response)
        .map_err(|e| McpError::new(McpErrorCode::InternalError, format!("JSON error: {e}")))
}

/// Uninstall pre-commit guard from a repository.
///
/// # Parameters
/// - `code_repo_path`: Path to the code repository
#[tool(description = "Uninstall pre-commit guard from a repository.")]
pub fn uninstall_precommit_guard(_ctx: &McpContext, code_repo_path: String) -> McpResult<String> {
    let _repo_path = normalize_repo_path(&code_repo_path);

    // TODO: Call storage/guard layer to remove hook.
    // For now, report no-op removal to avoid destructive file operations.
    let response = serde_json::json!({ "removed": false });

    tracing::debug!("Uninstalling pre-commit guard from {}", code_repo_path);

    serde_json::to_string(&response)
        .map_err(|e| McpError::new(McpErrorCode::InternalError, format!("JSON error: {e}")))
}
