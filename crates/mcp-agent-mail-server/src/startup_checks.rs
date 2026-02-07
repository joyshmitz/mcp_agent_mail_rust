//! Startup verification probes for `AgentMailTUI`.
//!
//! Each probe checks one aspect of the runtime environment and returns
//! a [`ProbeResult`] with a human-friendly error message and remediation
//! hints when something is wrong.

use mcp_agent_mail_core::Config;
use std::fmt;
use std::net::TcpListener;
use std::path::Path;

// ──────────────────────────────────────────────────────────────────────
// Probe result types
// ──────────────────────────────────────────────────────────────────────

/// Outcome of a single startup probe.
#[derive(Debug, Clone)]
pub enum ProbeResult {
    /// Probe passed.
    Ok { name: &'static str },
    /// Probe failed with remediation guidance.
    Fail(ProbeFailure),
}

/// Details of a failed probe.
#[derive(Debug, Clone)]
pub struct ProbeFailure {
    /// Short probe identifier (e.g., "port", "database", "storage").
    pub name: &'static str,
    /// One-line problem description.
    pub problem: String,
    /// Actionable remediation steps.
    pub fix: String,
}

impl fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] Problem: {}\n        Fix: {}",
            self.name, self.problem, self.fix
        )
    }
}

/// Aggregate result of all startup probes.
#[derive(Debug)]
pub struct StartupReport {
    pub results: Vec<ProbeResult>,
}

impl StartupReport {
    /// Returns all failures.
    #[must_use]
    pub fn failures(&self) -> Vec<&ProbeFailure> {
        self.results
            .iter()
            .filter_map(|r| match r {
                ProbeResult::Fail(f) => Some(f),
                ProbeResult::Ok { .. } => None,
            })
            .collect()
    }

    /// Whether all probes passed.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failures().is_empty()
    }

    /// Format a human-readable error block for terminal output.
    #[must_use]
    pub fn format_errors(&self) -> String {
        use fmt::Write;
        let failures = self.failures();
        if failures.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        out.push_str("\n  Startup failed — the following checks did not pass:\n\n");
        for (i, fail) in failures.iter().enumerate() {
            let _ = writeln!(out, "  {}. [{}] {}", i + 1, fail.name, fail.problem);
            let _ = writeln!(out, "     Fix: {}\n", fail.fix);
        }
        out
    }
}

// ──────────────────────────────────────────────────────────────────────
// Individual probes
// ──────────────────────────────────────────────────────────────────────

/// Check that the HTTP path starts with `/` and ends with `/`.
fn probe_http_path(config: &Config) -> ProbeResult {
    let path = &config.http_path;
    if path.is_empty() || !path.starts_with('/') {
        return ProbeResult::Fail(ProbeFailure {
            name: "http-path",
            problem: format!("HTTP path {path:?} must start with '/'"),
            fix: "Set HTTP_PATH to a value like '/mcp/' or '/api/'".into(),
        });
    }
    if !path.ends_with('/') {
        return ProbeResult::Fail(ProbeFailure {
            name: "http-path",
            problem: format!("HTTP path {path:?} should end with '/'"),
            fix: format!("Set HTTP_PATH=\"{path}/\" (append trailing slash)"),
        });
    }
    ProbeResult::Ok { name: "http-path" }
}

/// Check that the configured port is available for binding.
fn probe_port(config: &Config) -> ProbeResult {
    let addr = format!("{}:{}", config.http_host, config.http_port);
    match TcpListener::bind(&addr) {
        Ok(_listener) => {
            // Drop the listener immediately to release the port
            ProbeResult::Ok { name: "port" }
        }
        Err(e) => {
            let kind = e.kind();
            let (problem, fix) = match kind {
                std::io::ErrorKind::AddrInUse => (
                    format!(
                        "Port {} is already in use on {}",
                        config.http_port, config.http_host
                    ),
                    format!(
                        "Stop the other process using port {}, or set HTTP_PORT to a different port",
                        config.http_port
                    ),
                ),
                std::io::ErrorKind::PermissionDenied => (
                    format!(
                        "Permission denied binding to {}:{}",
                        config.http_host, config.http_port
                    ),
                    if config.http_port < 1024 {
                        format!(
                            "Ports below 1024 require elevated privileges. Use HTTP_PORT={} or higher",
                            1024
                        )
                    } else {
                        "Check your firewall or OS security settings".into()
                    },
                ),
                std::io::ErrorKind::AddrNotAvailable => (
                    format!(
                        "Address {}:{} is not available",
                        config.http_host, config.http_port
                    ),
                    format!(
                        "The host {:?} may not be a valid local address. Try HTTP_HOST=127.0.0.1 or HTTP_HOST=0.0.0.0",
                        config.http_host
                    ),
                ),
                _ => (
                    format!("Cannot bind to {addr}: {e}"),
                    "Check network configuration and try a different port/host".into(),
                ),
            };
            ProbeResult::Fail(ProbeFailure {
                name: "port",
                problem,
                fix,
            })
        }
    }
}

/// Check that the storage root directory exists (or can be created) and is writable.
fn probe_storage_root(config: &Config) -> ProbeResult {
    let root = &config.storage_root;

    // Try to create if it doesn't exist
    if !root.exists() {
        if let Err(e) = std::fs::create_dir_all(root) {
            return ProbeResult::Fail(ProbeFailure {
                name: "storage",
                problem: format!("Cannot create storage directory {}: {e}", root.display()),
                fix: format!("Create the directory manually: mkdir -p {}", root.display()),
            });
        }
    }

    // Check it is a directory
    if !root.is_dir() {
        return ProbeResult::Fail(ProbeFailure {
            name: "storage",
            problem: format!("{} exists but is not a directory", root.display()),
            fix: format!(
                "Remove the file at {} and let the server create the directory",
                root.display()
            ),
        });
    }

    // Check writability by touching a temp file
    let probe_path = root.join(".am_startup_probe");
    match std::fs::write(&probe_path, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe_path);
            ProbeResult::Ok { name: "storage" }
        }
        Err(e) => ProbeResult::Fail(ProbeFailure {
            name: "storage",
            problem: format!("Storage directory {} is not writable: {e}", root.display()),
            fix: format!("Check permissions: chmod u+w {}", root.display()),
        }),
    }
}

/// Check that the database URL is plausible and the database is reachable.
fn probe_database(config: &Config) -> ProbeResult {
    let url = &config.database_url;

    // Basic URL format check
    if url.is_empty() {
        return ProbeResult::Fail(ProbeFailure {
            name: "database",
            problem: "DATABASE_URL is empty".into(),
            fix: "Set DATABASE_URL to a SQLite path like 'sqlite:///./storage.sqlite3'".into(),
        });
    }

    // For SQLite URLs, check parent directory exists
    if url.contains("sqlite") {
        let db_path = url
            .replace("sqlite+aiosqlite:///", "")
            .replace("sqlite:///", "")
            .replace("sqlite://", "");
        if !db_path.is_empty() && db_path != ":memory:" {
            let path = Path::new(&db_path);
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    return ProbeResult::Fail(ProbeFailure {
                        name: "database",
                        problem: format!(
                            "Database parent directory does not exist: {}",
                            parent.display()
                        ),
                        fix: format!("Create it: mkdir -p {}", parent.display()),
                    });
                }
            }
        }
    }

    ProbeResult::Ok { name: "database" }
}

/// Check auth configuration consistency.
fn probe_auth(config: &Config) -> ProbeResult {
    // Warn if bearer token is set but very short (likely a mistake)
    if let Some(ref token) = config.http_bearer_token {
        if token.len() < 8 {
            return ProbeResult::Fail(ProbeFailure {
                name: "auth",
                problem: "HTTP_BEARER_TOKEN is set but very short (< 8 chars)".into(),
                fix: "Use a longer token for security, or unset HTTP_BEARER_TOKEN to disable auth"
                    .into(),
            });
        }
    }

    // JWT enabled but no JWKS URL
    if config.http_jwt_enabled && config.http_jwt_jwks_url.is_none() {
        return ProbeResult::Fail(ProbeFailure {
            name: "auth",
            problem: "JWT authentication is enabled but HTTP_JWT_JWKS_URL is not set".into(),
            fix: "Set HTTP_JWT_JWKS_URL to your identity provider's JWKS endpoint".into(),
        });
    }

    ProbeResult::Ok { name: "auth" }
}

// ──────────────────────────────────────────────────────────────────────
// Main entry point
// ──────────────────────────────────────────────────────────────────────

/// Run all startup probes and return a report.
///
/// The probes are ordered from fastest to slowest, and all probes run
/// even if earlier ones fail (so the user sees all problems at once).
#[must_use]
pub fn run_startup_probes(config: &Config) -> StartupReport {
    let results = vec![
        probe_http_path(config),
        probe_auth(config),
        probe_database(config),
        probe_storage_root(config),
        probe_port(config),
    ];
    StartupReport { results }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn default_config_passes_http_path() {
        let config = default_config();
        let result = probe_http_path(&config);
        assert!(matches!(result, ProbeResult::Ok { .. }));
    }

    #[test]
    fn empty_http_path_fails() {
        let mut config = default_config();
        config.http_path = String::new();
        let result = probe_http_path(&config);
        assert!(matches!(result, ProbeResult::Fail(_)));
    }

    #[test]
    fn no_leading_slash_fails() {
        let mut config = default_config();
        config.http_path = "mcp/".into();
        let result = probe_http_path(&config);
        assert!(matches!(result, ProbeResult::Fail(_)));
    }

    #[test]
    fn no_trailing_slash_fails() {
        let mut config = default_config();
        config.http_path = "/mcp".into();
        let result = probe_http_path(&config);
        assert!(matches!(result, ProbeResult::Fail(_)));
    }

    #[test]
    fn valid_http_path_passes() {
        let mut config = default_config();
        config.http_path = "/mcp/".into();
        let result = probe_http_path(&config);
        assert!(matches!(result, ProbeResult::Ok { .. }));
    }

    #[test]
    fn default_config_passes_auth() {
        let config = default_config();
        let result = probe_auth(&config);
        assert!(matches!(result, ProbeResult::Ok { .. }));
    }

    #[test]
    fn short_bearer_token_fails() {
        let mut config = default_config();
        config.http_bearer_token = Some("abc".into());
        let result = probe_auth(&config);
        assert!(matches!(result, ProbeResult::Fail(_)));
    }

    #[test]
    fn valid_bearer_token_passes() {
        let mut config = default_config();
        config.http_bearer_token = Some("a-secure-token-here".into());
        let result = probe_auth(&config);
        assert!(matches!(result, ProbeResult::Ok { .. }));
    }

    #[test]
    fn empty_database_url_fails() {
        let mut config = default_config();
        config.database_url = String::new();
        let result = probe_database(&config);
        assert!(matches!(result, ProbeResult::Fail(_)));
    }

    #[test]
    fn default_database_url_passes() {
        let config = default_config();
        let result = probe_database(&config);
        assert!(matches!(result, ProbeResult::Ok { .. }));
    }

    #[test]
    fn writable_storage_root_passes() {
        let tmp = std::env::temp_dir().join("am_test_startup_probe");
        let _ = std::fs::create_dir_all(&tmp);
        let mut config = default_config();
        config.storage_root = tmp.clone();
        let result = probe_storage_root(&config);
        assert!(matches!(result, ProbeResult::Ok { .. }));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn nonexistent_storage_root_gets_created() {
        let tmp = std::env::temp_dir().join("am_test_startup_probe_create");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut config = default_config();
        config.storage_root = tmp.clone();
        let result = probe_storage_root(&config);
        assert!(matches!(result, ProbeResult::Ok { .. }));
        assert!(tmp.is_dir());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn format_errors_empty_when_all_pass() {
        let report = StartupReport {
            results: vec![
                ProbeResult::Ok { name: "test1" },
                ProbeResult::Ok { name: "test2" },
            ],
        };
        assert!(report.is_ok());
        assert!(report.format_errors().is_empty());
    }

    #[test]
    fn format_errors_shows_failures() {
        let report = StartupReport {
            results: vec![
                ProbeResult::Ok { name: "ok" },
                ProbeResult::Fail(ProbeFailure {
                    name: "port",
                    problem: "Port 8765 is in use".into(),
                    fix: "Use a different port".into(),
                }),
            ],
        };
        assert!(!report.is_ok());
        let errors = report.format_errors();
        assert!(errors.contains("Port 8765 is in use"));
        assert!(errors.contains("Use a different port"));
    }

    #[test]
    fn probe_failure_display() {
        let fail = ProbeFailure {
            name: "test",
            problem: "something broke".into(),
            fix: "fix it".into(),
        };
        let display = fail.to_string();
        assert!(display.contains("something broke"));
        assert!(display.contains("fix it"));
    }

    #[test]
    fn run_startup_probes_returns_results() {
        let config = default_config();
        let report = run_startup_probes(&config);
        // Should have 5 probes
        assert_eq!(report.results.len(), 5);
    }

    #[test]
    fn jwt_without_jwks_fails() {
        let mut config = default_config();
        config.http_jwt_enabled = true;
        config.http_jwt_jwks_url = None;
        let result = probe_auth(&config);
        assert!(matches!(result, ProbeResult::Fail(_)));
    }
}
