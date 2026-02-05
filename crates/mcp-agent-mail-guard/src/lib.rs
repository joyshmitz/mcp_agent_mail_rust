#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    #[error("not implemented")]
    NotImplemented,
    #[error("invalid repository path: {path}")]
    InvalidRepo { path: String },
    #[error("missing AGENT_NAME env var")]
    MissingAgentName,
    #[error("git error: {0}")]
    Git(#[from] git2::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type GuardResult<T> = Result<T, GuardError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardMode {
    Block,
    Warn,
}

impl GuardMode {
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("AGENT_MAIL_GUARD_MODE")
            .unwrap_or_else(|_| "block".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "warn" => Self::Warn,
            _ => Self::Block,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GuardStatus {
    pub worktrees_enabled: bool,
    pub guard_mode: GuardMode,
    pub hooks_dir: String,
    pub pre_commit_present: bool,
    pub pre_push_present: bool,
}

#[derive(Debug, Clone)]
pub struct GuardConflict {
    pub pattern: String,
    pub holder: String,
    pub expires_ts: String,
}

fn home_dir() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HOME") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }

    // Windows fallbacks (best-effort; tests run on Linux, but keep portable).
    if let Some(p) = std::env::var_os("USERPROFILE") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }

    let drive = std::env::var_os("HOMEDRIVE");
    let path = std::env::var_os("HOMEPATH");
    match (drive, path) {
        (Some(d), Some(p)) if !d.is_empty() && !p.is_empty() => Some(PathBuf::from(d).join(p)),
        _ => None,
    }
}

fn expand_user(path: &str) -> PathBuf {
    if path == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from("~"));
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn resolve_common_git_dir(repo: &git2::Repository) -> GuardResult<PathBuf> {
    // For worktrees, repo.path() points at .git/worktrees/<name>/.
    // The commondir file contains a relative path back to the common .git directory.
    let gitdir = repo.path();
    let commondir_path = gitdir.join("commondir");
    if commondir_path.is_file() {
        let rel = std::fs::read_to_string(commondir_path)?;
        let rel = rel.trim();
        if rel.is_empty() {
            return Ok(gitdir.to_path_buf());
        }
        let candidate = gitdir.join(rel);
        // canonicalize is nice-to-have; keep best-effort to avoid surprising errors.
        return Ok(candidate.canonicalize().unwrap_or(candidate));
    }

    Ok(gitdir.to_path_buf())
}

/// Resolve the git hooks directory for a repository, honoring `core.hooksPath`.
///
/// This is intentionally compatible with legacy semantics:
/// - Absolute `core.hooksPath` wins.
/// - Relative `core.hooksPath` is resolved against repo workdir (toplevel).
/// - Otherwise, use the common git dir's `hooks/` (handles worktrees).
pub fn resolve_hooks_dir(repo_path: &Path) -> GuardResult<PathBuf> {
    if !repo_path.exists() {
        return Err(GuardError::InvalidRepo {
            path: repo_path.display().to_string(),
        });
    }

    let repo = git2::Repository::discover(repo_path)?;
    if repo.is_bare() || repo.workdir().is_none() {
        return Err(GuardError::InvalidRepo {
            path: repo_path.display().to_string(),
        });
    }

    let config = repo.config()?;
    if let Ok(raw) = config.get_string("core.hooksPath") {
        let raw = raw.trim();
        if !raw.is_empty() {
            let expanded = expand_user(raw);
            if expanded.is_absolute() {
                return Ok(expanded);
            }

            let root = repo.workdir().unwrap_or(repo_path).to_path_buf();
            return Ok(root.join(expanded));
        }
    }

    let common_git_dir = resolve_common_git_dir(&repo)?;
    Ok(common_git_dir.join("hooks"))
}

const PLUGIN_FILE_NAME: &str = "50-agent-mail.py";

#[cfg(unix)]
fn chmod_exec(path: &Path) -> GuardResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn chmod_exec(_path: &Path) -> GuardResult<()> {
    Ok(())
}

fn is_legacy_single_file_guard(contents: &str) -> bool {
    // Legacy (pre-chain-runner) guard installs used a single hook file.
    // Keep this detection permissive and sentinel-based.
    contents.contains("mcp-agent-mail guard hook")
        || contents.contains("AGENT_NAME environment variable is required.")
}

fn render_chain_runner_script(hook_name: &str) -> String {
    // Mirrors legacy behavior: run hooks.d/<hook>/* in lexical order; forward stdin for pre-push.
    let mut lines: Vec<String> = vec![
        "#!/usr/bin/env python3".to_string(),
        format!("# mcp-agent-mail chain-runner ({hook_name})"),
        "import os".to_string(),
        "import sys".to_string(),
        "import stat".to_string(),
        "import subprocess".to_string(),
        "from pathlib import Path".to_string(),
        "".to_string(),
        "HOOK_DIR = Path(__file__).parent".to_string(),
        format!("RUN_DIR = HOOK_DIR / 'hooks.d' / '{hook_name}'"),
        format!("ORIG = HOOK_DIR / '{hook_name}.orig'"),
        "".to_string(),
        "def _is_exec(p: Path) -> bool:".to_string(),
        "    try:".to_string(),
        "        st = p.stat()".to_string(),
        "        return bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))"
            .to_string(),
        "    except Exception:".to_string(),
        "        return False".to_string(),
        "".to_string(),
        "def _list_execs() -> list[Path]:".to_string(),
        "    if not RUN_DIR.exists() or not RUN_DIR.is_dir():".to_string(),
        "        return []".to_string(),
        "    items = sorted([p for p in RUN_DIR.iterdir() if p.is_file()], key=lambda p: p.name)"
            .to_string(),
        "    # On POSIX, honor exec bit; on Windows, include all files (we'll dispatch .py via python)."
            .to_string(),
        "    if os.name == 'posix':".to_string(),
        "        try:".to_string(),
        "            items = [p for p in items if _is_exec(p)]".to_string(),
        "        except Exception:".to_string(),
        "            pass".to_string(),
        "    return items".to_string(),
        "".to_string(),
        "def _run_child(path: Path, * , stdin_bytes=None):".to_string(),
        "    # On Windows, prefer 'python' for .py plugins to avoid PATHEXT reliance.".to_string(),
        "    if os.name != 'posix' and path.suffix.lower() == '.py':".to_string(),
        "        return subprocess.run(['python', str(path)], input=stdin_bytes, check=False).returncode"
            .to_string(),
        "    return subprocess.run([str(path)], input=stdin_bytes, check=False).returncode"
            .to_string(),
        "".to_string(),
    ];

    if hook_name == "pre-push" {
        lines.extend([
            "# Read STDIN once (Git passes ref tuples); forward to children".to_string(),
            "stdin_bytes = sys.stdin.buffer.read()".to_string(),
            "for exe in _list_execs():".to_string(),
            "    rc = _run_child(exe, stdin_bytes=stdin_bytes)".to_string(),
            "    if rc != 0:".to_string(),
            "        sys.exit(rc)".to_string(),
            "".to_string(),
            "if ORIG.exists():".to_string(),
            "    rc = _run_child(ORIG, stdin_bytes=stdin_bytes)".to_string(),
            "    if rc != 0:".to_string(),
            "        sys.exit(rc)".to_string(),
            "sys.exit(0)".to_string(),
        ]);
    } else {
        lines.extend([
            "for exe in _list_execs():".to_string(),
            "    rc = _run_child(exe)".to_string(),
            "    if rc != 0:".to_string(),
            "        sys.exit(rc)".to_string(),
            "".to_string(),
            "if ORIG.exists():".to_string(),
            "    rc = _run_child(ORIG)".to_string(),
            "    if rc != 0:".to_string(),
            "        sys.exit(rc)".to_string(),
            "sys.exit(0)".to_string(),
        ]);
    }

    format!("{}\n", lines.join("\n"))
}

fn render_guard_plugin_stub(project: &str, hook_name: &str) -> String {
    // NOTE: This is a placeholder. The real implementation will live in br-2ei.3.3
    // and will block/warn based on active exclusive file reservations.
    format!(
        "#!/usr/bin/env python3\n# mcp-agent-mail guard plugin ({hook_name})\n# project: {project}\n# TODO(br-2ei.3.3): implement conflict detection\n\nimport sys\n\nsys.exit(0)\n"
    )
}

pub fn install_guard(_project: &str, repo: &Path) -> GuardResult<()> {
    if !repo.exists() {
        return Err(GuardError::InvalidRepo {
            path: repo.display().to_string(),
        });
    }

    let hooks_dir = resolve_hooks_dir(repo)?;
    std::fs::create_dir_all(&hooks_dir)?;

    // Ensure hooks.d/pre-commit exists.
    let run_dir = hooks_dir.join("hooks.d").join("pre-commit");
    std::fs::create_dir_all(&run_dir)?;

    let chain_path = hooks_dir.join("pre-commit");
    if chain_path.exists() {
        let content = std::fs::read_to_string(&chain_path).unwrap_or_default();
        let content = content.trim();
        if !content.contains("mcp-agent-mail chain-runner (pre-commit)") {
            let orig = hooks_dir.join("pre-commit.orig");
            if !orig.exists() {
                std::fs::rename(&chain_path, &orig)?;
            }
        }
    }

    // Write/overwrite chain-runner.
    let chain_script = render_chain_runner_script("pre-commit");
    std::fs::write(&chain_path, chain_script)?;
    chmod_exec(&chain_path)?;

    // Windows shims (.cmd/.ps1) to invoke the Python chain-runner.
    let cmd_path = hooks_dir.join("pre-commit.cmd");
    if !cmd_path.exists() {
        let body = "@echo off\r\nsetlocal\r\nset \"DIR=%~dp0\"\r\npython \"%DIR%pre-commit\" %*\r\nexit /b %ERRORLEVEL%\r\n";
        std::fs::write(&cmd_path, body)?;
    }
    let ps1_path = hooks_dir.join("pre-commit.ps1");
    if !ps1_path.exists() {
        let body = "$ErrorActionPreference = 'Stop'\n$hook = Join-Path $PSScriptRoot 'pre-commit'\npython $hook @args\nexit $LASTEXITCODE\n";
        std::fs::write(&ps1_path, body)?;
    }

    // Write our guard plugin (currently stubbed).
    let plugin_path = run_dir.join(PLUGIN_FILE_NAME);
    std::fs::write(
        &plugin_path,
        render_guard_plugin_stub(_project, "pre-commit"),
    )?;
    chmod_exec(&plugin_path)?;

    Ok(())
}

pub fn uninstall_guard(repo: &Path) -> GuardResult<()> {
    if !repo.exists() {
        return Err(GuardError::InvalidRepo {
            path: repo.display().to_string(),
        });
    }

    let hooks_dir = resolve_hooks_dir(repo)?;

    fn has_other_plugins(run_dir: &Path) -> bool {
        let Ok(rd) = std::fs::read_dir(run_dir) else {
            return false;
        };
        rd.filter_map(Result::ok).any(|ent| {
            let p = ent.path();
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n != PLUGIN_FILE_NAME)
                    .unwrap_or(false)
        })
    }

    // Remove our hooks.d plugins if present.
    for sub in ["pre-commit", "pre-push"] {
        let plugin = hooks_dir.join("hooks.d").join(sub).join(PLUGIN_FILE_NAME);
        if plugin.exists() {
            let _ = std::fs::remove_file(plugin);
        }
    }

    // Legacy top-level single-file uninstall (pre-chain-runner installs)
    // Only remove chain-runner if no other plugins depend on it.
    for hook_name in ["pre-commit", "pre-push"] {
        let hook_path = hooks_dir.join(hook_name);
        if !hook_path.exists() {
            continue;
        }

        let content = std::fs::read_to_string(&hook_path).unwrap_or_default();
        let content = content.trim();

        let is_chain_runner = content.contains("mcp-agent-mail chain-runner");
        let is_legacy_hook = is_legacy_single_file_guard(content);

        if is_chain_runner {
            let run_dir = hooks_dir.join("hooks.d").join(hook_name);
            let orig_path = hooks_dir.join(format!("{hook_name}.orig"));

            if has_other_plugins(&run_dir) {
                continue;
            }

            if orig_path.exists() {
                let _ = std::fs::remove_file(&hook_path);
                std::fs::rename(&orig_path, &hook_path)?;
            } else {
                let _ = std::fs::remove_file(&hook_path);
            }
        } else if is_legacy_hook {
            let _ = std::fs::remove_file(&hook_path);
        }
    }

    Ok(())
}

pub fn guard_status(_repo: &Path) -> GuardResult<GuardStatus> {
    Err(GuardError::NotImplemented)
}

pub fn guard_check(
    _repo: &Path,
    _paths: &[String],
    _advisory: bool,
) -> GuardResult<Vec<GuardConflict>> {
    Err(GuardError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn run_git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("git must run");
        assert!(
            out.status.success(),
            "git {:?} failed: {}{}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn resolve_hooks_dir_default() {
        let td = tempfile::TempDir::new().expect("tempdir");
        let repo_dir = td.path().join("repo");
        std::fs::create_dir_all(&repo_dir).expect("mkdir");
        run_git(&repo_dir, &["init", "-q"]);

        let hooks = resolve_hooks_dir(&repo_dir).expect("hooks dir");
        assert_eq!(hooks, repo_dir.join(".git").join("hooks"));
    }

    #[test]
    fn resolve_hooks_dir_core_hooks_path_absolute() {
        let td = tempfile::TempDir::new().expect("tempdir");
        let repo_dir = td.path().join("repo");
        std::fs::create_dir_all(&repo_dir).expect("mkdir");
        run_git(&repo_dir, &["init", "-q"]);

        let abs = td.path().join("alt_hooks");
        let repo = git2::Repository::discover(&repo_dir).expect("repo");
        repo.config()
            .expect("config")
            .set_str("core.hooksPath", abs.to_str().expect("utf8 path"))
            .expect("set hooksPath");

        let hooks = resolve_hooks_dir(&repo_dir).expect("hooks dir");
        assert_eq!(hooks, abs);
    }

    #[test]
    fn resolve_hooks_dir_core_hooks_path_relative() {
        let td = tempfile::TempDir::new().expect("tempdir");
        let repo_dir = td.path().join("repo");
        std::fs::create_dir_all(&repo_dir).expect("mkdir");
        run_git(&repo_dir, &["init", "-q"]);

        let repo = git2::Repository::discover(&repo_dir).expect("repo");
        repo.config()
            .expect("config")
            .set_str("core.hooksPath", ".githooks")
            .expect("set hooksPath");

        let hooks = resolve_hooks_dir(&repo_dir).expect("hooks dir");
        assert_eq!(hooks, repo_dir.join(".githooks"));
    }

    #[test]
    fn resolve_hooks_dir_worktree_uses_common_git_dir_hooks() {
        let td = tempfile::TempDir::new().expect("tempdir");
        let repo_dir = td.path().join("repo");
        std::fs::create_dir_all(&repo_dir).expect("mkdir");
        run_git(&repo_dir, &["init", "-q"]);
        run_git(&repo_dir, &["config", "user.email", "test@example.com"]);
        run_git(&repo_dir, &["config", "user.name", "test"]);

        // Create an initial commit so we can create a branch/worktree.
        std::fs::write(repo_dir.join("README"), "x").expect("write");
        run_git(&repo_dir, &["add", "README"]);
        run_git(&repo_dir, &["commit", "-qm", "init"]);
        run_git(&repo_dir, &["branch", "branch2"]);

        let wt_dir = td.path().join("wt");
        run_git(
            &repo_dir,
            &["worktree", "add", "-q", wt_dir.to_str().unwrap(), "branch2"],
        );

        let hooks = resolve_hooks_dir(&wt_dir).expect("hooks dir");
        assert_eq!(hooks, repo_dir.join(".git").join("hooks"));
    }

    #[test]
    fn install_and_uninstall_guard_preserves_existing_hook() {
        let td = tempfile::TempDir::new().expect("tempdir");
        let repo_dir = td.path().join("repo");
        std::fs::create_dir_all(&repo_dir).expect("mkdir");
        run_git(&repo_dir, &["init", "-q"]);

        let hooks_dir = repo_dir.join(".git").join("hooks");
        let pre_commit = hooks_dir.join("pre-commit");
        let orig_body = "#!/bin/sh\necho original\n";
        std::fs::write(&pre_commit, orig_body).expect("write pre-commit");

        install_guard("/abs/path/backend", &repo_dir).expect("install_guard");

        let chain_body = std::fs::read_to_string(&pre_commit).expect("read chain");
        assert!(
            chain_body.contains("mcp-agent-mail chain-runner (pre-commit)"),
            "expected chain-runner sentinel"
        );

        let preserved = std::fs::read_to_string(hooks_dir.join("pre-commit.orig"))
            .expect("read pre-commit.orig");
        assert_eq!(preserved, orig_body);

        let plugin_path = hooks_dir
            .join("hooks.d")
            .join("pre-commit")
            .join(PLUGIN_FILE_NAME);
        assert!(plugin_path.exists(), "expected plugin file to exist");

        uninstall_guard(&repo_dir).expect("uninstall_guard");

        assert!(!plugin_path.exists(), "expected plugin file to be removed");
        let restored = std::fs::read_to_string(&pre_commit).expect("read restored pre-commit");
        assert_eq!(restored, orig_body);
    }
}
