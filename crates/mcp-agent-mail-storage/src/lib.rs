#![forbid(unsafe_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectArchive {
    pub slug: String,
    pub root: String,
    pub repo_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitInfo {
    pub sha: String,
    pub short_sha: String,
    pub author: String,
    pub email: String,
    pub date: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageArchivePaths {
    pub canonical: String,
    pub outbox: String,
    pub inbox: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ArchiveStore;

impl ArchiveStore {
    pub fn new() -> Self {
        Self
    }

    pub fn archive_root(&self) -> String {
        "~/.mcp_agent_mail_git_mailbox_repo".to_string()
    }

    pub fn project_root(&self, slug: &str) -> String {
        format!("{}/projects/{}", self.archive_root(), slug)
    }

    pub fn archive_lock_path(&self, slug: &str) -> String {
        format!("{}/.archive.lock", self.project_root(slug))
    }

    pub fn message_paths(
        &self,
        slug: &str,
        sender: &str,
        recipients: &[String],
        timestamp: &str,
        subject_slug: &str,
        id: i64,
    ) -> MessageArchivePaths {
        let base = format!("{}/messages", self.project_root(slug));
        let rel = format!("{timestamp}/{timestamp}__{subject_slug}__{id}.md");
        let canonical = format!("{}/{}", base, rel);
        let outbox = format!(
            "{}/agents/{}/outbox/{}",
            self.project_root(slug),
            sender,
            rel
        );
        let inbox = recipients
            .iter()
            .map(|r| format!("{}/agents/{}/inbox/{}", self.project_root(slug), r, rel))
            .collect();
        MessageArchivePaths {
            canonical,
            outbox,
            inbox,
        }
    }
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

impl Default for ArchiveStore {
    fn default() -> Self {
        Self::new()
    }
}
