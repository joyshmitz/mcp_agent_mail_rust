//! In-memory read cache for hot-path project and agent lookups.
//!
//! Dramatically reduces DB round-trips for repeated `resolve_project` and
//! `resolve_agent` calls that happen on every tool invocation.
//!
//! - Projects cached for 5 minutes (almost never change after creation)
//! - Agents cached for 60 seconds (profile updates are infrequent)
//! - Max 1000 entries per category (~200KB total at saturation)
//! - Write-through: callers should call `invalidate_*` or `put_*` after mutations

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use crate::models::{AgentRow, ProjectRow};

const PROJECT_TTL: Duration = Duration::from_secs(300); // 5 min
const AGENT_TTL: Duration = Duration::from_secs(60); // 60s
const MAX_ENTRIES_PER_CATEGORY: usize = 1000;

struct CacheEntry<T> {
    value: T,
    inserted: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T) -> Self {
        Self {
            value,
            inserted: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.inserted.elapsed() > ttl
    }
}

/// In-memory read cache for projects and agents.
pub struct ReadCache {
    projects_by_slug: RwLock<HashMap<String, CacheEntry<ProjectRow>>>,
    agents_by_key: RwLock<HashMap<(i64, String), CacheEntry<AgentRow>>>,
}

impl ReadCache {
    fn new() -> Self {
        Self {
            projects_by_slug: RwLock::new(HashMap::new()),
            agents_by_key: RwLock::new(HashMap::new()),
        }
    }

    /// Look up a project by slug. Returns `None` if not cached or expired.
    pub fn get_project(&self, slug: &str) -> Option<ProjectRow> {
        let map = self
            .projects_by_slug
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(slug)
            .filter(|e| !e.is_expired(PROJECT_TTL))
            .map(|e| e.value.clone())
    }

    /// Cache a project (write-through after DB mutation).
    pub fn put_project(&self, slug: &str, project: &ProjectRow) {
        let mut map = self
            .projects_by_slug
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= MAX_ENTRIES_PER_CATEGORY {
            evict_expired(&mut map, PROJECT_TTL);
        }
        if map.len() < MAX_ENTRIES_PER_CATEGORY {
            map.insert(slug.to_string(), CacheEntry::new(project.clone()));
        }
    }

    /// Look up an agent by (`project_id`, name). Returns `None` if not cached or expired.
    pub fn get_agent(&self, project_id: i64, name: &str) -> Option<AgentRow> {
        let map = self
            .agents_by_key
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (project_id, name.to_string());
        map.get(&key)
            .filter(|e| !e.is_expired(AGENT_TTL))
            .map(|e| e.value.clone())
    }

    /// Cache an agent (write-through after DB mutation).
    pub fn put_agent(&self, project_id: i64, name: &str, agent: &AgentRow) {
        let mut map = self
            .agents_by_key
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= MAX_ENTRIES_PER_CATEGORY {
            evict_expired_agents(&mut map, AGENT_TTL);
        }
        if map.len() < MAX_ENTRIES_PER_CATEGORY {
            map.insert(
                (project_id, name.to_string()),
                CacheEntry::new(agent.clone()),
            );
        }
    }

    /// Invalidate a specific agent entry (call after `register_agent` update).
    pub fn invalidate_agent(&self, project_id: i64, name: &str) {
        let mut map = self
            .agents_by_key
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.remove(&(project_id, name.to_string()));
    }
}

fn evict_expired<T>(map: &mut HashMap<String, CacheEntry<T>>, ttl: Duration) {
    map.retain(|_, entry| !entry.is_expired(ttl));
}

fn evict_expired_agents<T>(map: &mut HashMap<(i64, String), CacheEntry<T>>, ttl: Duration) {
    map.retain(|_, entry| !entry.is_expired(ttl));
}

static READ_CACHE: OnceLock<ReadCache> = OnceLock::new();

/// Get the global read cache instance.
pub fn read_cache() -> &'static ReadCache {
    READ_CACHE.get_or_init(ReadCache::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_project(slug: &str) -> ProjectRow {
        ProjectRow {
            id: Some(1),
            slug: slug.to_string(),
            human_key: format!("/data/{slug}"),
            created_at: 0,
        }
    }

    fn make_agent(name: &str, project_id: i64) -> AgentRow {
        AgentRow {
            id: Some(1),
            project_id,
            name: name.to_string(),
            program: "test".to_string(),
            model: "test".to_string(),
            task_description: String::new(),
            inception_ts: 0,
            last_active_ts: 0,
            attachments_policy: "auto".to_string(),
            contact_policy: "open".to_string(),
        }
    }

    #[test]
    fn project_cache_hit_and_miss() {
        let cache = ReadCache::new();

        assert!(cache.get_project("foo").is_none());

        let project = make_project("foo");
        cache.put_project("foo", &project);

        let cached = cache.get_project("foo");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().slug, "foo");
    }

    #[test]
    fn agent_cache_hit_and_miss() {
        let cache = ReadCache::new();

        assert!(cache.get_agent(1, "BlueLake").is_none());

        let agent = make_agent("BlueLake", 1);
        cache.put_agent(1, "BlueLake", &agent);

        let cached = cache.get_agent(1, "BlueLake");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().name, "BlueLake");
    }

    #[test]
    fn agent_invalidate() {
        let cache = ReadCache::new();

        let agent = make_agent("RedCat", 2);
        cache.put_agent(2, "RedCat", &agent);
        assert!(cache.get_agent(2, "RedCat").is_some());

        cache.invalidate_agent(2, "RedCat");
        assert!(cache.get_agent(2, "RedCat").is_none());
    }

    #[test]
    fn max_entries_respected() {
        let cache = ReadCache::new();

        for i in 0..MAX_ENTRIES_PER_CATEGORY + 10 {
            let slug = format!("proj-{i}");
            cache.put_project(&slug, &make_project(&slug));
        }

        // After eviction of expired entries (none are expired, so cap applies)
        let map_len = cache.projects_by_slug.read().unwrap().len();
        assert!(map_len <= MAX_ENTRIES_PER_CATEGORY);
    }
}
