//! In-memory read cache for hot-path project and agent lookups,
//! plus a deferred touch queue to batch `last_active_ts` updates.
//!
//! Dramatically reduces DB round-trips for repeated `resolve_project` and
//! `resolve_agent` calls that happen on every tool invocation.
//!
//! - Projects cached for 5 minutes (almost never change after creation)
//! - Agents cached for 60 seconds (profile updates are infrequent)
//! - Max 1000 entries per category (~200KB total at saturation)
//! - Write-through: callers should call `invalidate_*` or `put_*` after mutations
//! - Deferred touch: `touch_agent` timestamps are buffered and flushed in batches

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::models::{AgentRow, ProjectRow};
use mcp_agent_mail_core::{LockLevel, OrderedMutex, OrderedRwLock};

const PROJECT_TTL: Duration = Duration::from_secs(300); // 5 min
const AGENT_TTL: Duration = Duration::from_secs(60); // 60s
const MAX_ENTRIES_PER_CATEGORY: usize = 1000;
/// Minimum interval between deferred touch flushes.
const TOUCH_FLUSH_INTERVAL: Duration = Duration::from_secs(30);

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
    projects_by_slug: OrderedRwLock<HashMap<String, CacheEntry<ProjectRow>>>,
    projects_by_human_key: OrderedRwLock<HashMap<String, CacheEntry<ProjectRow>>>,
    agents_by_key: OrderedRwLock<HashMap<(i64, String), CacheEntry<AgentRow>>>,
    agents_by_id: OrderedRwLock<HashMap<i64, CacheEntry<AgentRow>>>,
    /// Deferred touch queue: `agent_id` → latest requested timestamp (micros).
    deferred_touches: OrderedMutex<HashMap<i64, i64>>,
    /// Last time we flushed the deferred touches.
    last_touch_flush: OrderedMutex<Instant>,
}

impl ReadCache {
    fn new() -> Self {
        Self {
            projects_by_slug: OrderedRwLock::new(
                LockLevel::DbReadCacheProjectsBySlug,
                HashMap::new(),
            ),
            projects_by_human_key: OrderedRwLock::new(
                LockLevel::DbReadCacheProjectsByHumanKey,
                HashMap::new(),
            ),
            agents_by_key: OrderedRwLock::new(LockLevel::DbReadCacheAgentsByKey, HashMap::new()),
            agents_by_id: OrderedRwLock::new(LockLevel::DbReadCacheAgentsById, HashMap::new()),
            deferred_touches: OrderedMutex::new(
                LockLevel::DbReadCacheDeferredTouches,
                HashMap::new(),
            ),
            last_touch_flush: OrderedMutex::new(
                LockLevel::DbReadCacheLastTouchFlush,
                Instant::now(),
            ),
        }
    }

    // -------------------------------------------------------------------------
    // Project cache
    // -------------------------------------------------------------------------

    /// Look up a project by slug. Returns `None` if not cached or expired.
    pub fn get_project(&self, slug: &str) -> Option<ProjectRow> {
        let map = self.projects_by_slug.read();
        map.get(slug)
            .filter(|e| !e.is_expired(PROJECT_TTL))
            .map(|e| e.value.clone())
    }

    /// Look up a project by `human_key`.
    pub fn get_project_by_human_key(&self, human_key: &str) -> Option<ProjectRow> {
        let map = self.projects_by_human_key.read();
        map.get(human_key)
            .filter(|e| !e.is_expired(PROJECT_TTL))
            .map(|e| e.value.clone())
    }

    /// Cache a project (write-through after DB mutation).
    /// Indexes by both `slug` and `human_key`.
    pub fn put_project(&self, project: &ProjectRow) {
        // Index by slug
        {
            let mut map = self.projects_by_slug.write();
            if map.len() >= MAX_ENTRIES_PER_CATEGORY {
                evict_expired(&mut map, PROJECT_TTL);
            }
            if map.len() < MAX_ENTRIES_PER_CATEGORY {
                map.insert(project.slug.clone(), CacheEntry::new(project.clone()));
            }
        }
        // Index by human_key
        {
            let mut map = self.projects_by_human_key.write();
            if map.len() >= MAX_ENTRIES_PER_CATEGORY {
                evict_expired(&mut map, PROJECT_TTL);
            }
            if map.len() < MAX_ENTRIES_PER_CATEGORY {
                map.insert(project.human_key.clone(), CacheEntry::new(project.clone()));
            }
        }
    }

    // -------------------------------------------------------------------------
    // Agent cache
    // -------------------------------------------------------------------------

    /// Look up an agent by (`project_id`, name). Returns `None` if not cached or expired.
    pub fn get_agent(&self, project_id: i64, name: &str) -> Option<AgentRow> {
        let map = self.agents_by_key.read();
        let key = (project_id, name.to_string());
        map.get(&key)
            .filter(|e| !e.is_expired(AGENT_TTL))
            .map(|e| e.value.clone())
    }

    /// Look up an agent by id.
    pub fn get_agent_by_id(&self, agent_id: i64) -> Option<AgentRow> {
        let map = self.agents_by_id.read();
        map.get(&agent_id)
            .filter(|e| !e.is_expired(AGENT_TTL))
            .map(|e| e.value.clone())
    }

    /// Cache an agent (write-through after DB mutation).
    /// Indexes by both (`project_id`, `name`) and `id`.
    pub fn put_agent(&self, agent: &AgentRow) {
        // Index by (project_id, name)
        {
            let mut map = self.agents_by_key.write();
            if map.len() >= MAX_ENTRIES_PER_CATEGORY {
                evict_expired_agents(&mut map, AGENT_TTL);
            }
            if map.len() < MAX_ENTRIES_PER_CATEGORY {
                map.insert(
                    (agent.project_id, agent.name.clone()),
                    CacheEntry::new(agent.clone()),
                );
            }
        }
        // Index by id (if present)
        if let Some(id) = agent.id {
            let mut map = self.agents_by_id.write();
            if map.len() >= MAX_ENTRIES_PER_CATEGORY {
                map.retain(|_, entry| !entry.is_expired(AGENT_TTL));
            }
            if map.len() < MAX_ENTRIES_PER_CATEGORY {
                map.insert(id, CacheEntry::new(agent.clone()));
            }
        }
    }

    /// Invalidate a specific agent entry (call after `register_agent` update).
    pub fn invalidate_agent(&self, project_id: i64, name: &str) {
        let mut map = self.agents_by_key.write();
        if let Some(entry) = map.remove(&(project_id, name.to_string())) {
            // Also remove from id index
            if let Some(id) = entry.value.id {
                drop(map); // release key map lock first
                let mut id_map = self.agents_by_id.write();
                id_map.remove(&id);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Deferred touch queue
    // -------------------------------------------------------------------------

    /// Enqueue a deferred `touch_agent` update. Returns `true` if the flush
    /// interval has elapsed and the caller should drain.
    pub fn enqueue_touch(&self, agent_id: i64, ts_micros: i64) -> bool {
        {
            let mut touches = self.deferred_touches.lock();
            // Keep only the latest timestamp per agent
            touches
                .entry(agent_id)
                .and_modify(|existing| {
                    if ts_micros > *existing {
                        *existing = ts_micros;
                    }
                })
                .or_insert(ts_micros);
        }

        let last = self.last_touch_flush.lock();
        last.elapsed() >= TOUCH_FLUSH_INTERVAL
    }

    /// Drain all pending touch entries and reset the flush clock.
    /// Returns the map of `agent_id` → latest timestamp.
    pub fn drain_touches(&self) -> HashMap<i64, i64> {
        let drained: HashMap<i64, i64> = {
            let mut touches = self.deferred_touches.lock();
            touches.drain().collect()
        };
        let mut last = self.last_touch_flush.lock();
        *last = Instant::now();
        drained
    }

    /// Check if there are pending touches.
    pub fn has_pending_touches(&self) -> bool {
        let touches = self.deferred_touches.lock();
        !touches.is_empty()
    }

    /// Create a new standalone cache instance (for testing).
    #[must_use]
    pub fn new_for_testing() -> Self {
        Self::new()
    }

    /// Clear all cache entries (for testing).
    #[cfg(test)]
    pub fn clear(&self) {
        self.projects_by_slug.write().clear();
        self.projects_by_human_key.write().clear();
        self.agents_by_key.write().clear();
        self.agents_by_id.write().clear();
        self.deferred_touches.lock().clear();
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
        cache.put_project(&project);

        let cached = cache.get_project("foo");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().slug, "foo");
    }

    #[test]
    fn project_cache_by_human_key() {
        let cache = ReadCache::new();

        let project = make_project("myproj");
        cache.put_project(&project);

        let cached = cache.get_project_by_human_key("/data/myproj");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().slug, "myproj");
    }

    #[test]
    fn agent_cache_hit_and_miss() {
        let cache = ReadCache::new();

        assert!(cache.get_agent(1, "BlueLake").is_none());

        let agent = make_agent("BlueLake", 1);
        cache.put_agent(&agent);

        let cached = cache.get_agent(1, "BlueLake");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().name, "BlueLake");
    }

    #[test]
    fn agent_cache_by_id() {
        let cache = ReadCache::new();

        let agent = make_agent("GreenHill", 2);
        cache.put_agent(&agent);

        let cached = cache.get_agent_by_id(1);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().name, "GreenHill");
    }

    #[test]
    fn agent_invalidate() {
        let cache = ReadCache::new();

        let agent = make_agent("RedCat", 2);
        cache.put_agent(&agent);
        assert!(cache.get_agent(2, "RedCat").is_some());
        assert!(cache.get_agent_by_id(1).is_some());

        cache.invalidate_agent(2, "RedCat");
        assert!(cache.get_agent(2, "RedCat").is_none());
        assert!(cache.get_agent_by_id(1).is_none());
    }

    #[test]
    fn max_entries_respected() {
        let cache = ReadCache::new();

        for i in 0..MAX_ENTRIES_PER_CATEGORY + 10 {
            let slug = format!("proj-{i}");
            cache.put_project(&make_project(&slug));
        }

        let map_len = cache.projects_by_slug.read().len();
        assert!(map_len <= MAX_ENTRIES_PER_CATEGORY);
    }

    #[test]
    fn deferred_touch_coalesces() {
        let cache = ReadCache::new();

        // Two touches for same agent - should keep latest
        cache.enqueue_touch(42, 1000);
        cache.enqueue_touch(42, 2000);
        cache.enqueue_touch(42, 1500); // earlier timestamp, ignored

        let drained = cache.drain_touches();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[&42], 2000);
    }

    #[test]
    fn deferred_touch_multi_agent() {
        let cache = ReadCache::new();

        cache.enqueue_touch(1, 100);
        cache.enqueue_touch(2, 200);
        cache.enqueue_touch(3, 300);

        let drained = cache.drain_touches();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[&1], 100);
        assert_eq!(drained[&2], 200);
        assert_eq!(drained[&3], 300);

        // After drain, should be empty
        assert!(!cache.has_pending_touches());
    }

    #[test]
    fn drain_resets_flush_clock() {
        let cache = ReadCache::new();

        cache.enqueue_touch(1, 100);
        let _ = cache.drain_touches();

        // Immediately after drain, should_flush should be false
        let should_flush = cache.enqueue_touch(1, 200);
        assert!(!should_flush, "should not flush immediately after drain");
    }
}
