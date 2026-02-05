# Recovery Runbook

## Symptoms
- SQLite corruption detected (`PRAGMA integrity_check` fails).
- Search/index inconsistencies vs archive.
- Missing records in SQLite after archive write.

## Steps
1. Acquire project archive lock (`projects/<slug>/.archive.lock`).
2. Validate archive as source of truth (ensure files exist, git repo healthy).
3. Rebuild SQLite index from archive contents.
4. Update version markers (archive commit hash + db schema version).
5. Verify counts and sample hashes.
6. Release lock.

## Commands (Planned)
- `reindex` (archive -> SQLite)
- `integrity-check` (SQLite + archive)
- `doctor repair` (wraps the above with backups)
