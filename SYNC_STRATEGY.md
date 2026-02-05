# Sync Strategy

## Source of Truth
- Primary: Git archive (markdown + attachments under `projects/<slug>/`).
- Secondary: SQLite index for queries, FTS, and fast lookups.
- Rationale: Git archive is the human-auditable canonical store; SQLite is rebuildable.

## Sync Triggers
- On command: any write tool (send_message, reserve files, register agent) writes archive then updates SQLite.
- On exit: flush pending archive writes and checkpoint WAL if enabled.
- Timer/throttle: periodic integrity checks and optional archive -> SQLite resync.

## Versioning
- DB marker: `schema_version` + `last_archive_commit`.
- Archive marker: last SQLite sync timestamp stored in archive metadata.

## Concurrency
- Lock file path: `projects/<slug>/.archive.lock` for archive writes.
- Busy timeout: SQLite busy timeout (60s target) + exponential backoff for lock contention.

## Failure Handling
- DB locked: retry with backoff; if still locked, return a clear error and keep archive as canonical.
- Archive write error: abort tool, no DB update, return error.
- Git commit error: surface error, preserve files on disk for manual recovery.
- SQLite corruption: run integrity check; rebuild from archive if needed.
