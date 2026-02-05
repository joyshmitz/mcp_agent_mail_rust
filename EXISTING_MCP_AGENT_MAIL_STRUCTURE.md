# Existing MCP Agent Mail Structure (Legacy Python)

> **THE SPEC** - Complete behavioral specification extracted from Python codebase.
> After reading this, you should NOT need to consult legacy code.

---

## Overview

- **Legacy codebase:** `/data/projects/mcp_agent_mail_rust/legacy_python_mcp_agent_mail_code/mcp_agent_mail`
- **Total size:** ~25,000 LOC Python
- **Primary modules:** `app.py` (10,261 LOC), `storage.py` (~3,600 LOC), `cli.py` (~5,000 LOC), `http.py` (~2,900 LOC), `db.py` (824 LOC), `config.py` (480 LOC), `guard.py` (~900 LOC), `models.py` (163 LOC), `llm.py` (257 LOC), `utils.py` (234 LOC)

## Entry Points

- `mcp_agent_mail.__main__.py` provides CLI entry safe under pytest
- `mcp_agent_mail.__init__.py` exposes `build_mcp_server()`
- `mcp_agent_mail.http.py` includes `main()` for HTTP server
- `mcp_agent_mail.cli.py` includes Typer CLI app and `if __name__ == "__main__"`

## CLI Commands (Typer)
Source: `src/mcp_agent_mail/cli.py`.

| Command | Args / Flags (from signatures) |
| --- | --- |
| `products ensure` | `product_key?`, `--name/-n` |
| `products link` | `product_key`, `project` |
| `products status` | `product_key` |
| `products search` | `product_key`, `query`, `--limit/-l` |
| `products inbox` | `product_key`, `agent`, `--limit/-l`, `--urgent-only/--all`, `--include-bodies/--no-bodies`, `--since-ts` |
| `products summarize-thread` | `product_key`, `thread_id`, `--per-thread-limit/-n`, `--no-llm` |
| `serve-http` | `--host`, `--port`, `--path` |
| `serve-stdio` | no flags |
| `lint` | no flags |
| `typecheck` | no flags |
| `share export` | `--output/-o`, `--interactive/-i`, `--project/-p` (repeat), `--inline-threshold`, `--detach-threshold`, `--scrub-preset`, `--chunk-threshold`, `--chunk-size`, `--dry-run/--no-dry-run`, `--zip/--no-zip`, `--signing-key`, `--signing-public-out`, `--age-recipient` (repeat) |
| `share update` | `bundle`, `--project/-p` (repeat), `--inline-threshold`, `--detach-threshold`, `--chunk-threshold`, `--chunk-size`, `--scrub-preset`, `--zip/--no-zip`, `--signing-key`, `--signing-public-out`, `--age-recipient` (repeat) |
| `share preview` | `bundle`, `--host`, `--port`, `--open-browser/--no-open-browser` |
| `share verify` | `bundle`, `--public-key` |
| `share decrypt` | `encrypted_path`, `--output/-o`, `--identity/-i`, `--passphrase/-p` |
| `share wizard` | no flags |
| `archive save` | `--project/-p` (repeat), `--scrub-preset`, `--label/-l` |
| `archive list` | `--limit/-n`, `--json` |
| `archive restore` | `archive_file`, `--force/-f`, `--dry-run` |
| `clear-and-reset-everything` | `--force/-f`, `--archive/--no-archive` |
| `migrate` | no flags |
| `list-projects` | `--include-agents`, `--json` |
| `guard install` | `project`, `repo`, `--prepush/--no-prepush` |
| `guard uninstall` | `repo` |
| `guard status` | `repo` |
| `guard check` | `--stdin-nul`, `--advisory`, `--repo` |
| `file_reservations list` | `project`, `--active-only` |
| `file_reservations active` | `project`, `--limit` |
| `file_reservations soon` | `project`, `--minutes` |
| `acks pending` | `project`, `agent`, `--limit` |
| `acks remind` | `project`, `agent`, `--min-age-minutes`, `--limit` |
| `acks overdue` | `project`, `agent`, `--ttl-minutes`, `--limit` |
| `list-acks` | `--project`, `--agent`, `--limit` |
| `config set-port` | `port`, `--env-file` |
| `config show-port` | no flags |
| `amctl env` | `--path/-p`, `--agent/-a` |
| `am-run` | `slot`, `cmd...`, `--path/-p`, `--agent/-a`, `--ttl-seconds`, `--shared/--exclusive`, `--block-on-conflicts/--no-block-on-conflicts` |
| `projects mark-identity` | `project_path`, `--commit/--no-commit` |
| `projects discovery-init` | `project_path`, `--product/-P` |
| `projects adopt` | `source`, `target`, `--dry-run/--apply` |
| `mail status` | `project_path` |
| `docs insert-blurbs` | `--scan-dir/-d` (repeat), `--yes`, `--dry-run`, `--max-depth` |
| `doctor check` | `project?`, `--verbose/-v`, `--json` |
| `doctor repair` | `project?`, `--dry-run`, `--yes/-y`, `--backup-dir` |
| `doctor backups` | `--json` |
| `doctor restore` | `backup_path`, `--dry-run`, `--yes/-y` |

## CLI Behavior Notes (Legacy Python)

### Share Commands (CLI → `share.py`)
- Default thresholds:
  - `INLINE_ATTACHMENT_THRESHOLD = 64 KiB`
  - `DETACH_ATTACHMENT_THRESHOLD = 25 MiB`
  - `DEFAULT_CHUNK_THRESHOLD = 20 MiB`
  - `DEFAULT_CHUNK_SIZE = 4 MiB`
- `share export`:
  - `--scrub-preset` defaults to `standard` (case-insensitive); invalid preset exits 1.
  - `--dry-run` uses a temp output dir and prints a summary + security checklist; no bundle artifacts written.
  - If `detach_threshold <= inline_threshold`, it auto-adjusts: `detach = inline + max(1024, inline/2)`.
  - `--interactive` runs a wizard that prompts for project filters, thresholds, preset, and zip; returned values override flags.
  - Builds snapshot, scrubs per preset, packages attachments, builds FTS (if available), writes manifest + viewer assets.
  - Optional signing (`--signing-key` Ed25519 seed) and optional `--signing-public-out`.
  - Optional age encryption (`--age-recipient` repeated) applied to the ZIP output.
- `share update`:
  - Loads export config from existing bundle `manifest.json` + stored export config.
  - Overrides allowed for project scope, thresholds, scrub preset; validates non-negative; chunk size >= 1024.
  - Creates temp snapshot, rebuilds bundle assets, then syncs into existing bundle directory.
  - `--zip` default is **false** (contrast with export default **true**).
- `share preview`:
  - Defaults: `--host 127.0.0.1`, `--port 9000`, `--open-browser` default false.
  - Serves static bundle with no-cache headers; listens for `r` (reload), `d` (deploy requested), `q` (quit).
  - Exits with code **42** when deployment was requested via `d`.
- `share verify`:
  - Validates SRI hashes and optional Ed25519 signature; `--public-key` uses provided base64 key or manifest signature.
- `share decrypt`:
  - `--output` defaults to filename without `.age` (or adds `_decrypted` suffix).
  - `--identity` (age key file) is mutually exclusive with `--passphrase`.
- `share wizard`:
  - Launches `scripts/share_to_github_pages.py` from repo (source-only); errors if not found.

### Doctor Commands (CLI)
- `doctor check`:
  - `--json` prints machine-readable diagnostics + summary counts.
  - Checks: stale locks, SQLite `PRAGMA integrity_check`, orphaned message recipients,
    FTS row count mismatch, expired file reservations, WAL/SHM presence.
  - `--verbose` prints up to 5 detail lines per diagnostic.
- `doctor repair`:
  - `--dry-run` previews; `--yes` skips confirmations; `--backup-dir` overrides backup location.
  - Creates a backup (unless dry-run), heals stale locks, releases expired reservations.
  - Data repair: deletes orphaned message recipients (prompt unless `--yes`).
- `doctor backups`:
  - Lists backups (table) or JSON.
- `doctor restore`:
  - Requires `manifest.json` in backup dir; warns about overwriting DB/archive.
  - `--dry-run` prints what would restore; otherwise performs restore and reports results.

### Guard Commands (CLI)
- `guard install`:
  - Requires `WORKTREES_ENABLED=1`; installs pre-commit guard script; optional `--prepush`.
- `guard uninstall`:
  - Resolves hooks dir via `core.hooksPath` or `.git/hooks`, removes guard scripts if present.
- `guard status`:
  - Prints gate/mode, resolved hooks path, and presence of pre-commit/pre-push hooks.
- `guard check`:
  - Requires `AGENT_NAME` env var; reads NUL-delimited paths when `--stdin-nul`.
  - Normalizes to repo-root relative; respects `core.ignorecase`.
  - Uses `pathspec` (gitignore) when available, else fnmatch; symmetric matching.
  - Prints conflicts; non-zero exit unless `--advisory`.

### Build Slot Helpers (CLI)
- `amctl env` prints environment variables:
  - `SLUG`, `PROJECT_UID`, `BRANCH`, `AGENT`, `CACHE_KEY`, `ARTIFACT_DIR`.
- `am-run`:
  - Acquires build slot (server tool if available, else local JSON lease under `build_slots/`).
  - Renewal interval: `max(60, ttl_seconds/2)`; releases slot on exit.
  - `--block-on-conflicts` exits 1 when exclusive conflicts present (unless `--shared`).
  - Exports env vars: `AM_SLOT`, `SLUG`, `PROJECT_UID`, `BRANCH`, `AGENT`, `CACHE_KEY`.

## Data Model (SQLModel)
Source: `src/mcp_agent_mail/models.py`.

### Table: `projects`
- `id` (PK)
- `slug` (unique, indexed)
- `human_key` (indexed)
- `created_at` (UTC naive)

### Table: `products`
- `id` (PK)
- `product_uid` (unique, indexed)
- `name` (unique, indexed)
- `created_at` (UTC naive)

### Table: `product_project_links`
- `id` (PK)
- `product_id` (FK -> products.id)
- `project_id` (FK -> projects.id)
- `created_at` (UTC naive)
- Unique: `(product_id, project_id)`

### Table: `agents`
- `id` (PK)
- `project_id` (FK -> projects.id)
- `name` (indexed)
- `program`
- `model`
- `task_description`
- `inception_ts` (UTC naive)
- `last_active_ts` (UTC naive)
- `attachments_policy` (default: `auto`)
- `contact_policy` (default: `auto`)  # open | auto | contacts_only | block_all
- Unique: `(project_id, name)`

### Table: `messages`
- `id` (PK)
- `project_id` (FK -> projects.id)
- `sender_id` (FK -> agents.id)
- `thread_id` (indexed, optional)
- `subject`
- `body_md`
- `importance` (default: `normal`)
- `ack_required` (default: false)
- `created_ts` (UTC naive)
- `attachments` (JSON array, default `[]`)
- Indexes: `(project_id, created_ts)` and `(project_id, sender_id, created_ts)`

### Table: `message_recipients`
- `message_id` (PK, FK -> messages.id)
- `agent_id` (PK, FK -> agents.id)
- `kind` (default: `to`)  # to | cc | bcc
- `read_ts` (optional)
- `ack_ts` (optional)
- Index: `(agent_id, message_id)`

### Table: `file_reservations`
- `id` (PK)
- `project_id` (FK -> projects.id)
- `agent_id` (FK -> agents.id)
- `path_pattern`
- `exclusive` (default: true)
- `reason` (default: empty)
- `created_ts` (UTC naive)
- `expires_ts`
- `released_ts` (optional)
- Indexes: `(project_id, released_ts, expires_ts)` and `(project_id, agent_id, released_ts)`

### Table: `agent_links`
- `id` (PK)
- `a_project_id` (FK -> projects.id)
- `a_agent_id` (FK -> agents.id)
- `b_project_id` (FK -> projects.id)
- `b_agent_id` (FK -> agents.id)
- `status` (default: `pending`)  # pending | approved | blocked
- `reason` (default: empty)
- `created_ts` (UTC naive)
- `updated_ts` (UTC naive)
- `expires_ts` (optional)
- Unique: `(a_project_id, a_agent_id, b_project_id, b_agent_id)`

### Table: `project_sibling_suggestions`
- `id` (PK)
- `project_a_id` (FK -> projects.id)
- `project_b_id` (FK -> projects.id)
- `score` (float)
- `status` (default: `suggested`)  # suggested | confirmed | dismissed
- `rationale` (default: empty)
- `created_ts` (UTC naive)
- `evaluated_ts` (UTC naive)
- `confirmed_ts` (optional)
- `dismissed_ts` (optional)
- Unique: `(project_a_id, project_b_id)`

## Storage Layout (Git Archive)
Source: `src/mcp_agent_mail/storage.py`.
- Archive is a Git repo under `STORAGE_ROOT`, with per-project subtree `projects/<slug>/`.
- Per-project lock file: `projects/<slug>/.archive.lock`.
- Commit lock file: `.commit.lock` under project root when scoped; otherwise repo root.
- Canonical messages: `projects/<slug>/messages/YYYY/MM/<timestamp>__<subject-slug>__<id>.md`.
- Thread digests: `projects/<slug>/messages/threads/<thread_id>.md`.
- Per-agent inbox/outbox copies: `projects/<slug>/agents/<name>/inbox/YYYY/MM/` and `.../outbox/...`.
- Agent profile: `projects/<slug>/agents/<name>/profile.json`.
- File reservations: `projects/<slug>/file_reservations/<sha1(path_pattern)>.json` and `id-<id>.json`.
- Attachments: `projects/<slug>/attachments/<sha1[:2]>/<sha1>.webp`.
- Originals (optional): `projects/<slug>/attachments/originals/<sha1[:2]>/<sha1>.<ext>`.
- Attachment manifests: `projects/<slug>/attachments/_manifests/<sha1>.json`.
- Attachment audit log: `projects/<slug>/attachments/_audit/<sha1>.log`.
- Notification signals: `{NOTIFICATIONS_SIGNALS_DIR}/projects/<slug>/agents/<agent>.signal`.

### Message File Format
- Frontmatter is JSON with header line `---json`, followed by Markdown body.
- Filenames include ISO timestamp + subject slug + optional message id.

---

## MCP Tools (35 Total)

### Identity Cluster (CLUSTER_IDENTITY)

| Tool | Parameters | Returns | Notes |
|------|------------|---------|-------|
| `health_check` | none | `{status, environment, http_host, http_port, database_url}` | Infrastructure check |
| `ensure_project` | `human_key: str, identity_mode?: str` | `{id, slug, human_key, created_at}` | MUST be absolute path; idempotent |
| `register_agent` | `project_key, program, model, name?, task_description?, attachments_policy?` | Agent record | Upsert semantics; auto-generates name if omitted |
| `create_agent_identity` | Same as register_agent + `name_hint?` | Agent record | Always creates NEW identity |
| `whois` | `project_key, agent_name, include_recent_commits?, commit_limit?` | Agent profile + commits | Lookup with optional Git history |

### Messaging Cluster (CLUSTER_MESSAGING)

| Tool | Parameters | Returns | Notes |
|------|------------|---------|-------|
| `send_message` | `project_key, sender_name, to: list, subject, body_md, cc?, bcc?, attachment_paths?, convert_images?, importance?, ack_required?, thread_id?, auto_contact_if_blocked?` | `{deliveries, count}` | Complex - handles contacts, archives |
| `reply_message` | `project_key, message_id, sender_name, body_md, to?, cc?, bcc?, subject_prefix?` | Message payload | Inherits thread_id, importance, ack_required |
| `fetch_inbox` | `project_key, agent_name, urgent_only?, since_ts?, limit?, include_bodies?` | `list[Message]` | Non-mutating read |
| `mark_message_read` | `project_key, agent_name, message_id` | `{message_id, read, read_at}` | Idempotent |
| `acknowledge_message` | `project_key, agent_name, message_id` | `{message_id, acknowledged, acknowledged_at, read_at}` | Also marks read |

### Contact Cluster (CLUSTER_CONTACT)

| Tool | Parameters | Returns | Notes |
|------|------------|---------|-------|
| `request_contact` | `project_key, from_agent, to_agent, to_project?, reason?, ttl_seconds?, register_if_missing?, program?, model?, task_description?` | `{from, from_project, to, to_project, status, expires_ts?}` | Creates/refreshes a pending AgentLink |
| `respond_contact` | `project_key, to_agent, from_agent, from_project?, accept: bool, ttl_seconds?` | `{from, to, approved, expires_ts?, updated}` | Approve/deny contact request (idempotent) |
| `list_contacts` | `project_key, agent_name` | `list[{to, status, reason, updated_ts?, expires_ts?}]` | Returns outgoing contact links (Python format) |
| `set_contact_policy` | `project_key, agent_name, policy` | `{agent, policy}` | Invalid policy coerces to `auto`; policies: `open\|auto\|contacts_only\|block_all` |

### File Reservation Cluster (CLUSTER_FILE_RESERVATIONS)

| Tool | Parameters | Returns | Notes |
|------|------------|---------|-------|
| `file_reservation_paths` | `project_key, agent_name, paths: list, ttl_seconds?, exclusive?, reason?` | `{granted, conflicts}` | TTL >= 60s; symmetric fnmatch |
| `release_file_reservations` | `project_key, agent_name, paths?, file_reservation_ids?` | `{released, released_at}` | Omit both = release all |
| `renew_file_reservations` | `project_key, agent_name, extend_seconds?, paths?, file_reservation_ids?` | `{renewed, file_reservations}` | Extends from max(now, expiry) |
| `force_release_file_reservation` | `project_key, agent_name, file_reservation_id, note?, notify_previous?` | Release result | Validates inactivity heuristics |
| `install_precommit_guard` | `project_key, code_repo_path` | Install result | Resolves `core.hooksPath` |
| `uninstall_precommit_guard` | `code_repo_path` | Uninstall result | Removes hook |

### Search Cluster (CLUSTER_SEARCH)

| Tool | Parameters | Returns | Notes |
|------|------------|---------|-------|
| `search_messages` | `project_key, query, limit?` | `list[{id, subject, importance, ...}]` | FTS5 syntax: phrases, prefix, boolean |
| `summarize_thread` | `project_key, thread_id, include_examples?, llm_mode?, llm_model?, per_thread_limit?` | Summary with participants, key_points, action_items | Multi-thread: comma-separated IDs |

### Macro Cluster (CLUSTER_MACROS)

| Tool | Parameters | Returns | Notes |
|------|------------|---------|-------|
| `macro_start_session` | `human_key, program, model, agent_name?, task_description?, file_reservation_paths?, file_reservation_reason?, file_reservation_ttl_seconds?, inbox_limit?` | `{project, agent, file_reservations, inbox}` | Composite: ensure_project + register_agent + reserve + fetch_inbox |
| `macro_prepare_thread` | `project_key, thread_id, program, model, agent_name?, task_description?, register_if_missing?, include_examples?, include_inbox_bodies?, llm_mode?, llm_model?, inbox_limit?` | `{agent, thread_summary, inbox}` | Composite: register + summarize + fetch_inbox |
| `macro_file_reservation_cycle` | `project_key, agent_name, paths, ttl_seconds?, exclusive?, reason?, auto_release?` | Reservation result | Composite: reserve + optional release |
| `macro_contact_handshake` | `project_key, requester?, target?, reason?, auto_accept?, ttl_seconds?, welcome_subject?, welcome_body?, thread_id?, register_if_missing?, program?, model?, task_description?` | Handshake result | Composite: request + optional approve + optional welcome |

### Product Cluster (CLUSTER_PRODUCT)

| Tool | Parameters | Returns | Notes |
|------|------------|---------|-------|
| `ensure_product` | `product_key?, name?` | Product record | Auto-generates UID if omitted |
| `products_link` | `product_key, project_keys: list` | Link result | Many-to-many linking |
| `search_messages_product` | `product_key, query, limit?` | Cross-project search | Searches all linked projects |
| `fetch_inbox_product` | `product_key, agent_name, urgent_only?, since_ts?, limit?, include_bodies?` | Cross-project inbox | Aggregates from all linked projects |
| `summarize_thread_product` | `product_key, thread_id, include_examples?, llm_mode?, llm_model?, per_thread_limit?` | Product-scoped summary | Cross-project thread aggregation |

### Build Slot Cluster (CLUSTER_BUILD_SLOTS)

| Tool | Parameters | Returns | Notes |
|------|------------|---------|-------|
| `acquire_build_slot` | `project_key, agent_name, slot_key, ttl_seconds?` | Slot result | Uses file_reservations with `build_slots/{key}.lock` |
| `renew_build_slot` | `project_key, agent_name, slot_key, extend_seconds?` | Renewal result | Extends slot TTL |
| `release_build_slot` | `project_key, agent_name, slot_key` | Release result | Releases slot |

---

## MCP Resources (20+)

### Configuration
- `resource://config/environment{?format}` - Environment snapshot

### Identity
- `resource://identity/{project}{?format}` - Git identity resolution
- `resource://agents/{project_key}{?format}` - Agent list with profiles

### Tooling
- `resource://tooling/directory{?format}` - All tools with cluster/capability metadata
- `resource://tooling/schemas{?format}` - JSON schemas for all tools
- `resource://tooling/metrics{?format}` - Tool call counts, error rates
- `resource://tooling/locks{?format}` - Active archive locks
- `resource://tooling/capabilities/{agent}{?project,format}` - Agent capability mapping
- `resource://tooling/recent/{window_seconds}{?agent,project,format}` - Recent tool usage

### Projects
- `resource://projects{?format}` - All projects
- `resource://project/{slug}{?format}` - Project details + stats
- `resource://product/{key}{?format}` - Product with linked projects

### Messages & Threads
- `resource://message/{message_id}{?project,format}` - Full message details
- `resource://thread/{thread_id}{?project,include_bodies,format}` - Thread messages
- `resource://inbox/{agent}{?project,since_ts,urgent_only,include_bodies,limit,format}` - Inbox view
- `resource://mailbox/{agent}{?project,limit,format}` - Combined inbox/outbox
- `resource://mailbox-with-commits/{agent}{?project,limit,format}` - Mailbox + commit metadata
- `resource://outbox/{agent}{?project,limit,include_bodies,since_ts,format}` - Sent messages

### Views
- `resource://views/urgent-unread/{agent}{?project,limit,format}` - Unread high/urgent
- `resource://views/ack-required/{agent}{?project,limit,format}` - Requiring ack
- `resource://views/acks-stale/{agent}{?project,ttl_seconds,limit,format}` - Unacked > TTL
- `resource://views/ack-overdue/{agent}{?project,ttl_minutes,limit,format}` - Overdue acks

### File Reservations
- `resource://file_reservations/{slug}{?active_only,format}` - Active/all reservations

---

## HTTP Transport Endpoints (HTTP Server)
Source: `src/mcp_agent_mail/http.py`.

- `GET /health/liveness` → `{ "status": "alive" }`
- `GET /health/readiness` → `{ "status": "ready" }` or 503 with error details
- `GET /.well-known/oauth-authorization-server` → `{ "mcp_oauth": false }`
- `GET /.well-known/oauth-authorization-server/mcp` → `{ "mcp_oauth": false }`
- `POST {HTTP_PATH}` → Streamable HTTP MCP transport (JSON-RPC)
- `GET /mail/...` → HTML UI + JSON endpoints (inbox, locks, archive, etc.)

---

## Configuration Environment Variables

### Application
```
APP_ENVIRONMENT=development              # development | production
WORKTREES_ENABLED=false
GIT_IDENTITY_ENABLED=false
PROJECT_IDENTITY_MODE=dir                # dir | git-remote | git-common-dir | git-toplevel
PROJECT_IDENTITY_REMOTE=origin
```

### Database
```
DATABASE_URL=sqlite+aiosqlite:///./storage.sqlite3
DATABASE_ECHO=false
DATABASE_POOL_SIZE=                      # default: None (let SQLAlchemy decide)
DATABASE_MAX_OVERFLOW=                   # default: None
DATABASE_POOL_TIMEOUT=                   # default: None
```

### Storage
```
STORAGE_ROOT=~/.mcp_agent_mail_git_mailbox_repo
GIT_AUTHOR_NAME=mcp-agent
GIT_AUTHOR_EMAIL=mcp-agent@example.com
INLINE_IMAGE_MAX_BYTES=65536             # 64KB
CONVERT_IMAGES=true
KEEP_ORIGINAL_IMAGES=false
ALLOW_ABSOLUTE_ATTACHMENT_PATHS=true     # Dev only
```

### HTTP Transport
```
HTTP_HOST=127.0.0.1
HTTP_PORT=8765
HTTP_PATH=/api/
HTTP_BEARER_TOKEN=
HTTP_ALLOW_LOCALHOST_UNAUTHENTICATED=true

# Rate Limiting
HTTP_RATE_LIMIT_ENABLED=false
HTTP_RATE_LIMIT_BACKEND=memory           # memory | redis
HTTP_RATE_LIMIT_TOOLS_PER_MINUTE=60
HTTP_RATE_LIMIT_RESOURCES_PER_MINUTE=120
HTTP_RATE_LIMIT_TOOLS_BURST=0
HTTP_RATE_LIMIT_RESOURCES_BURST=0
HTTP_RATE_LIMIT_REDIS_URL=

# Request Logging / OTEL
HTTP_REQUEST_LOG_ENABLED=false
HTTP_OTEL_ENABLED=false
OTEL_SERVICE_NAME=mcp-agent-mail
OTEL_EXPORTER_OTLP_ENDPOINT=

# JWT
HTTP_JWT_ENABLED=false
HTTP_JWT_ALGORITHMS=HS256
HTTP_JWT_SECRET=
HTTP_JWT_JWKS_URL=
HTTP_JWT_AUDIENCE=
HTTP_JWT_ISSUER=
HTTP_JWT_ROLE_CLAIM=role

# RBAC
HTTP_RBAC_ENABLED=true
HTTP_RBAC_READER_ROLES=reader,read,ro
HTTP_RBAC_WRITER_ROLES=writer,write,tools,rw
HTTP_RBAC_DEFAULT_ROLE=reader
HTTP_RBAC_READONLY_TOOLS=health_check,fetch_inbox,whois,search_messages,summarize_thread

# CORS
HTTP_CORS_ENABLED=true
HTTP_CORS_ORIGINS=
HTTP_CORS_ALLOW_CREDENTIALS=false
HTTP_CORS_ALLOW_METHODS=*
HTTP_CORS_ALLOW_HEADERS=*
```

### Contact & Messaging
```
CONTACT_ENFORCEMENT_ENABLED=true
CONTACT_AUTO_TTL_SECONDS=86400           # 24h
CONTACT_AUTO_RETRY_ENABLED=true
MESSAGING_AUTO_REGISTER_RECIPIENTS=true
MESSAGING_AUTO_HANDSHAKE_ON_BLOCK=true
```

### File Reservations
```
FILE_RESERVATIONS_CLEANUP_ENABLED=false
FILE_RESERVATIONS_CLEANUP_INTERVAL_SECONDS=60
FILE_RESERVATION_INACTIVITY_SECONDS=1800 # 30min
FILE_RESERVATION_ACTIVITY_GRACE_SECONDS=900
FILE_RESERVATIONS_ENFORCEMENT_ENABLED=true
```

### Agent Naming
```
AGENT_NAME_ENFORCEMENT_MODE=coerce       # strict | coerce | always_auto
```

### LLM
```
LLM_ENABLED=true
LLM_DEFAULT_MODEL=gpt-4o-mini
LLM_TEMPERATURE=0.2
LLM_MAX_TOKENS=512
LLM_CACHE_ENABLED=true
LLM_CACHE_BACKEND=memory
LLM_CACHE_REDIS_URL=
LLM_COST_LOGGING_ENABLED=true
```

---

### Tool Filtering
```
TOOLS_FILTER_ENABLED=false
TOOLS_FILTER_PROFILE=full
TOOLS_FILTER_MODE=include
TOOLS_FILTER_CLUSTERS=
TOOLS_FILTER_TOOLS=
```

### Notifications
```
NOTIFICATIONS_ENABLED=false
NOTIFICATIONS_SIGNALS_DIR=~/.mcp_agent_mail/signals
NOTIFICATIONS_INCLUDE_METADATA=true
NOTIFICATIONS_DEBOUNCE_MS=100
```

### Ack TTL / Escalation
```
ACK_TTL_ENABLED=false
ACK_TTL_SECONDS=1800
ACK_TTL_SCAN_INTERVAL_SECONDS=60
ACK_ESCALATION_ENABLED=false
ACK_ESCALATION_MODE=log
ACK_ESCALATION_CLAIM_TTL_SECONDS=3600
ACK_ESCALATION_CLAIM_EXCLUSIVE=false
ACK_ESCALATION_CLAIM_HOLDER_NAME=
```

### Logging / Output
```
LOG_RICH_ENABLED=true
LOG_LEVEL=INFO
LOG_INCLUDE_TRACE=false
LOG_JSON_ENABLED=false
MCP_AGENT_MAIL_OUTPUT_FORMAT=
TOON_DEFAULT_FORMAT=
TOON_STATS=false
TOON_TRU_BIN=
TOON_BIN=
```

### Instrumentation / Metrics
```
TOOLS_LOG_ENABLED=true
INSTRUMENTATION_ENABLED=false
INSTRUMENTATION_SLOW_QUERY_MS=250
TOOL_METRICS_EMIT_ENABLED=false
TOOL_METRICS_EMIT_INTERVAL_SECONDS=60
```

### Retention / Quota
```
RETENTION_REPORT_ENABLED=false
RETENTION_REPORT_INTERVAL_SECONDS=3600
RETENTION_MAX_AGE_DAYS=180
RETENTION_IGNORE_PROJECT_PATTERNS=demo,test*,testproj*,testproject,backendproj*,frontendproj*
QUOTA_ENABLED=false
QUOTA_ATTACHMENTS_LIMIT_BYTES=0
QUOTA_INBOX_LIMIT_COUNT=0
```

## Core Business Logic

### Agent Naming Rules
- MUST be adjective+noun combinations (e.g., "GreenLake", "BlueDog")
- 62 adjectives × 69 nouns = 4,278 valid combinations
- Case-insensitive unique per project
- NOT descriptive role names

### Contact Enforcement Policies
- **`open`:** No restrictions
- **`auto`:** Recent contact within TTL (24h) OR approved link
- **`contacts_only`:** Requires approved link
- **`block_all`:** Rejects all (except self)

**Auto-allowed:**
- Self-send
- Recent thread participants
- Overlapping file reservations

### File Reservation Logic
- Pattern matching: `pathspec` library (gitignore syntax) or `fnmatch` fallback
- Symmetric matching: `fnmatch(pattern, path) OR fnmatch(path, pattern)`
- Exclusive reservations conflict; shared never conflict
- Self-overlap allowed

### Message Archive Flow
1. Validate sender, recipients, contact policy
2. Process attachments (WebP conversion, inline if < 64KB)
3. Write canonical copy: `messages/{YYYY}/{MM}/{timestamp}_{subject_slug}_{id}.md`
4. Write sender outbox: `agents/{sender}/outbox/{YYYY}/{MM}/...`
5. Write recipient inboxes: `agents/{recipient}/inbox/{YYYY}/{MM}/...`
6. Git commit: `"message {id} from {sender} to {recipients}"`
7. Update SQLite index

### Guard Behavior (Pre-Commit / Pre-Push)
- Enabled only when `WORKTREES_ENABLED` or `GIT_IDENTITY_ENABLED` is true.
- `AGENT_MAIL_GUARD_MODE=block` by default; `warn|advisory` for non-blocking.
- `AGENT_MAIL_BYPASS=1` skips checks.
- Requires `AGENT_NAME` env var.
- Pre-commit:
  - Paths from `git diff --cached --name-only -z --diff-filter=ACMRDTU`.
  - Rename pairs from `git diff --cached --name-status -M -z`.
  - Conflicts if exclusive reservation is active, unexpired, and owned by another agent.
  - Uses `pathspec` if installed, else `fnmatch` with symmetric matching.
- Pre-push:
  - Reads refs from stdin and enumerates commits via `git rev-list`.
  - Falls back to `git diff --name-status -M -z <remote>..<local>`.
  - Same conflict logic as pre-commit.
- Install:
  - Installs chain-runner hook; preserves existing hook as `.orig`.
  - Executes `hooks.d/<hook_name>/*` in lexical order.
  - Adds Windows shim for `.cmd`/`.ps1` when needed.

### Thread ID Rules
- Pattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`
- Max 128 chars
- Must start with alphanumeric

---

## Git Archive Structure

```
{STORAGE_ROOT}/{project_slug}/
├── agents/
│   └── {AgentName}/
│       ├── profile.json
│       ├── inbox/
│       │   └── {YYYY}/{MM}/{timestamp}_{subject}_{id}.md
│       └── outbox/
│           └── {YYYY}/{MM}/{timestamp}_{subject}_{id}.md
├── messages/
│   └── {YYYY}/{MM}/{timestamp}_{subject}_{id}.md
│   └── threads/{thread_id}.md
├── attachments/
│   ├── {sha1[:2]}/{sha1}.webp
│   ├── originals/{sha1[:2]}/{sha1}.{ext}
│   ├── _manifests/{sha1}.json
│   └── _audit/{sha1}.log
└── file_reservations/
    ├── {sha1(path_pattern)}.json
    └── id-{id}.json
```

---

## SQLite Specifics

### WAL Mode Configuration
- `journal_mode=WAL`
- `synchronous=NORMAL`
- Busy timeout: 60s
- WAL autocheckpoint: 1000 pages (~4MB)
- Page cache: 32MB
- Memory-mapped I/O: 256MB

### FTS5 Virtual Table
```sql
CREATE VIRTUAL TABLE IF NOT EXISTS fts_messages
USING fts5(message_id UNINDEXED, subject, body)
```

### FTS Triggers
- `messages_ai` insert trigger -> inserts into `fts_messages`
- `messages_ad` delete trigger -> deletes from `fts_messages`
- `messages_au` update trigger -> deletes and re-inserts

### Performance Indexes
- `idx_messages_created_ts`
- `idx_messages_thread_id`
- `idx_messages_importance`
- `idx_messages_sender_created`
- `idx_messages_project_created`
- `idx_messages_project_sender_created`
- `idx_file_reservations_expires_ts`
- `idx_file_reservations_project_released_expires`
- `idx_file_reservations_project_agent_released`
- `idx_message_recipients_agent`
- `idx_message_recipients_agent_message`
- `idx_agent_links_a_project`
- `idx_agent_links_b_project`
- `idx_agent_links_status`

---

## Share / Export Pipeline (Static Bundle)
Source: `src/mcp_agent_mail/share.py`.

1. Snapshot SQLite (WAL checkpoint + `sqlite3.backup()` into new file).
2. Apply project scope (delete other project rows).
3. Scrub snapshot (presets: `standard`, `strict`, `archive`).
4. Build FTS + materialized views for static viewer.
5. Add performance indexes (subject_lower, sender_lower).
6. Finalize DB for export: `journal_mode=DELETE`, `page_size=1024`, VACUUM, ANALYZE.
7. Bundle attachments:
   - Inline <= 64KiB
   - Detach >= 25MiB
   - Copy others into `attachments/<sha256[:2]>/<sha256>.<ext>`
   - Rewrite `messages.attachments` JSON to bundle paths / data URIs
8. Chunk DB if size >= 20MiB into `chunks/` + `mailbox.sqlite3.config.json`.
9. Copy viewer assets; export viewer data.
10. Write bundle scaffolding: `manifest.json`, README, deploy hints, `_headers`.
11. Optional: sign manifest (Ed25519), encrypt bundle (age), package as zip.

## Concurrency Model

### Database
- SQLite WAL for concurrent readers + single writer
- Exponential backoff with jitter on lock contention
- Circuit breaker: 5 failures → open for 30s
- Connection pooling: 3 base + 4 overflow, recycle every 30min

### Git Archive
- Per-project advisory locks (`.archive.lock` via `filelock.SoftFileLock`)
- Lock metadata: `.archive.lock.owner.json`
- Commit queue with batching (max 10, max wait 50ms)
- Stale lock cleanup on startup

---

## Error Types

```
CAPABILITY_DENIED, NOT_FOUND, INVALID_ARGUMENT, TYPE_ERROR, MISSING_FIELD,
DATABASE_POOL_EXHAUSTED, TIMEOUT, GIT_INDEX_LOCK, RESOURCE_EXHAUSTED,
CONTACT_REQUIRED, CONTACT_BLOCKED, OS_ERROR, DATABASE_ERROR, RESOURCE_BUSY,
PERMISSION_ERROR, CONNECTION_ERROR, UNHANDLED_EXCEPTION
```

---

*Spec extracted by FuchsiaForge | 2026-02-04*  
*Updated by IndigoCreek | 2026-02-04*
