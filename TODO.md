# MCP Agent Mail Rust Port — TODO

## 0. Coordination / Meta
- [ ] Confirm MCP Agent Mail server is stable (health check path, lock handling).
- [ ] Sync with other agents on division of labor and file reservations.
- [ ] Reserve files before major edits in `crates/` (Agent Mail leases).

## 1. Workspace & Crate Scaffolding
- [x] Create workspace `Cargo.toml` with required path deps.
- [x] Add `rust-toolchain.toml` with nightly channel.
- [x] Create crate directories for core/db/storage/server/cli/guard/share/conformance.
- [x] Scaffold minimal `Cargo.toml` for each crate.
- [x] Add placeholder `lib.rs`/`main.rs` for each crate.
- [ ] Add README for Rust port (overview, usage, dev commands).

## 2. Conformance Harness (Skeleton -> Full)
### Skeleton (done)
- [x] `crates/mcp-agent-mail-conformance/tests/conformance/README.md` with schema.
- [x] Fixtures placeholder JSON.
- [x] Python generator stub.
- [x] Rust test to load fixture schema.

### Full Conformance (pending)
- [x] Implement Python reference runner:
  - [x] Start legacy Python server in controlled mode.
  - [x] Call all MCP tools and record outputs.
  - [x] Call all MCP resources and record outputs.
  - [x] Store outputs in fixture JSON with deterministic ordering.
- [x] Define canonical fixture schema fields:
  - [x] Tool output shapes (success + error cases).
  - [x] Resource output shapes (normal + with query params).
  - [x] Expected error JSON for invalid inputs.
- [x] Implement Rust conformance runner:
  - [x] Load fixtures.
  - [x] Invoke Rust MCP tools/resources.
  - [x] Compare outputs and report diffs.
- [ ] Add conformance CLI helper to regenerate fixtures.
- [ ] Add CI task for conformance tests.

## 3. DB Layer (sqlmodel_rust) — Models & Schema
### Models (done - CoralBadger)
- [x] Define SQLModel structs for all tables (`src/models.rs`).
- [x] Include JSON attachments field.
- [x] Provide `utcnow_naive` helper → now using i64 micros with `timestamps.rs` converters.
- [x] Add error types (`src/error.rs`).
- [x] Add timestamp conversion utilities (`src/timestamps.rs`).

### Schema & Indexes (done - CoralBadger)
- [x] Add explicit indexes + unique constraints matching legacy (`src/schema.rs`):
  - [x] `projects.slug` unique index
  - [x] `product_project_links(product_id, project_id)` unique index
  - [x] `agents(project_id, name)` unique index
  - [x] `messages` indexes (project_created, project_sender_created, importance, thread_id)
  - [x] `message_recipients(agent_id, message_id)` index
  - [x] `file_reservations` indexes (project_released_expires, project_agent_released)
  - [x] `agent_links` indexes (a_project, b_project, status) + unique pair
  - [x] `project_sibling_suggestions(project_a, project_b)` unique index
- [x] Add FTS triggers + ensure triggers are installed.
- [ ] Add schema migration story (use sqlmodel_schema MigrationRunner).

### SQLite Tuning (partial - CoralBadger)
- [x] Define WAL pragma setup SQL (`src/schema.rs`).
- [x] Define connection pool config with size/timeout defaults (`src/pool.rs`).
- [x] Wire pool to sqlmodel_pool + sqlmodel_sqlite.
- [ ] Add query tracking + slow query logging (instrumentation).

### Query Stubs (done - CoralBadger)
- [x] Add CRUD operation stubs in `src/queries.rs`.
- [x] Wire queries to actual sqlmodel operations.

## 4. Server Layer (fastmcp_rust)
### Tool + Resource Mapping (skeleton done)
- [x] Stub all tools with correct signature.
- [x] Stub all resources with correct URI templates.
- [x] Register all tools/resources on server builder.
- [x] Align resource URIs to `resource://` scheme and add query-aware variants.
- [ ] Validate resource query matching strategy against fastmcp router behavior.

### Tool Implementations (in progress)
- [x] Implement `health_check` with actual state.
- [x] Implement identity tools: `ensure_project`, `register_agent`, `create_agent_identity`, `whois`.
- [x] Implement messaging tools: `send_message`, `reply_message`, `fetch_inbox`, `mark_message_read`, `acknowledge_message`.
- [x] Implement search tools: `search_messages`, `summarize_thread` (LIKE-based; FTS5 upgrade pending).
- [x] Implement file reservation tools: `file_reservation_paths`, `release`, `renew` (force_release pending full validation).
- [x] Implement contact tools: `request_contact`, `respond_contact`, `list_contacts`, `set_contact_policy`.
- [x] Implement product tools: `ensure_product`, `products_link`, `search_messages_product`, `fetch_inbox_product`, `summarize_thread_product`.
- [x] Implement build slot tools: `acquire_build_slot`, `renew_build_slot`, `release_build_slot`.
- [x] Implement macros: `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`.

### Resource Implementations (done — CoralBadger)
- [x] `resource://config/environment` (real values).
- [x] `resource://tooling/*` (directory/schemas/metrics/locks/capabilities/recent) — full Python format parity.
- [x] `resource://projects` / `project/{slug}` / `agents/{project_key}`.
- [x] `resource://message/{id}` / `thread/{id}` / inbox/outbox/mailbox views (full).
- [x] `resource://file_reservations/{slug}` and ack views (full).
- [x] `resource://views/*` (urgent-unread/ack-required/acks-stale/ack-overdue) — with DB queries.
- [ ] Implement query parsing for static resources (`resource://projects?format=` etc.).

## 5. Storage Layer (Git Archive)
- [ ] Implement archive root creation + `.gitattributes`.
- [ ] Implement per-project locks (`.archive.lock`) and commit locks.
- [ ] Implement commit queue batching.
- [ ] Implement message write pipeline (canonical + inbox/outbox + commit).
- [ ] Implement file reservation writes (digest + id files).
- [ ] Implement attachment pipeline (WebP, originals, manifests, audit logs).
- [ ] Implement notification signals (debounced signal files).
- [ ] Implement read helpers (message by id, thread digest, commit history).

## 6. Guard (Pre-commit/Pre-push)
- [ ] Implement guard install/uninstall with chain-runner hook.
- [ ] Implement pre-commit check (staged paths, rename handling).
- [ ] Implement pre-push check (commit diff scanning).
- [ ] Implement path matching (pathspec + fnmatch fallback).
- [ ] Implement advisory mode and bypass env var.

## 7. Share / Export
- [ ] Implement SQLite snapshot (WAL checkpoint + backup).
- [ ] Implement scrub presets (standard/strict/archive).
- [ ] Implement FTS + materialized views for static viewer.
- [ ] Implement attachment bundling (inline/detach thresholds).
- [ ] Implement chunking for large DB.
- [ ] Implement manifest + signing + encryption (age/Ed25519).
- [ ] Implement preview server and verify/decrypt.

## 8. CLI
- [ ] Implement all Typer-equivalent commands in Rust CLI:
  - [ ] `serve-http`, `serve-stdio` (if needed), `lint`, `typecheck`.
  - [ ] `share` subcommands (export/update/preview/verify/decrypt/wizard).
  - [ ] `archive` subcommands (save/list/restore).
  - [ ] `guard` subcommands (install/uninstall/status/check).
  - [ ] `acks` subcommands (pending/remind/overdue).
  - [ ] `file_reservations` subcommands (list/active/soon).
  - [ ] `config` subcommands (set-port/show-port).
  - [ ] `doctor` subcommands (check/repair/backups/restore).
  - [ ] `projects` subcommands (mark-identity/discovery-init/adopt).
  - [ ] `products` subcommands (ensure/link/status/search/inbox/summarize-thread).
  - [ ] `docs insert-blurbs`.
  - [ ] `am-run` and `amctl env`.

## 9. Benchmarks (done — CoralBadger)
- [x] Create benchmarks reusing conformance fixtures.
- [x] Measure tool latency for 8 representative tools.
- [x] Establish baseline (most tools sub-100µs).
- [ ] Add archive write throughput benchmarks (when storage layer done).

## 10. Dependency Integration
- [ ] Replace any tokio usage with asupersync.
- [ ] Integrate sqlmodel_rust session/pool properly.
- [ ] Use ftui for all CLI rendering.
- [ ] Integrate beads_rust (issue/task awareness).
- [ ] Integrate coding_agent_session_search (agent detection) or port logic to avoid tokio.
- [ ] Evaluate fastmcp resource query param handling; add enhancements or adapters if needed.

## 11. Testing & QA
- [ ] Add unit tests for tool validation rules.
- [ ] Add integration tests for DB + storage pipelines.
- [ ] Add e2e tests for MCP tool calls.
- [ ] Add guard tests for conflict detection.
- [ ] Run full toolchain: `cargo check`, `cargo clippy`, `cargo fmt`, `cargo test`.
