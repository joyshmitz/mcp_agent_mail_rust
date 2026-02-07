# MCP Agent Mail (Rust Port)

This repository is a Rust port of the legacy Python `mcp_agent_mail` project. It provides a
mail‑like coordination layer for coding agents via an MCP server, with Git‑backed artifacts and
SQLite indexing.

## Quick Start

### Easiest Local Run (`am`)
```bash
cd /data/projects/mcp_agent_mail_rust
alias am='/data/projects/mcp_agent_mail_rust/scripts/am'
am
```

What `am` / `am serve` does by default:
- uses MCP base path `/mcp/` (override with `--path api` or `--api`)
- sets `LOG_RICH_ENABLED=true`
- auto-loads `HTTP_BEARER_TOKEN` from `~/mcp_agent_mail/.env` if not already set

### Run MCP Server (stdio)
```bash
cargo run -p mcp-agent-mail
```

### Run MCP Server (HTTP)
```bash
cargo run -p mcp-agent-mail -- serve --host 127.0.0.1 --port 8765
```

Notes:
- The server accepts both `/mcp/` and `/api/` as MCP HTTP base-path aliases for local/dev compatibility.
- `mcp-agent-mail serve` now supports explicit `--transport mcp|api|auto` and `--path`.
- `scripts/am` options: `--path mcp|api`, `--mcp`, `--api`, `--host`, `--port`, `--env-file`, `--no-auth`.

### Run CLI
```bash
cargo run -p mcp-agent-mail-cli -- --help
```

## Architecture

This is a Cargo workspace with small crates and a strict dependency layering. The goal is to keep hot-path performance work isolated (DB + storage) and keep the MCP/tool surface thin and testable.

### Crate Map

| Crate | Kind | Purpose |
|------|------|---------|
| `mcp-agent-mail` | bin | Server entrypoint and CLI glue (`serve`, stdio transport, etc.). |
| `mcp-agent-mail-server` | lib | HTTP/MCP server runtime + web UI + TUI surfaces. |
| `mcp-agent-mail-tools` | lib | MCP tool implementations (register agent, send messages, reservations, search, etc.). |
| `mcp-agent-mail-storage` | lib | Git-backed artifact archive writing (commit coalescing, archive locks, spill/backpressure policies). |
| `mcp-agent-mail-db` | lib | SQLite schema + queries + pool/retry/caching. |
| `mcp-agent-mail-core` | lib | Shared config, models, errors, metrics, lock-order rules. Keep this “bottom of the stack”. |
| `mcp-agent-mail-cli` | bin (`am`) | Operator CLI/launcher helpers and local tooling. |
| `mcp-agent-mail-guard` | lib | Pre-commit guard and file-reservation enforcement helpers. |
| `mcp-agent-mail-share` | lib | Snapshot/bundle/export helpers (shareable artifacts). |
| `mcp-agent-mail-conformance` | test harness | Fixture-based parity tests against legacy Python behavior. |

### Dependency Layering

```text
mcp-agent-mail-core
  ├─ mcp-agent-mail-db
  ├─ mcp-agent-mail-storage
  ├─ mcp-agent-mail-guard
  ├─ mcp-agent-mail-share
  └─ mcp-agent-mail-tools (core + db + storage + guard)
       └─ mcp-agent-mail-server (core + db + storage + tools + fastmcp + ftui)
            ├─ mcp-agent-mail (bin)
            ├─ mcp-agent-mail-cli (bin: am)
            └─ mcp-agent-mail-conformance (tests)
```

### Server Module Map (Where Things Live)

| Area | Files/globs | Notes |
|------|-------------|------|
| Server runtime + HTTP/MCP routing | `crates/mcp-agent-mail-server/src/lib.rs` | Owns transports, auth, base-path aliases, and router wiring. |
| Web UI (mail + static assets) | `crates/mcp-agent-mail-server/src/mail_ui.rs`, `crates/mcp-agent-mail-server/src/static_files.rs`, `crates/mcp-agent-mail-server/src/templates.rs` | Operator-facing web surfaces. |
| Console/rich logging | `crates/mcp-agent-mail-server/src/console.rs`, `crates/mcp-agent-mail-server/src/tool_metrics.rs`, `crates/mcp-agent-mail-server/src/theme.rs` | High-signal operator output and metrics panels. |
| TUI event backbone + shared state | `crates/mcp-agent-mail-server/src/tui_events.rs`, `crates/mcp-agent-mail-server/src/tui_bridge.rs` | Typed `MailEvent` model + bounded ring buffer + shared counters/state. |
| TUI data ingestion | `crates/mcp-agent-mail-server/src/tui_poller.rs` | Background DB polling that feeds the shared state (stats + agent list). |
| Full-screen TUI | `crates/mcp-agent-mail-server/src/tui_app.rs`, `crates/mcp-agent-mail-server/src/tui_chrome.rs`, `crates/mcp-agent-mail-server/src/tui_screens/**` | Interactive AgentMailTUI (“ops cockpit”). |
| Housekeeping | `crates/mcp-agent-mail-server/src/startup_checks.rs`, `crates/mcp-agent-mail-server/src/cleanup.rs`, `crates/mcp-agent-mail-server/src/retention.rs`, `crates/mcp-agent-mail-server/src/ack_ttl.rs` | Startup validation and background maintenance. |

Console/TUI layout persistence and the `CONSOLE_*` configuration contract live in `crates/mcp-agent-mail-core/src/config.rs` (real env + a persisted envfile at `CONSOLE_PERSIST_PATH`).

### Ownership Map (File Reservations)

Before editing, reserve the smallest surface that matches your work. Suggested reservation globs:

| Area | Reserve paths/globs |
|------|----------------------|
| Core types/config | `crates/mcp-agent-mail-core/src/**` |
| SQLite schema/queries/pool | `crates/mcp-agent-mail-db/src/**` |
| Git archive + commit coalescing | `crates/mcp-agent-mail-storage/src/**` |
| MCP tool implementations | `crates/mcp-agent-mail-tools/src/**` |
| Server router + web UI | `crates/mcp-agent-mail-server/src/lib.rs`, `crates/mcp-agent-mail-server/src/static_files.rs`, `crates/mcp-agent-mail-server/src/templates.rs`, `crates/mcp-agent-mail-server/src/mail_ui.rs` |
| TUI | `crates/mcp-agent-mail-server/src/tui_*.rs`, `crates/mcp-agent-mail-server/src/tui_screens/**` |
| CLI/launcher | `crates/mcp-agent-mail-cli/src/**`, `scripts/am` |
| Pre-commit guard | `crates/mcp-agent-mail-guard/src/**` |
| Share/export | `crates/mcp-agent-mail-share/src/**` |
| Conformance fixtures/harness | `crates/mcp-agent-mail-conformance/src/**`, `crates/mcp-agent-mail-conformance/tests/conformance/**` |

## Configuration (Env Vars)

Config is loaded from environment variables (and `.env` in the working directory). See
`crates/mcp-agent-mail-core/src/config.rs` for the full set.

Console/logging related:

- `LOG_RICH_ENABLED` (default: `true`): enable rich/ftui console output.
- `LOG_TOOL_CALLS_ENABLED` (default: `true`): enable tool call start/end panel logging.
- `LOG_TOOL_CALLS_RESULT_MAX_CHARS` (default: `2000`): max characters of tool result JSON rendered in panels.

Console layout + persistence (rich TTY only; interactive tuning is HTTP mode only):

- `CONSOLE_PERSIST_PATH` (default: `~/.config/mcp-agent-mail/config.env`): user-local envfile where console prefs are read/written. Read from real env only; `CONSOLE_*` keys do not fall back to repo `.env`.
- `CONSOLE_AUTO_SAVE` (default: `true`): automatically persist console prefs on interactive changes.
- `CONSOLE_INTERACTIVE` (default: `true`): enable interactive console layout tuning (HTTP + TTY only).
- `CONSOLE_UI_HEIGHT_PERCENT` (default: `33`, clamp `10..80`): inline HUD height percent.
- `CONSOLE_UI_ANCHOR` (default: `bottom`): `bottom|top`.
- `CONSOLE_UI_AUTO_SIZE` (default: `false`): use inline auto-sizing mode.
- `CONSOLE_INLINE_AUTO_MIN_ROWS` (default: `8`, clamp `>=4`).
- `CONSOLE_INLINE_AUTO_MAX_ROWS` (default: `18`, clamp `>=min`).
- `CONSOLE_SPLIT_MODE` (default: `inline`): `inline|left` (left requires AltScreen work; see `br-1m6a.20`).
- `CONSOLE_SPLIT_RATIO_PERCENT` (default: `30`, clamp `10..80`): requested left split ratio.
- `CONSOLE_THEME` (default: `cyberpunk_aurora`): console theme id (see `br-1m6a.12`).

## Conformance Tests

Run fixture-based parity tests against the Rust server router:
```bash
cargo test -p mcp-agent-mail-conformance
```

### Regenerate Fixtures (Legacy Python)
Use the legacy Python venv (bundled in `legacy_python_mcp_agent_mail_code/mcp_agent_mail/.venv`):
```bash
legacy_python_mcp_agent_mail_code/mcp_agent_mail/.venv/bin/python \
  crates/mcp-agent-mail-conformance/tests/conformance/python_reference/generate_fixtures.py
```

## Benchmarks
```bash
cargo bench -p mcp-agent-mail
```

## Dev Workflow

Quality gates:
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Multi-Agent Builds (Target Dir Isolation)

When multiple agents build in parallel, set a per-agent target dir to avoid lock contention:
```bash
export CARGO_TARGET_DIR="/tmp/target-$(whoami)-am"
```

## Notes

- Rust nightly is required (see `rust-toolchain.toml`).
- This port uses local crates for MCP, SQLite, async IO, and UI:
  - `/dp/fastmcp_rust`
  - `/dp/sqlmodel_rust`
  - `/dp/asupersync`
  - `/dp/frankentui`
  - `/dp/beads_rust`
  - `/dp/coding_agent_session_search`
