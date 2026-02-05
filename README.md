# MCP Agent Mail (Rust Port)

This repository is a Rust port of the legacy Python `mcp_agent_mail` project. It provides a
mail‑like coordination layer for coding agents via an MCP server, with Git‑backed artifacts and
SQLite indexing.

## Quick Start

### Run MCP Server (stdio)
```bash
cargo run -p mcp-agent-mail
```

### Run MCP Server (HTTP)
```bash
cargo run -p mcp-agent-mail -- serve --host 127.0.0.1 --port 8765
```

### Run CLI
```bash
cargo run -p mcp-agent-mail-cli -- --help
```

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

