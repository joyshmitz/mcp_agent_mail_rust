# Conformance Fixtures (Python MCP Agent Mail)

This directory contains fixture-based conformance tests that compare Rust outputs
against the legacy Python MCP Agent Mail behavior.

## Fixture Schema

```json
{
  "version": "legacy-python@0.3.0",
  "generated_at": "ISO-8601",
  "tools": {
    "health_check": {
      "cases": [
        {
          "name": "default_env",
          "input": {},
          "expect": {
            "ok": {
              "status": "ok",
              "environment": "development",
              "http_host": "127.0.0.1",
              "http_port": 8765,
              "database_url": "sqlite+aiosqlite:///./storage.sqlite3"
            }
          }
        }
      ]
    }
  },
  "resources": {
    "resource://config/environment": {
      "cases": [
        {
          "name": "default_env",
          "input": {},
          "expect": {
            "ok": {
              "environment": "development",
              "database_url": "sqlite+aiosqlite:///./storage.sqlite3",
              "http": { "host": "127.0.0.1", "port": 8765, "path": "/api/" }
            }
          }
        }
      ]
    }
  }
}
```

Notes:
- Each tool/resource can have multiple `cases` (happy path + error cases).
- `input` is the tool args object (for tools) or resource query input (for resources).
- `expect` must contain exactly one of `ok` or `err`.

## Generating Fixtures (Python Reference)

```
legacy_python_mcp_agent_mail_code/mcp_agent_mail/.venv/bin/python \
  crates/mcp-agent-mail-conformance/tests/conformance/python_reference/generate_fixtures.py
```

Notes:
- Use the legacy project venv Python. The generator imports `mcp_agent_mail`, which is not available in the system `python3` env.

The generator should:
- Start legacy Python MCP Agent Mail in a controlled mode.
- Call each tool and resource endpoint.
- Record JSON output for parity comparisons.

## Running Conformance Tests

```
cargo test -p mcp-agent-mail-conformance
```
