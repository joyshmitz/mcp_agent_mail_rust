# Feature Parity: MCP Agent Mail (Python -> Rust)

## Status Legend
- Not Started
- In Progress
- Implemented
- Verified (Conformance)
- Verified (Tests)

## Core Server Features
| Feature | Status | Evidence |
| --- | --- | --- |
| FastMCP server (stdio transport) | Implemented | `crates/mcp-agent-mail-server/src/lib.rs` |
| FastMCP server (HTTP) | Implemented | `crates/mcp-agent-mail-server/src/lib.rs` |
| Tool registry + tool clusters | Verified (Conformance) | `crates/mcp-agent-mail-server/src/lib.rs` |
| Resource URI system (`resource://...`) | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/resources.rs` |
| Tool filtering profiles (full/core/minimal/messaging/custom) | Not Started | |
| Tool metrics snapshot | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/resources.rs` (`resource://tooling/metrics`) |
| Recent tool usage tracking | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/resources.rs` (`resource://tooling/recent/{window_seconds}`) |

## Identity & Projects
| Feature | Status | Evidence |
| --- | --- | --- |
| Ensure project | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/identity.rs` |
| Register agent | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/identity.rs` |
| Create agent identity | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/identity.rs` |
| Agent contact policy | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/contacts.rs` |
| Agent links (contact requests) | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/contacts.rs` |
| Product bus (products + links) | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/products.rs` |

## Messaging
| Feature | Status | Evidence |
| --- | --- | --- |
| Send message (attachments stubbed) | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/messaging.rs` |
| Reply message | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/messaging.rs` |
| Fetch inbox | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/messaging.rs` |
| Search messages (FTS: LIKE fallback) | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/search.rs` |
| Summarize thread (LLM disabled mode) | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/search.rs` |
| Acknowledge + read tracking | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/messaging.rs` |
| Ack-required views | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/resources.rs` |

## File Reservations
| Feature | Status | Evidence |
| --- | --- | --- |
| Reserve paths (exclusive/shared) | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/reservations.rs` |
| Renew reservations | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/reservations.rs` |
| Release reservations | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/reservations.rs` |
| Force-release stale reservations | Not Started | |
| Reservation views | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/resources.rs` |

## Build Slots
| Feature | Status | Evidence |
| --- | --- | --- |
| Acquire build slot | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/build_slots.rs` |
| Renew build slot | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/build_slots.rs` |
| Release build slot | Verified (Conformance) | `crates/mcp-agent-mail-tools/src/build_slots.rs` |

## CLI & Ops
| Feature | Status | Evidence |
| --- | --- | --- |
| CLI command parity | Not Started | |
| Config management | Not Started | |
| Doctor check/repair | Not Started | |
| Guard install/uninstall | Not Started | |
| Share export/update/verify | Not Started | |
| Static bundle preview | Not Started | |

## Storage & Database
| Feature | Status | Evidence |
| --- | --- | --- |
| SQLite schema + migrations (idempotent init) | Verified (Tests) | `crates/mcp-agent-mail-db/src/schema.rs` |
| DB pool + WAL PRAGMAs | Verified (Tests) | `crates/mcp-agent-mail-db/src/pool.rs` |
| Core queries used by tools | Verified (Conformance) | `crates/mcp-agent-mail-db/src/queries.rs` |
| FTS indexing | Implemented | `crates/mcp-agent-mail-db/src/schema.rs` |
| Git archive write pipeline | Not Started | |
| Attachment handling + WebP conversion | Not Started | |
| Query tracking + slow queries | Not Started | |

## Conformance & Benchmarks
| Feature | Status | Evidence |
| --- | --- | --- |
| Python fixture generator | Verified (Tests) | `crates/mcp-agent-mail-conformance/tests/conformance/python_reference/generate_fixtures.py` |
| Rust conformance tests | Verified (Tests) | `crates/mcp-agent-mail-conformance/tests/conformance.rs` |
| Benchmark suite | Verified (Tests) | `crates/mcp-agent-mail/benches/benchmarks.rs` |
| Feature parity report complete | Not Started | |
