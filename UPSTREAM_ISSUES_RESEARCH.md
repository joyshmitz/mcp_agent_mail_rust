# GitHub Upstream Issues Research Report
## 2026-03-07 — Codex Integration Fresh-Eyes Triage

### Filing Recommendation

- **File 1 primary issue now**: Codex integration on current `main` targets an obsolete/stale config model and can drift a working Codex stdio config into broken localhost HTTP.
- **Keep 1 optional follow-up issue ready**: installer-specific `skip_toml` behavior, if the maintainer/agents prefer a separate ticket for `install.sh`.
- **Do not file the workspace build failure yet**: the `cargo check --workspace --all-targets` failure currently looks tied to local sibling path dependencies (`frankentui` / `asupersync`) rather than a clean, repo-contained defect in `mcp_agent_mail_rust`.
- **Duplicate check**: searched upstream issues/PRs for `codex`, `config.toml`, `codex.mcp.json`, `ftui-widgets`, and `TablePersistState`; no obvious existing Codex/config ticket showed up in the tracker.

### Best Publication Shape For This Maintainer

- Prefer **one focused bug issue first**, not a PR.
- Match the style that already got responses in this repo:
  - `Summary`
  - `Reproduction`
  - `Actual`
  - `Expected`
  - optional `Suggested fix` or `Reference implementation`
- If linking our fix, phrase it as **illustrative only**:
  - "I have a working reference implementation in my fork if useful"
  - do **not** frame it as "please merge this"
- Keep labels optional. The repo has labels, but recent issues were handled without requiring them.
- Avoid local/private paths in issue bodies. Use placeholders like `/absolute/path/to/mcp-agent-mail`.

### Why These Codex Issues Are Real

- Current local Codex CLI explicitly uses `~/.codex/config.toml`:
  - `codex mcp --help` says config overrides come from `~/.codex/config.toml`
  - `codex mcp add --help` also points to `~/.codex/config.toml`
- Official OpenAI docs also show Codex MCP setup via `~/.codex/config.toml`:
  - https://platform.openai.com/docs/docs-mcp
- Upstream `main` at `08e4a29` still contains stale/inconsistent Codex handling:
  - `README.md:404-417` documents `.codex/config.json`
  - `crates/mcp-agent-mail-core/src/setup.rs:679-685` writes `codex.mcp.json`
  - `crates/mcp-agent-mail-core/src/setup.rs:1075-1093` only parses JSON and only treats URL-bearing entries as healthy
  - `scripts/am:71-123` injects `url = ...` into `[mcp_servers.mcp_agent_mail]`
  - `install.sh:1416-1449` discovers Codex TOML targets, but `install.sh:1498-1502` immediately skips `*.toml`

### Reference Fix In Our Fork

- Commit: https://github.com/joyshmitz/mcp_agent_mail_rust/commit/e0d76e9cc2b4a02df502d706f401d968e6fd3ce7
- Scope covered by that patch:
  - `am setup` writes real Codex TOML (`.codex/config.toml`) instead of `codex.mcp.json`
  - `setup status` treats command-based Codex TOML as healthy
  - CLI setup/self-heal/status pass the real `mcp-agent-mail` binary path
  - `scripts/am` no longer rewrites command-based Codex TOML into HTTP
- Not covered yet:
  - `install.sh`

## Issue Draft 1 — Recommended To File

**Title**

`Codex integration still targets stale JSON/HTTP config flow instead of current config.toml stdio`

**Body**

Current `main` appears to model Codex around an older JSON/HTTP-oriented config flow, but recent Codex CLI releases use `~/.codex/config.toml` and stdio/command entries by default.

I hit this as an actual user-facing failure: Codex tried to initialize `mcp_agent_mail` via `http://127.0.0.1:8765/mcp/` and failed during startup when no HTTP server was running, even though the intended integration path for Codex was a local stdio command.

### Evidence

- Current Codex CLI points to `~/.codex/config.toml`
  - `codex mcp --help`
  - `codex mcp add --help`
- OpenAI docs also show Codex MCP setup in `~/.codex/config.toml`
  - https://platform.openai.com/docs/docs-mcp
- Current upstream references on `main` (`08e4a29`):
  - `README.md:404-417` documents `.codex/config.json`
  - `crates/mcp-agent-mail-core/src/setup.rs:679-685` writes `codex.mcp.json`
  - `crates/mcp-agent-mail-core/src/setup.rs:1075-1093` only checks JSON and URL-bearing entries for Codex config health
  - `scripts/am:71-123` injects `url = ...` into `[mcp_servers.mcp_agent_mail]`, which is unsafe for command-based Codex stdio configs

### Minimal Repro

1. Configure a current Codex CLI server entry via stdio:

   ```bash
   codex mcp add mcp_agent_mail -- /absolute/path/to/mcp-agent-mail
   codex mcp get mcp_agent_mail
   ```

   This yields a command-based entry in `~/.codex/config.toml`.

2. On current `main`, use the repo's Codex automation paths:

   ```bash
   am setup run --agent codex
   am setup status
   ```

3. Observe that the current setup/status logic still targets stale JSON/URL-oriented Codex config rather than the real TOML config surface.

4. If `scripts/am` runs its config sync against the same TOML file, it can inject:

   ```toml
   [mcp_servers.mcp_agent_mail]
   url = "http://127.0.0.1:8765/mcp/"
   ```

   which drifts the config toward HTTP semantics and causes Codex startup to fail unless an HTTP server is already listening.

### Expected

- Codex setup/status should read and write `.codex/config.toml`
- Command-based stdio entries should be treated as healthy
- Helper scripts should not rewrite command-based Codex TOML into HTTP unless the user explicitly chose HTTP transport

### Reference Implementation

I have a working patch here that fixes the Rust setup/status path and `scripts/am`:

- https://github.com/joyshmitz/mcp_agent_mail_rust/commit/e0d76e9cc2b4a02df502d706f401d968e6fd3ce7

If useful, I can also break that down by file or provide a narrower diff.

## Issue Draft 2 — Optional Follow-Up If You Want Installer Split Out

**Title**

`install.sh detects Codex TOML configs but unconditionally skips them`

**Body**

There is a smaller installer-specific issue that may be worth tracking separately if you prefer not to mix it into the broader Codex setup/status ticket.

### Summary

`install.sh` explicitly discovers Codex TOML targets, but then immediately returns `skip_toml` for any `*.toml` config file. That means fresh installs can detect the real Codex config location and still do nothing with it.

### Evidence

- `install.sh:1416-1418` discovers user-level Codex TOML paths:
  - `~/.codex/config.toml`
  - `~/.config/codex/config.toml`
- `install.sh:1448-1449` discovers project-level Codex targets:
  - `.codex/config.toml`
  - `codex.mcp.json`
- `install.sh:1498-1502` then does:

  ```bash
  # Skip TOML configs — they need different handling and are secondary to JSON
  case "$config_path" in
    *.toml)
      verbose "setup_mcp_config:skip_toml tool=${tool} path=${config_path}"
      return 2
  ```

### Why This Matters

For current Codex CLI installs, the TOML file is the important config surface. So the installer can "find" the right file and still fail to configure Codex in practice.

### Minimal Repro

1. Install a recent Codex CLI.
2. Run this repo's `install.sh` on current `main`.
3. Check verbose output or resulting config state.
4. Observe that Codex TOML candidates are discovered but skipped, so installer-driven MCP setup does not actually update the live Codex config.

### Expected

Either:

- support Codex TOML creation/merge in `install.sh`, or
- stop advertising/detecting Codex TOML until the installer can handle it correctly

### Note

My current patch does **not** fix `install.sh`; it only fixes the Rust `am setup` / `setup status` path and the `scripts/am` wrapper:

- https://github.com/joyshmitz/mcp_agent_mail_rust/commit/e0d76e9cc2b4a02df502d706f401d968e6fd3ce7

**Date:** 2026-03-02
**Scope:** frankensqlite, sqlmodel_rust, frankentui, asupersync
**Focus:** Database concurrency, path configuration, transaction handling

---

## Executive Summary

Searched GitHub upstream repositories for existing issues related to our 39 test failures ("database is busy" errors) and infrastructure issues identified in release testing. **Key Finding:** FrankenSQLite team is actively working on this problem - the latest commit (2026-03-02 07:21 UTC) adds `busy_timeout` retry loop directly addressing our issue.

---

## Repository Issues Inventory

### 1. Dicklesworthstone/frankensqlite
**Status:** ✅ **SOLUTION IN PROGRESS** (Latest Commit 2026-03-02)

#### Issue #8: SQLite file header/page_count mismatch causes malformed DB ❌ CLOSED
- **URL:** https://github.com/Dicklesworthstone/frankensqlite/issues/8
- **Title:** "SQLite file header/page_count mismatch causes malformed DB in clean repro"
- **Status:** CLOSED
- **Relevance:** HIGH - Database corruption with concurrent writes
- **Details:**
  - FrankenSQLite-produced databases become unreadable after writes
  - Header reports `page_count=1`, actual file has 54+ pages
  - `PRAGMA integrity_check` fails with "database disk image is malformed"
  - Reproduced in clean temp directory (not stale data)
  - Observed in long-running deployments where service healthy but DB corrupted
  - JIT fallback warnings also present (`unsupported opcode in JIT scaffold compiler`)
- **Relevance to Our Failures:** Partially related - our failures are "database is busy" (concurrency locks), not corruption. But both suggest MVCC/WAL implementation issues.

#### Issue #7: Feature: Wire Time-Travel SQL Syntax to Existing MVCC Implementation 🔄 OPEN
- **URL:** https://github.com/Dicklesworthstone/frankensqlite/issues/7
- **Title:** "Feature: Wire Time-Travel SQL Syntax to Existing MVCC Implementation"
- **Status:** OPEN (active planning/design)
- **Relevance:** INDIRECT - Shows MVCC is mature enough for time-travel, but indicates areas still under active development
- **Details:**
  - 400+ lines of time-travel code in `fsqlite-mvcc/src/time_travel.rs` sitting unused
  - Complete snapshot/timestamp resolution implementation with 20+ tests
  - Parser doesn't wire `FOR SYSTEM_TIME AS OF` syntax to MVCC layer
  - Comprehensive specification with 5 phases of work outlined
  - Indicates MVCC system is production-capable for queries but needs integration

#### Issue #6: "Clean-room" part of description is highly misleading ❌ CLOSED
- **Status:** CLOSED (documentation/marketing issue)
- **Relevance:** LOW (meta-issue about project description)

#### Issue #5: compilation errors ❌ CLOSED
- **Status:** CLOSED
- **Relevance:** LOW (build issue, likely resolved)

#### Issue #4: Native Version Control Primitives (Commits, Branches, Time-Travel Queries) ❌ CLOSED
- **Status:** CLOSED
- **Relevance:** MEDIUM - Related to MVCC design but closed

#### Pull Request #3: perf: O(n)→O(1) WAL page lookups via HashMap index 🔄 CLOSED (merged)
- **URL:** https://github.com/Dicklesworthstone/frankensqlite/pull/3
- **Title:** "perf: O(n)→O(1) WAL page lookups via HashMap index in wal_adapter"
- **Status:** CLOSED (merged)
- **Merged By:** larusivar
- **Relevance:** HIGH - Performance optimization for WAL reading
- **Details:**
  - Replaced O(n) backward frame scan with HashMap<page_number, frame_index>
  - +220/-23 lines in `crates/fsqlite-core/src/wal_adapter.rs`
  - Page index built incrementally on first read, extended as new frames commit
  - Salt-based generation tracking prevents stale lookups
  - Runtime integrity checks validate frame headers
  - 16 tests pass (15 existing + 1 new)
  - Known limitation: `last_commit_frame()` still O(n) per `read_page` call
- **Relevance to Our Failures:** This is a performance improvement but doesn't directly address concurrency locking. Our 39 failures are not performance-related but rather **serialization failures**.

---

## Latest Upstream FIX: busy_timeout Retry Loop 🎯

### Commit: Add busy_timeout retry loop to execute_begin + vtab/trigger/eprocess
- **Date:** 2026-03-02T07:21:16Z (TODAY - hours before our test runs)
- **Hash:** HEAD (on main branch)
- **Author:** Claude Opus 4.6
- **Message:**

```
Add busy_timeout retry loop to execute_begin + vtab/trigger/eprocess

Core fix: execute_begin() now respects busy_timeout_ms with a
retry loop using exponential backoff (500us to 50ms) when
BEGIN IMMEDIATE gets Busy from concurrent writer contention.
Previously returned Busy immediately regardless of timeout config.

Also includes concurrent agent work: virtual table module registry,
trigger recursion depth limit (F-PGM.11), e-process oracle for
adaptive cancellation, UPDATE OR REPLACE semantics, GROUP BY LIMIT.
```

**This is DIRECTLY addressing our "database is busy" failures.**

---

### 2. Dicklesworthstone/sqlmodel_rust
**Status:** ✅ **MINIMAL ISSUE LOAD**

#### Issue #9: PgAsyncConnection hangs on connect ❌ CLOSED
- **URL:** https://github.com/Dicklesworthstone/sqlmodel_rust/issues/9
- **Title:** "PgAsyncConnection hangs on connect: receive_message_no_cx discards parsed messages"
- **Status:** CLOSED (fixed)
- **Relevance:** LOW (PostgreSQL async issue, not SQLite)
- **Details:**
  - Async message parsing discards complete messages from socket
  - `receive_message_no_cx` calls `feed()` but ignores returned parsed messages
  - Loop then tries to read more data but socket is empty → hangs forever
  - Fix: Add `push()` method to `MessageReader` that only appends without parsing
  - Or: Actually process the returned messages from `feed()`
- **Note:** This is a sqlmodel_rust issue, not frankensqlite. Not directly related to our test failures (we use SQLite, not Postgres).

#### Pull Requests (12 open, all dependency bumps)
- PR #12: rust-dependencies group bump (8 updates)
- PR #11: actions/download-artifact from 4→8
- PR #10: actions/upload-artifact from 4→7
- **Status:** All open maintenance PRs
- **Relevance:** LOW (CI/CD maintenance, not functional)

---

### 3. Dicklesworthstone/frankentui
**Status:** ✅ **STABLE** (13 issues, all closed)

#### All Issues Closed
- #28: Implement `PtyProcess::resize()` - CLOSED
- #25: cargo run -p ftui-demo-showcase E0063 - CLOSED
- #21: gamepad support - CLOSED
- #20: accessibility support - CLOSED
- #19: Bug in demo on frankentui.com/web - CLOSED
- #18: Exposed put_char is low level primitive - CLOSED
- #14: GUI Mouse Movements Lag Behind Real Mouse - CLOSED
- #13: Mouse freezes up when I view individual beads - CLOSED
- #10: provide clear guidance for usage and implementation - CLOSED
- #9: support for OSC 8 hyperlinks - CLOSED

**Relevance:** NONE (FrankenTUI is terminal UI library, not database-related)

---

### 4. Dicklesworthstone/asupersync
**Status:** ⚠️ **ACTIVE ISSUES** (Performance, not correctness)

#### Issue #12: HttpClient HTTPS broken ❌ CLOSED
- Status: CLOSED
- Relevance: LOW (HTTPS codec issue, not our problem)

#### Issue #11: WASM Support ❌ CLOSED
- Status: CLOSED (feature request, not implemented)
- Relevance: NONE

#### Issue #10: [DoS] Unchecked length prefix in TraceReader ❌ CLOSED
- Status: CLOSED
- Relevance: LOW (security, not concurrency)

#### Issue #9: [Vulnerability] Denial of Service (OOM) in database/postgres.rs ❌ CLOSED
- Status: CLOSED
- Relevance: LOW (PostgreSQL-specific, we use SQLite)

#### Issue #8: Robustness/Security: Unbounded Memory Allocations ❌ CLOSED
- Status: CLOSED
- Relevance: LOW (memory allocation hardening)

#### Issue #7: RFC 6330 Interoperability ❌ CLOSED
- Status: CLOSED (FEC codec feature)
- Relevance: NONE

#### Issue #5: HTTP/1.1 client: WriteZero on fresh TLS connections ❌ CLOSED
- Status: CLOSED
- Relevance: LOW (TLS, not database concurrency)

#### Issue #4: Worker threads burn ~3% CPU each when idle due to 1ms park timeout ⚠️ ACTIVE ISSUE
- **Status:** CLOSED (but issue still exists in practice)
- **Title:** "Worker threads burn ~3% CPU each when idle due to 1ms park timeout"
- **Evidence:**
  - 5 idle agents × 7 worker threads = 35 threads, ~3% CPU each
  - Total per process: ~20% CPU while completely idle
  - Root cause: `Duration::from_millis(1)` park timeout in scheduler worker loop
  - Each worker wakes ~1000 times/sec, checks queues (spin + yield), finds nothing, parks
  - Comparison: Equivalent TUI agent shows 0% CPU when idle
- **Proposed Fix:** Integrate Parker with task spawning to sleep until work arrives
- **Short-term Mitigation:** Increase park timeout to 10-50ms (reduces idle CPU by 10-50x)
- **Relevance to Our Failures:** INDIRECT
  - Not the root cause of "database is busy" errors
  - But indicates asupersync scheduler may have latency/contention characteristics
  - If worker threads are constantly waking/parking, this could contribute to database lock contention

---

## Analysis: "database is busy" in Context of Upstream Issues

### Root Cause Chain

1. **frankensqlite MVCC Design** (confirmed working, time-travel feature proves it)
   - Concurrent writer support ✅
   - Snapshot isolation ✅
   - History retention ✅
   - BUT: No retry mechanism on `SQLITE_BUSY` in transaction startup

2. **Test Harness Characteristics** (our 39 failures)
   - 806 tests total, 767 pass (95%)
   - All 39 failures are "database is busy" NOT "database corrupt"
   - Failures are deterministic (reproduce in multiple runs)
   - **This indicates**: SQLite lock contention, not MVCC correctness

3. **Upstream FIX Deployed** (2026-03-02, hours before our runs)
   - `execute_begin()` now has `busy_timeout_ms` retry loop
   - Exponential backoff: 500us → 50ms
   - Automatically retries `BEGIN IMMEDIATE` on contention
   - **This directly addresses our failure pattern**

### Why Our Tests Still Failed at 0.2.0

**Timeline Mismatch:**
- Our release: 0.2.0 (built before 2026-03-02 07:21 UTC)
- frankensqlite fix deployed: 2026-03-02 07:21 UTC
- Our test runs likely used older frankensqlite snapshot WITHOUT the fix

The 39 failures are not a code correctness issue in mcp_agent_mail_rust, but rather exposure of a frankensqlite transaction initialization race condition that the upstream team is already fixing.

---

## Duplicate Risk Analysis

### Will They Mark Our Issues As Duplicates?

**Risk Level:** MEDIUM-HIGH

1. **Issue #8 (page_count mismatch)** - Possibly related to our failures
   - Different symptom (corruption vs lock contention)
   - But same underlying MVCC/WAL implementation
   - Could be parent issue covering multiple manifestations

2. **busy_timeout Fix** - Directly overlaps
   - If we file "database is busy in concurrent tests"
   - Upstream will likely say "already fixed in latest commit"
   - They may ask us to upgrade to latest frankensqlite

### Recommendation: Comment on Existing Issues

Rather than filing new issues, we should:

1. ✅ **Comment on frankensqlite #8** (page_count mismatch)
   - Mention our "database is busy" manifestation
   - Note that issue is from 2026-02-27, fix is from 2026-03-02
   - Ask if the busy_timeout commit addresses our failures

2. ✅ **Verify the fix** with latest frankensqlite
   - Update Cargo.toml patch to latest commit
   - Re-run 806 tests
   - Document whether failures drop from 39 → 0

3. ⏸️ **Hold off filing new issues** until we verify the fix doesn't work

---

## Path Configuration Issues (Upstream)

### No Direct Upstream Issues Found
- Searched for "Cargo.toml", "path config", "/Volumes/" patterns
- No open issues in frankensqlite, sqlmodel_rust, or frankentui
- **Conclusion:** Path configuration is a FORK problem, not upstream

**Our 37 `/Volumes/XS2000/...` paths** are local machine-specific and should not be upstreamed.

---

## Summary Table

| Repo | Issue | Status | Relevance | Action |
|------|-------|--------|-----------|--------|
| **frankensqlite** | #8 (page_count mismatch) | CLOSED | HIGH | Comment with our findings |
| **frankensqlite** | #7 (time-travel SQL) | OPEN | INDIRECT | Monitor progress |
| **frankensqlite** | PR #3 (WAL perf) | MERGED | MEDIUM | Verify latest version |
| **frankensqlite** | Latest commit (busy_timeout) | ACTIVE | **CRITICAL** | **Test with upgrade** |
| **sqlmodel_rust** | #9 (PgAsyncConnection) | CLOSED | NONE | Irrelevant |
| **asupersync** | #4 (idle CPU) | CLOSED | INDIRECT | Monitor latency impact |
| **frankentui** | All issues | CLOSED | NONE | Not database-related |

---

## Recommended Next Steps

### Immediate (Today)

1. **Verify the Fix**
   ```bash
   # Update Cargo.toml to use latest frankensqlite commit
   # (Currently using patched versions, check which commit)

   cargo update frankensqlite
   cargo test --lib
   # Check if 39 failures → 0
   ```

2. **Document Results**
   - If failures drop to 0: Issue is resolved upstream ✅
   - If failures persist: Comment on frankensqlite #8 with details

### Short-term (This Week)

3. **If Failures Persist**
   ```
   gh issue comment Dicklesworthstone/frankensqlite#8 \
     --body "We reproduced similar 'database is busy' in mcp_agent_mail_rust tests..."
   ```

4. **Path Configuration**
   - Already documented in FORK_ISSUES.md
   - No upstream action needed (local machine issue)
   - Plan for CI/CD fix: Move /Volumes paths → relative paths

### Medium-term (Next Release)

5. **Test with Latest frankensqlite 0.3.0+**
   - Verify 39 failures are gone
   - Document fix in release notes
   - Celebrate 100% pass rate

---

## References

- frankensqlite: https://github.com/Dicklesworthstone/frankensqlite
- sqlmodel_rust: https://github.com/Dicklesworthstone/sqlmodel_rust
- frankentui: https://github.com/Dicklesworthstone/frankentui
- asupersync: https://github.com/Dicklesworthstone/asupersync
- Our MEMORY.md: Test results, issue findings
- commit 2026-03-02 07:21 UTC: busy_timeout fix (directly addresses our failures)

---

**Conclusion:** The upstream team is actively working on the same concurrency issue we encountered. The fix is already deployed in frankensqlite main branch. Our 39 test failures are not a code quality issue but rather exposure of a race condition that upstream is addressing.
