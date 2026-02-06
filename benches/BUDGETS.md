# Performance Budgets

Baseline performance targets for mcp-agent-mail Rust port.
Updated via `scripts/bench_cli.sh` and `cargo bench`.

## Optimization Workflow

1. **Profile** — measure before changing anything
2. **Change** — apply one optimization
3. **Prove** — verify behavior unchanged (golden outputs) AND performance improved

## Hardware Notes

- Platform: Linux x86_64 (Ubuntu)
- Kernel: 6.17.0
- Target dir: `/data/tmp/cargo-target`
- Build profile: `release` for CLI benchmarks, `bench` for Criterion

## Tool Handler Budgets

Targets based on initial baseline (2026-02-05). Budgets are 2x the measured baseline to absorb variance.

| Surface | Baseline | Budget | Notes |
|---------|----------|--------|-------|
| Format resolution (explicit) | ~39ns | < 100ns | Pure string matching, no I/O |
| Format resolution (implicit) | ~20ns | < 50ns | Fast path: no param, no default |
| Format resolution (MIME alias) | ~36ns | < 100ns | Includes normalize_mime() |
| Stats parsing (full) | ~243ns | < 500ns | 2 lines: token estimates + saved |
| Stats parsing (noisy) | ~293ns | < 600ns | 4 lines, scan with noise |
| Stats parsing (empty) | ~12ns | < 30ns | Early return |
| Encoder resolution (default) | ~30ns | < 100ns | Single string |
| Encoder resolution (custom) | ~92ns | < 200ns | whitespace split |
| Stub encoder (subprocess) | ~12ms | < 25ms | Fork+exec+pipe |
| apply_toon_format (toon) | ~12ms | < 25ms | Includes subprocess I/O |
| apply_toon_format (json) | ~27ns | < 60ns | Passthrough, no I/O |
| JSON serialize (8-field) | ~246ns | < 500ns | serde_json baseline |
| JSON parse (8-field) | ~553ns | < 1.2µs | serde_json baseline |

## CLI Startup Budgets

| Command | Target | Notes |
|---------|--------|-------|
| `am --help` | < 20ms | Startup + argument parsing |
| `am lint` | < 50ms | Static analysis |
| `am typecheck` | < 50ms | Type checking |

## Archive Write Budgets

Baseline numbers are taken from the bench harness artifacts emitted by:

```bash
cargo bench -p mcp-agent-mail --bench benchmarks -- archive_write
```

Artifacts (JSON + raw samples) are written under:
- `tests/artifacts/bench/archive/<run_id>/summary.json`

Most recent baseline run (2026-02-06): `tests/artifacts/bench/archive/1770365294_1633729/summary.json`.

Budgets are set to ~2x the measured baseline p95 to absorb variance.

| Operation | Baseline p50 | Baseline p95 | Baseline p99 | Budget p95 | Budget p99 | Notes |
|-----------|--------------|--------------|--------------|------------|------------|-------|
| Single message (no attachments) | ~7.2ms | ~11.0ms | ~12.6ms | < 25ms | < 30ms | Writes canonical+outbox+1 inbox + git commit flush |
| Single message (inline attachment) | ~7.5ms | ~10.9ms | ~11.3ms | < 25ms | < 30ms | Includes WebP convert + manifest + audit + inline base64 body |
| Single message (file attachment) | ~8.0ms | ~11.3ms | ~13.6ms | < 25ms | < 30ms | Includes WebP convert + manifest + audit + file-path body |
| Batch 100 messages (no attachments) | ~101ms | ~111ms | ~111ms | < 250ms | < 300ms | 100 writes + commit batching (max 10 ops/commit) |

## Share/Export Pipeline Budgets

To be established by br-2ei.7.3.

| Stage | Target | Notes |
|-------|--------|-------|
| Snapshot (100 msgs) | TBD | DB → file |
| Scope filtering | TBD | Path matching |
| Scrub (PII removal) | TBD | String scanning |
| Bundle assembly | TBD | ZIP creation |
| Encryption (1MB) | TBD | AES-256-GCM |

## Golden Outputs

Stable surfaces validated via `scripts/bench_golden.sh validate`:

- `am --help` text
- `am <subcommand> --help` text (7 subcommands)
- Stub encoder outputs (encode, stats, help, version)
- CLI version string

Checksums stored in `benches/golden/checksums.sha256`.

## Opportunity Matrix

Score = Impact × Confidence / Effort. Only pursue Score ≥ 2.0.

| Hotspot | Impact | Confidence | Effort | Score | Action |
|---------|--------|------------|--------|-------|--------|
| (to be filled after flamegraph analysis) | | | | | |

## Isomorphism Invariants

Properties that must be preserved across optimizations:

1. **Ordering**: Tool list order in resources matches Python reference
2. **Tie-breaking**: Message sort by (created_ts DESC, id DESC)
3. **Float precision**: saved_percent rounded to 1 decimal
4. **Timestamp format**: ISO-8601 with timezone (microsecond precision)
5. **JSON key order**: Alphabetical within envelope.meta
