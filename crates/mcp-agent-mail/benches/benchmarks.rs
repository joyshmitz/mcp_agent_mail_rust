#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::significant_drop_tightening
)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fastmcp::{Budget, CallToolParams, Cx};
use fastmcp_core::SessionState;
use mcp_agent_mail_conformance::Fixtures;
use serde::Serialize;
use serde_json::Value;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn fixtures_path() -> std::path::PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/mcp-agent-mail` for this bench crate.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../mcp-agent-mail-conformance/tests/conformance/fixtures/python_reference.json")
}

fn seed_fixtures(fixtures: &Fixtures) {
    static SEEDED: Once = Once::new();

    SEEDED.call_once(|| {
        // Reuse the conformance fixtures to seed a realistic DB state.
        // This ensures benchmarks remain aligned with parity expectations.
        let config = mcp_agent_mail_core::Config::from_env();
        let router = mcp_agent_mail_server::build_server(&config).into_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let mut req_id: u64 = 1;

        for (tool_name, tool_fixture) in &fixtures.tools {
            for case in &tool_fixture.cases {
                let args = match &case.input {
                    Value::Null => None,
                    Value::Object(map) if map.is_empty() => None,
                    other => Some(other.clone()),
                };
                let params = CallToolParams {
                    name: tool_name.clone(),
                    arguments: args,
                    meta: None,
                };

                let _ = router
                    .handle_tools_call(
                        &cx,
                        req_id,
                        params,
                        &budget,
                        SessionState::new(),
                        None,
                        None,
                    )
                    .expect("tool call should succeed during seeding");
                req_id += 1;
            }
        }

        // Ensure any archive writes/commits from seeding are flushed before benchmarking.
        mcp_agent_mail_storage::wbq_flush();
        mcp_agent_mail_storage::flush_async_commits();
    });
}

fn bench_tools(c: &mut Criterion) {
    // Ensure DB is initialized before anything touches the pool cache.
    let tmp = TempDir::new().expect("tempdir");
    let original_cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(tmp.path()).expect("chdir to tempdir");

    // Load fixtures via absolute path (bench runs in tempdir so relative paths won't work).
    let fixtures = Fixtures::load(fixtures_path()).expect("fixtures");
    seed_fixtures(&fixtures);

    let config = mcp_agent_mail_core::Config::from_env();
    let router = mcp_agent_mail_server::build_server(&config).into_router();
    let cx = Cx::for_testing();
    let budget = Budget::INFINITE;

    let mut group = c.benchmark_group("mcp_agent_mail_tools");

    // Bench high-frequency operations across tool clusters.
    // Format: (tool_name, case_name)
    let targets: &[(&str, &str)] = &[
        // Health
        ("health_check", "default"),
        // Identity cluster
        ("ensure_project", "abs_path_backend"),
        ("register_agent", "green_castle"),
        // Messaging cluster
        ("fetch_inbox", "gc_inbox_with_bodies"),
        ("search_messages", "search_hello"),
        ("summarize_thread", "summarize_thread_root"),
        // File reservations cluster
        ("file_reservation_paths", "reserve_src_glob"),
        // Macros cluster
        ("macro_start_session", "macro_start_session_basic"),
    ];

    for (tool_name, case_name) in targets {
        let fixture = fixtures
            .tools
            .get(*tool_name)
            .unwrap_or_else(|| panic!("missing tool fixture: {tool_name}"));
        let case = fixture
            .cases
            .iter()
            .find(|c| c.name == *case_name)
            .unwrap_or_else(|| panic!("missing case {case_name} for tool {tool_name}"));

        let args = match &case.input {
            Value::Null => None,
            Value::Object(map) if map.is_empty() => None,
            other => Some(other.clone()),
        };

        let params = CallToolParams {
            name: tool_name.to_string(),
            arguments: args,
            meta: None,
        };

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new(*tool_name, *case_name),
            &params,
            |b, params| {
                let mut req_id: u64 = 1;
                b.iter(|| {
                    let out = router
                        .handle_tools_call(
                            &cx,
                            req_id,
                            params.clone(),
                            &budget,
                            SessionState::new(),
                            None,
                            None,
                        )
                        .expect("tool call");
                    req_id = req_id.wrapping_add(1);
                    black_box(out);
                });
            },
        );
    }

    group.finish();

    // Ensure we don't drop the temp repo while background writers still have work.
    mcp_agent_mail_storage::wbq_flush();
    mcp_agent_mail_storage::flush_async_commits();

    std::env::set_current_dir(original_cwd).expect("restore cwd");
    drop(tmp);
}

#[derive(Debug, Clone, Copy)]
enum ArchiveScenario {
    SingleNoAttachments,
    SingleInlineAttachment,
    SingleFileAttachment,
    BatchNoAttachments { batch_size: usize },
}

impl ArchiveScenario {
    const fn name(self) -> &'static str {
        match self {
            Self::SingleNoAttachments => "single_no_attachments",
            Self::SingleInlineAttachment => "single_inline_attachment",
            Self::SingleFileAttachment => "single_file_attachment",
            Self::BatchNoAttachments { .. } => "batch_no_attachments",
        }
    }

    const fn elements_per_op(self) -> u64 {
        match self {
            Self::BatchNoAttachments { batch_size } => batch_size as u64,
            _ => 1,
        }
    }
}

fn repo_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/mcp-agent-mail`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn run_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}_{}", now.as_secs(), std::process::id())
}

fn artifact_dir(run_id: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("artifacts")
        .join("bench")
        .join("archive")
        .join(run_id)
}

fn write_bmp24(path: &Path, width: u32, height: u32, seed: u32) -> std::io::Result<()> {
    // Minimal 24-bit BMP writer (uncompressed).
    // Pixel data is BGR, rows padded to 4-byte boundary, stored bottom-up.
    let width_us = width as usize;
    let height_us = height as usize;
    let row_bytes_unpadded = width_us * 3;
    let row_stride = (row_bytes_unpadded + 3) & !3;
    let pixel_bytes = row_stride * height_us;
    let file_size = 14 + 40 + pixel_bytes;

    let mut buf = Vec::with_capacity(file_size);

    // BITMAPFILEHEADER (14)
    buf.extend_from_slice(b"BM");
    buf.extend_from_slice(&(file_size as u32).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved1
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    buf.extend_from_slice(&(54u32).to_le_bytes()); // offset to pixels

    // BITMAPINFOHEADER (40)
    buf.extend_from_slice(&(40u32).to_le_bytes()); // header size
    buf.extend_from_slice(&(width as i32).to_le_bytes());
    buf.extend_from_slice(&(height as i32).to_le_bytes());
    buf.extend_from_slice(&(1u16).to_le_bytes()); // planes
    buf.extend_from_slice(&(24u16).to_le_bytes()); // bpp
    buf.extend_from_slice(&0u32.to_le_bytes()); // compression
    buf.extend_from_slice(&(pixel_bytes as u32).to_le_bytes());
    buf.extend_from_slice(&(2835i32).to_le_bytes()); // ~72dpi
    buf.extend_from_slice(&(2835i32).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // colors used
    buf.extend_from_slice(&0u32.to_le_bytes()); // important colors

    let pad = vec![0u8; row_stride - row_bytes_unpadded];
    for y in 0..height_us {
        let y_u32 = y as u32;
        for x in 0..width_us {
            let x_u32 = x as u32;
            let r = ((x_u32.wrapping_add(seed)) & 0xFF) as u8;
            let g = ((y_u32.wrapping_add(seed.wrapping_mul(3))) & 0xFF) as u8;
            let b = ((x_u32 ^ y_u32 ^ seed) & 0xFF) as u8;
            buf.push(b);
            buf.push(g);
            buf.push(r);
        }
        buf.extend_from_slice(&pad);
    }

    std::fs::write(path, buf)
}

#[derive(Debug, Clone, Serialize)]
struct ArchiveBenchScenarioResult {
    scenario: String,
    elements_per_op: u64,
    samples_us: Vec<u64>,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    budget_p95_us: u64,
    budget_p99_us: u64,
    p95_within_budget: bool,
    p99_within_budget: bool,
    p95_delta_us: i64,
    p99_delta_us: i64,
    throughput_elements_per_sec: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ArchiveBenchRun {
    run_id: String,
    arch: String,
    os: String,
    budget_regressions: usize,
    results: Vec<ArchiveBenchScenarioResult>,
}

const PERCENTILE_SCALE: u32 = 1_000_000;

fn percentile_us(mut samples: Vec<u64>, pct: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    let n = samples.len();
    let max_idx = n.saturating_sub(1);
    let pct = pct.clamp(0.0, 1.0);
    // Fixed-point to avoid float->usize casts and large-int->float precision lints.
    let denom_u64 = u64::from(PERCENTILE_SCALE);
    let scaled = (pct * f64::from(PERCENTILE_SCALE)).round();
    let scaled_u64 = u64::try_from(scaled as i64).unwrap_or(0).min(denom_u64);
    let idx_u64 = (scaled_u64.saturating_mul(max_idx as u64) + (denom_u64 / 2)) / denom_u64;
    let idx = usize::try_from(idx_u64).unwrap_or(max_idx).min(max_idx);
    samples[idx]
}

const fn scenario_budgets_us(scenario: ArchiveScenario) -> (u64, u64) {
    match scenario {
        ArchiveScenario::BatchNoAttachments { .. } => (250_000, 300_000),
        _ => (25_000, 30_000),
    }
}

#[allow(clippy::too_many_lines)]
fn run_archive_harness_once() {
    static DID_RUN: Once = Once::new();
    DID_RUN.call_once(|| {
        let run_id = run_id();
        let out_dir = artifact_dir(&run_id);
        let _ = std::fs::create_dir_all(&out_dir);

        // Small, deterministic fixed-run harness for p50/p95/p99 + raw samples.
        let scenarios: &[(ArchiveScenario, usize)] = &[
            (ArchiveScenario::SingleNoAttachments, 200),
            (ArchiveScenario::SingleInlineAttachment, 50),
            (ArchiveScenario::SingleFileAttachment, 50),
            (ArchiveScenario::BatchNoAttachments { batch_size: 100 }, 10),
        ];

        let mut results = Vec::new();
        let mut regressions = 0usize;

        for (scenario, ops) in scenarios {
            if let ArchiveScenario::BatchNoAttachments { batch_size } = *scenario {
                // Measure each batch in a fresh repo so the samples reflect a "single burst"
                // and aren't dominated by repo growth effects across repeated batch runs.
                let original_cwd = std::env::current_dir().expect("cwd");
                let project_slug = "bench-archive";
                let sender = "BenchSender";
                let recipients = vec!["BenchReceiver".to_string()];

                let mut samples_us: Vec<u64> = Vec::with_capacity(*ops);
                for _ in 0..*ops {
                    let tmp = TempDir::new().expect("tempdir");
                    std::env::set_current_dir(tmp.path()).expect("chdir");

                    let mut config = mcp_agent_mail_core::Config::from_env();
                    config.storage_root = tmp.path().join("archive_repo");
                    config.database_url = format!(
                        "sqlite+aiosqlite:///{}",
                        tmp.path().join("storage.sqlite3").display()
                    );

                    let archive = mcp_agent_mail_storage::ensure_archive(&config, project_slug)
                        .expect("ensure_archive");

                    let t0 = Instant::now();
                    let mut msg_id: i64 = 1;
                    for _ in 0..batch_size {
                        let message_json = serde_json::json!({
                            "id": msg_id,
                            "project": project_slug,
                            "subject": "bench batch",
                            "created_ts": 1_700_000_000_000_000i64,
                        });
                        mcp_agent_mail_storage::write_message_bundle(
                            &archive,
                            &config,
                            &message_json,
                            "hello",
                            sender,
                            &recipients,
                            &[],
                            None,
                        )
                        .expect("write_message_bundle");
                        msg_id += 1;
                    }
                    mcp_agent_mail_storage::flush_async_commits();

                    samples_us.push(t0.elapsed().as_micros() as u64);
                    std::env::set_current_dir(&original_cwd).expect("restore cwd");
                    drop(tmp);
                }

                let elements_per_op = scenario.elements_per_op();
                let total_elements = elements_per_op.saturating_mul(*ops as u64);
                let total_elements_f64 =
                    u32::try_from(total_elements).map_or_else(|_| f64::from(u32::MAX), f64::from);
                let total_us = samples_us.iter().copied().sum::<u64>();
                let total_us_f64 =
                    u32::try_from(total_us).map_or_else(|_| f64::from(u32::MAX), f64::from);
                let throughput = if total_us_f64 > 0.0 {
                    total_elements_f64 / (total_us_f64 / 1_000_000.0)
                } else {
                    0.0
                };

                let p50_us = percentile_us(samples_us.clone(), 0.50);
                let p95_us = percentile_us(samples_us.clone(), 0.95);
                let p99_us = percentile_us(samples_us.clone(), 0.99);

                let (budget_p95_us, budget_p99_us) = scenario_budgets_us(*scenario);
                let p95_within_budget = p95_us <= budget_p95_us;
                let p99_within_budget = p99_us <= budget_p99_us;
                let p95_delta_us = p95_us as i64 - budget_p95_us as i64;
                let p99_delta_us = p99_us as i64 - budget_p99_us as i64;
                if !p95_within_budget || !p99_within_budget {
                    regressions += 1;
                }

                let scenario_result = ArchiveBenchScenarioResult {
                    scenario: scenario.name().to_string(),
                    elements_per_op,
                    samples_us: samples_us.clone(),
                    p50_us,
                    p95_us,
                    p99_us,
                    budget_p95_us,
                    budget_p99_us,
                    p95_within_budget,
                    p99_within_budget,
                    p95_delta_us,
                    p99_delta_us,
                    throughput_elements_per_sec: (throughput * 100.0).round() / 100.0,
                };

                let _ = std::fs::write(
                    out_dir.join(format!("{}.json", scenario.name())),
                    serde_json::to_string_pretty(&scenario_result).unwrap_or_default(),
                );
                results.push(scenario_result);
                continue;
            }

            let tmp = TempDir::new().expect("tempdir");
            let original_cwd = std::env::current_dir().expect("cwd");
            std::env::set_current_dir(tmp.path()).expect("chdir");

            let mut config = mcp_agent_mail_core::Config::from_env();
            config.storage_root = tmp.path().join("archive_repo");
            config.database_url = format!(
                "sqlite+aiosqlite:///{}",
                tmp.path().join("storage.sqlite3").display()
            );

            let project_slug = "bench-archive";
            let archive = mcp_agent_mail_storage::ensure_archive(&config, project_slug)
                .expect("ensure_archive");

            let sender = "BenchSender";
            let recipients = vec!["BenchReceiver".to_string()];

            // Pre-generate attachment inputs (outside timed region).
            let input_dir = tmp.path().join("input");
            let _ = std::fs::create_dir_all(&input_dir);

            let mut attachment_paths: Vec<PathBuf> = Vec::new();
            if matches!(
                *scenario,
                ArchiveScenario::SingleInlineAttachment | ArchiveScenario::SingleFileAttachment
            ) {
                for i in 0..*ops {
                    let p = input_dir.join(format!("img_{i}.bmp"));
                    write_bmp24(&p, 32, 32, i as u32).expect("write bmp");
                    attachment_paths.push(p);
                }
            }

            let mut msg_id: i64 = 1;
            let mut samples_us: Vec<u64> = Vec::with_capacity(*ops);
            let start_all = Instant::now();

            match *scenario {
                ArchiveScenario::SingleNoAttachments => {
                    for _ in 0..*ops {
                        let t0 = Instant::now();

                        let message_json = serde_json::json!({
                            "id": msg_id,
                            "project": project_slug,
                            "subject": "bench no attachments",
                            "created_ts": 1_700_000_000_000_000i64,
                        });

                        mcp_agent_mail_storage::write_message_bundle(
                            &archive,
                            &config,
                            &message_json,
                            "hello",
                            sender,
                            &recipients,
                            &[],
                            None,
                        )
                        .expect("write_message_bundle");
                        mcp_agent_mail_storage::flush_async_commits();

                        samples_us.push(t0.elapsed().as_micros() as u64);
                        msg_id += 1;
                    }
                }
                ArchiveScenario::SingleInlineAttachment | ArchiveScenario::SingleFileAttachment => {
                    let policy = if matches!(*scenario, ArchiveScenario::SingleInlineAttachment) {
                        mcp_agent_mail_storage::EmbedPolicy::Inline
                    } else {
                        mcp_agent_mail_storage::EmbedPolicy::File
                    };

                    for path in attachment_paths.iter().take(*ops) {
                        let t0 = Instant::now();

                        let img_path = path.to_string_lossy().to_string();
                        let body = format!("inline image: ![img]({img_path})\n");
                        let (body2, meta, rel_paths) =
                            mcp_agent_mail_storage::process_markdown_images(
                                &archive, &config, &body, policy,
                            )
                            .expect("process_markdown_images");

                        let attachments_json: Vec<serde_json::Value> = meta
                            .into_iter()
                            .filter_map(|m| serde_json::to_value(m).ok())
                            .collect();

                        let message_json = serde_json::json!({
                            "id": msg_id,
                            "project": project_slug,
                            "subject": "bench attachment",
                            "created_ts": 1_700_000_000_000_000i64,
                            "attachments": attachments_json,
                        });

                        mcp_agent_mail_storage::write_message_bundle(
                            &archive,
                            &config,
                            &message_json,
                            &body2,
                            sender,
                            &recipients,
                            &rel_paths,
                            None,
                        )
                        .expect("write_message_bundle");
                        mcp_agent_mail_storage::flush_async_commits();

                        samples_us.push(t0.elapsed().as_micros() as u64);
                        msg_id += 1;
                    }
                }
                ArchiveScenario::BatchNoAttachments { batch_size } => {
                    for _ in 0..*ops {
                        let t0 = Instant::now();

                        for _ in 0..batch_size {
                            let message_json = serde_json::json!({
                                "id": msg_id,
                                "project": project_slug,
                                "subject": "bench batch",
                                "created_ts": 1_700_000_000_000_000i64,
                            });
                            mcp_agent_mail_storage::write_message_bundle(
                                &archive,
                                &config,
                                &message_json,
                                "hello",
                                sender,
                                &recipients,
                                &[],
                                None,
                            )
                            .expect("write_message_bundle");
                            msg_id += 1;
                        }
                        mcp_agent_mail_storage::flush_async_commits();

                        samples_us.push(t0.elapsed().as_micros() as u64);
                    }
                }
            }

            let total = start_all.elapsed();
            let elements_per_op = scenario.elements_per_op();
            let total_elements = elements_per_op.saturating_mul(*ops as u64);
            let total_elements_f64 =
                u32::try_from(total_elements).map_or_else(|_| f64::from(u32::MAX), f64::from);
            let throughput = if total.as_secs_f64() > 0.0 {
                total_elements_f64 / total.as_secs_f64()
            } else {
                0.0
            };

            let p50_us = percentile_us(samples_us.clone(), 0.50);
            let p95_us = percentile_us(samples_us.clone(), 0.95);
            let p99_us = percentile_us(samples_us.clone(), 0.99);

            let (budget_p95_us, budget_p99_us) = scenario_budgets_us(*scenario);
            let p95_within_budget = p95_us <= budget_p95_us;
            let p99_within_budget = p99_us <= budget_p99_us;
            let p95_delta_us = p95_us as i64 - budget_p95_us as i64;
            let p99_delta_us = p99_us as i64 - budget_p99_us as i64;
            if !p95_within_budget || !p99_within_budget {
                regressions += 1;
            }

            let scenario_result = ArchiveBenchScenarioResult {
                scenario: scenario.name().to_string(),
                elements_per_op,
                samples_us: samples_us.clone(),
                p50_us,
                p95_us,
                p99_us,
                budget_p95_us,
                budget_p99_us,
                p95_within_budget,
                p99_within_budget,
                p95_delta_us,
                p99_delta_us,
                throughput_elements_per_sec: (throughput * 100.0).round() / 100.0,
            };

            let _ = std::fs::write(
                out_dir.join(format!("{}.json", scenario.name())),
                serde_json::to_string_pretty(&scenario_result).unwrap_or_default(),
            );

            results.push(scenario_result);

            std::env::set_current_dir(original_cwd).expect("restore cwd");
            drop(tmp);
        }

        let run = ArchiveBenchRun {
            run_id,
            arch: std::env::consts::ARCH.to_string(),
            os: std::env::consts::OS.to_string(),
            budget_regressions: regressions,
            results,
        };

        let _ = std::fs::write(
            out_dir.join("summary.json"),
            serde_json::to_string_pretty(&run).unwrap_or_default(),
        );
    });
}

#[allow(clippy::too_many_lines)]
fn bench_archive_write(c: &mut Criterion) {
    run_archive_harness_once();

    let scenarios: &[ArchiveScenario] = &[
        ArchiveScenario::SingleNoAttachments,
        ArchiveScenario::SingleInlineAttachment,
        ArchiveScenario::SingleFileAttachment,
    ];

    let mut group = c.benchmark_group("archive_write");
    for &scenario in scenarios {
        group.throughput(Throughput::Elements(scenario.elements_per_op()));

        group.bench_with_input(
            BenchmarkId::new(scenario.name(), scenario.elements_per_op()),
            &scenario,
            |b, &scenario| {
                b.iter_custom(|iters| {
                    let tmp = TempDir::new().expect("tempdir");
                    let original_cwd = std::env::current_dir().expect("cwd");
                    std::env::set_current_dir(tmp.path()).expect("chdir");

                    let mut config = mcp_agent_mail_core::Config::from_env();
                    config.storage_root = tmp.path().join("archive_repo");
                    config.database_url = format!(
                        "sqlite+aiosqlite:///{}",
                        tmp.path().join("storage.sqlite3").display()
                    );

                    let project_slug = "bench-archive";
                    let archive = mcp_agent_mail_storage::ensure_archive(&config, project_slug)
                        .expect("archive");

                    let sender = "BenchSender";
                    let recipients = vec!["BenchReceiver".to_string()];

                    // Pre-generate attachment inputs (outside timed region).
                    let input_dir = tmp.path().join("input");
                    let _ = std::fs::create_dir_all(&input_dir);
                    let mut attachment_paths: Vec<PathBuf> = Vec::new();
                    if matches!(
                        scenario,
                        ArchiveScenario::SingleInlineAttachment
                            | ArchiveScenario::SingleFileAttachment
                    ) {
                        for i in 0..iters {
                            let p = input_dir.join(format!("img_{i}.bmp"));
                            write_bmp24(&p, 32, 32, i as u32).expect("write bmp");
                            attachment_paths.push(p);
                        }
                    }

                    let mut msg_id: i64 = 1;
                    let t0 = Instant::now();

                    match scenario {
                        ArchiveScenario::SingleNoAttachments => {
                            for _ in 0..iters {
                                let message_json = serde_json::json!({
                                    "id": msg_id,
                                    "project": project_slug,
                                    "subject": "bench no attachments",
                                    "created_ts": 1_700_000_000_000_000i64,
                                });

                                mcp_agent_mail_storage::write_message_bundle(
                                    &archive,
                                    &config,
                                    &message_json,
                                    "hello",
                                    sender,
                                    &recipients,
                                    &[],
                                    None,
                                )
                                .expect("write_message_bundle");
                                mcp_agent_mail_storage::flush_async_commits();
                                msg_id += 1;
                            }
                        }
                        ArchiveScenario::SingleInlineAttachment
                        | ArchiveScenario::SingleFileAttachment => {
                            let policy =
                                if matches!(scenario, ArchiveScenario::SingleInlineAttachment) {
                                    mcp_agent_mail_storage::EmbedPolicy::Inline
                                } else {
                                    mcp_agent_mail_storage::EmbedPolicy::File
                                };
                            let iters_us = usize::try_from(iters).unwrap_or(usize::MAX);
                            for path in attachment_paths.iter().take(iters_us) {
                                let img_path = path.to_string_lossy().to_string();
                                let body = format!("inline image: ![img]({img_path})\n");

                                let (body2, meta, rel_paths) =
                                    mcp_agent_mail_storage::process_markdown_images(
                                        &archive, &config, &body, policy,
                                    )
                                    .expect("process_markdown_images");

                                let attachments_json: Vec<serde_json::Value> = meta
                                    .into_iter()
                                    .filter_map(|m| serde_json::to_value(m).ok())
                                    .collect();

                                let message_json = serde_json::json!({
                                    "id": msg_id,
                                    "project": project_slug,
                                    "subject": "bench attachment",
                                    "created_ts": 1_700_000_000_000_000i64,
                                    "attachments": attachments_json,
                                });

                                mcp_agent_mail_storage::write_message_bundle(
                                    &archive,
                                    &config,
                                    &message_json,
                                    &body2,
                                    sender,
                                    &recipients,
                                    &rel_paths,
                                    None,
                                )
                                .expect("write_message_bundle");
                                mcp_agent_mail_storage::flush_async_commits();
                                msg_id += 1;
                            }
                        }
                        ArchiveScenario::BatchNoAttachments { batch_size } => {
                            for _ in 0..iters {
                                for _ in 0..batch_size {
                                    let message_json = serde_json::json!({
                                        "id": msg_id,
                                        "project": project_slug,
                                        "subject": "bench batch",
                                        "created_ts": 1_700_000_000_000_000i64,
                                    });
                                    mcp_agent_mail_storage::write_message_bundle(
                                        &archive,
                                        &config,
                                        &message_json,
                                        "hello",
                                        sender,
                                        &recipients,
                                        &[],
                                        None,
                                    )
                                    .expect("write_message_bundle");
                                    msg_id += 1;
                                }
                                mcp_agent_mail_storage::flush_async_commits();
                            }
                        }
                    }

                    let dt = t0.elapsed();
                    std::env::set_current_dir(original_cwd).expect("restore cwd");
                    drop(tmp);
                    dt
                });
            },
        );
    }

    group.finish();

    // Batch benches are much slower (intentionally) under legacy-ish commit batching,
    // so use a smaller sample size to keep `cargo bench` runtimes reasonable.
    let scenario = ArchiveScenario::BatchNoAttachments { batch_size: 100 };
    let mut batch_group = c.benchmark_group("archive_write_batch");
    batch_group.sample_size(20);
    batch_group.throughput(Throughput::Elements(scenario.elements_per_op()));
    batch_group.bench_with_input(
        BenchmarkId::new(scenario.name(), scenario.elements_per_op()),
        &scenario,
        |b, &scenario| {
            b.iter_custom(|iters| {
                let tmp = TempDir::new().expect("tempdir");
                let original_cwd = std::env::current_dir().expect("cwd");
                std::env::set_current_dir(tmp.path()).expect("chdir");

                let mut config = mcp_agent_mail_core::Config::from_env();
                config.storage_root = tmp.path().join("archive_repo");
                config.database_url = format!(
                    "sqlite+aiosqlite:///{}",
                    tmp.path().join("storage.sqlite3").display()
                );

                let project_slug = "bench-archive";
                let archive =
                    mcp_agent_mail_storage::ensure_archive(&config, project_slug).expect("archive");

                let sender = "BenchSender";
                let recipients = vec!["BenchReceiver".to_string()];

                let mut msg_id: i64 = 1;
                let t0 = Instant::now();

                for _ in 0..iters {
                    if let ArchiveScenario::BatchNoAttachments { batch_size } = scenario {
                        for _ in 0..batch_size {
                            let message_json = serde_json::json!({
                                "id": msg_id,
                                "project": project_slug,
                                "subject": "bench batch",
                                "created_ts": 1_700_000_000_000_000i64,
                            });
                            mcp_agent_mail_storage::write_message_bundle(
                                &archive,
                                &config,
                                &message_json,
                                "hello",
                                sender,
                                &recipients,
                                &[],
                                None,
                            )
                            .expect("write_message_bundle");
                            msg_id += 1;
                        }
                        mcp_agent_mail_storage::flush_async_commits();
                    }
                }

                let dt = t0.elapsed();
                std::env::set_current_dir(original_cwd).expect("restore cwd");
                drop(tmp);
                dt
            });
        },
    );
    batch_group.finish();
}

criterion_group!(benches, bench_tools, bench_archive_write);
criterion_main!(benches);
