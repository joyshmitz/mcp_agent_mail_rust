//! Inspector detail cards for the timeline pane.
//!
//! Renders structured detail views for selected `MailEvent` entries,
//! with masked payloads and copy-friendly formatting.

use ftui::Frame;
use ftui::layout::Rect;
use ftui::widgets::Widget;
use ftui::widgets::block::Block;
use ftui::widgets::borders::BorderType;
use ftui::widgets::paragraph::Paragraph;

use crate::tui_events::{MailEvent, MailEventKind};

use super::dashboard::format_event;

// ──────────────────────────────────────────────────────────────────────
// Inspector rendering
// ──────────────────────────────────────────────────────────────────────

/// Render an inspector detail card for the given event into `area`.
///
/// If `event` is `None`, renders an empty placeholder.
pub fn render_inspector(frame: &mut Frame<'_>, area: Rect, event: Option<&MailEvent>) {
    let Some(event) = event else {
        let block = Block::default()
            .title("Inspector")
            .border_type(BorderType::Rounded);
        let p = Paragraph::new("(select an event)").block(block);
        p.render(area, frame);
        return;
    };

    let entry = format_event(event);
    let title = format!("Inspector — {}", kind_label(event.kind()));
    let body = detail_body(event);

    // Combine header + body.
    let header = format!(
        "Seq: {}  Time: {}  {}\n{}",
        event.seq(),
        entry.timestamp,
        source_label(event.source()),
        "─".repeat(area.width.saturating_sub(2) as usize),
    );
    let full_text = format!("{header}\n{body}");

    let block = Block::default()
        .title(&title)
        .border_type(BorderType::Rounded);
    let p = Paragraph::new(full_text).block(block);
    p.render(area, frame);
}

/// Human-readable label for the event kind.
const fn kind_label(kind: MailEventKind) -> &'static str {
    match kind {
        MailEventKind::ToolCallStart => "Tool Call (start)",
        MailEventKind::ToolCallEnd => "Tool Call (end)",
        MailEventKind::MessageSent => "Message Sent",
        MailEventKind::MessageReceived => "Message Received",
        MailEventKind::ReservationGranted => "Reservation Granted",
        MailEventKind::ReservationReleased => "Reservation Released",
        MailEventKind::AgentRegistered => "Agent Registered",
        MailEventKind::HttpRequest => "HTTP Request",
        MailEventKind::HealthPulse => "Health Pulse",
        MailEventKind::ServerStarted => "Server Started",
        MailEventKind::ServerShutdown => "Server Shutdown",
    }
}

/// Human-readable label for the event source.
const fn source_label(src: crate::tui_events::EventSource) -> &'static str {
    match src {
        crate::tui_events::EventSource::Tooling => "source:tooling",
        crate::tui_events::EventSource::Http => "source:http",
        crate::tui_events::EventSource::Mail => "source:mail",
        crate::tui_events::EventSource::Reservations => "source:reservations",
        crate::tui_events::EventSource::Lifecycle => "source:lifecycle",
        crate::tui_events::EventSource::Database => "source:database",
        crate::tui_events::EventSource::Unknown => "source:unknown",
    }
}

/// Format the event-specific detail body.
#[allow(clippy::too_many_lines)]
fn detail_body(event: &MailEvent) -> String {
    match event {
        MailEvent::ToolCallStart {
            tool_name,
            params_json,
            project,
            agent,
            redacted,
            ..
        } => {
            let mut lines = Vec::new();
            lines.push(format!("Tool: {tool_name}"));
            if let Some(p) = project {
                lines.push(format!("Project: {p}"));
            }
            if let Some(a) = agent {
                lines.push(format!("Agent: {a}"));
            }
            if *redacted {
                lines.push("⚠ Params redacted".to_string());
            } else {
                lines.push(String::new());
                lines.push("Parameters:".to_string());
                // Pretty-print JSON (already masked at event creation).
                let pretty = serde_json::to_string_pretty(params_json)
                    .unwrap_or_else(|_| params_json.to_string());
                for line in pretty.lines() {
                    lines.push(format!("  {line}"));
                }
            }
            lines.join("\n")
        }

        MailEvent::ToolCallEnd {
            tool_name,
            duration_ms,
            result_preview,
            queries,
            query_time_ms,
            per_table,
            project,
            agent,
            redacted,
            ..
        } => {
            let mut lines = Vec::new();
            lines.push(format!("Tool: {tool_name}"));
            lines.push(format!("Duration: {duration_ms}ms"));
            if let Some(p) = project {
                lines.push(format!("Project: {p}"));
            }
            if let Some(a) = agent {
                lines.push(format!("Agent: {a}"));
            }
            lines.push(format!("Queries: {queries} ({query_time_ms:.1}ms)"));
            if !per_table.is_empty() {
                lines.push("  Per table:".to_string());
                for (table, count) in per_table {
                    lines.push(format!("    {table}: {count}"));
                }
            }
            if *redacted {
                lines.push("⚠ Result redacted".to_string());
            } else if let Some(preview) = result_preview {
                lines.push(String::new());
                lines.push("Result:".to_string());
                for line in preview.lines().take(20) {
                    lines.push(format!("  {line}"));
                }
                if preview.lines().count() > 20 {
                    lines.push("  ... (truncated)".to_string());
                }
            }
            lines.join("\n")
        }

        MailEvent::MessageSent {
            id,
            from,
            to,
            subject,
            thread_id,
            project,
            ..
        }
        | MailEvent::MessageReceived {
            id,
            from,
            to,
            subject,
            thread_id,
            project,
            ..
        } => {
            let mut lines = Vec::new();
            lines.push(format!("Message ID: #{id}"));
            lines.push(format!("Project: {project}"));
            lines.push(format!("From: {from}"));
            lines.push(format!("To: {}", to.join(", ")));
            lines.push(format!("Subject: {subject}"));
            lines.push(format!("Thread: {thread_id}"));
            lines.join("\n")
        }

        MailEvent::ReservationGranted {
            agent,
            paths,
            exclusive,
            ttl_s,
            project,
            ..
        } => {
            let mut lines = Vec::new();
            lines.push(format!("Project: {project}"));
            lines.push(format!("Agent: {agent}"));
            lines.push(format!(
                "Exclusive: {}",
                if *exclusive { "yes" } else { "no" }
            ));
            lines.push(format!("TTL: {ttl_s}s"));
            lines.push(String::new());
            lines.push("Paths:".to_string());
            for path in paths {
                lines.push(format!("  {path}"));
            }
            lines.join("\n")
        }

        MailEvent::ReservationReleased {
            agent,
            paths,
            project,
            ..
        } => {
            let mut lines = Vec::new();
            lines.push(format!("Project: {project}"));
            lines.push(format!("Agent: {agent}"));
            lines.push(String::new());
            lines.push("Paths released:".to_string());
            for path in paths {
                lines.push(format!("  {path}"));
            }
            lines.join("\n")
        }

        MailEvent::AgentRegistered {
            name,
            program,
            model_name,
            project,
            ..
        } => {
            let mut lines = Vec::new();
            lines.push(format!("Agent: {name}"));
            lines.push(format!("Project: {project}"));
            lines.push(format!("Program: {program}"));
            lines.push(format!("Model: {model_name}"));
            lines.join("\n")
        }

        MailEvent::HttpRequest {
            method,
            path,
            status,
            duration_ms,
            client_ip,
            ..
        } => {
            let mut lines = Vec::new();
            lines.push(format!("{method} {path}"));
            lines.push(format!("Status: {status}"));
            lines.push(format!("Duration: {duration_ms}ms"));
            lines.push(format!("Client: {client_ip}"));
            lines.join("\n")
        }

        MailEvent::HealthPulse { db_stats, .. } => {
            let mut lines = Vec::new();
            lines.push(format!("Projects: {}", db_stats.projects));
            lines.push(format!("Agents: {}", db_stats.agents));
            lines.push(format!("Messages: {}", db_stats.messages));
            lines.push(format!("Reservations: {}", db_stats.file_reservations));
            lines.push(format!("Contact links: {}", db_stats.contact_links));
            lines.push(format!("Ack pending: {}", db_stats.ack_pending));
            if !db_stats.agents_list.is_empty() {
                lines.push(String::new());
                lines.push("Active agents:".to_string());
                for a in &db_stats.agents_list {
                    lines.push(format!("  {} ({})", a.name, a.program));
                }
            }
            lines.join("\n")
        }

        MailEvent::ServerStarted {
            endpoint,
            config_summary,
            ..
        } => {
            let mut lines = Vec::new();
            lines.push(format!("Endpoint: {endpoint}"));
            if !config_summary.is_empty() {
                lines.push(String::new());
                lines.push("Config:".to_string());
                for line in config_summary.lines() {
                    lines.push(format!("  {line}"));
                }
            }
            lines.join("\n")
        }

        MailEvent::ServerShutdown { .. } => "Server is shutting down.".to_string(),
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui_events::{DbStatSnapshot, EventSource};
    use serde_json::json;

    #[test]
    fn render_inspector_no_event() {
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(60, 20, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 60, 20), None);
    }

    #[test]
    fn render_inspector_tool_call_start() {
        let event = MailEvent::tool_call_start(
            "send_message",
            json!({"project_key": "test", "body": "hello"}),
            Some("my-project".to_string()),
            Some("RedFox".to_string()),
        );
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(80, 30, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 80, 30), Some(&event));
    }

    #[test]
    fn render_inspector_tool_call_end() {
        let event = MailEvent::tool_call_end(
            "send_message",
            42,
            Some("ok".to_string()),
            3,
            1.5,
            vec![("messages".to_string(), 2), ("projects".to_string(), 1)],
            Some("my-project".to_string()),
            Some("RedFox".to_string()),
        );
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(80, 30, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 80, 30), Some(&event));
    }

    #[test]
    fn render_inspector_message_sent() {
        let event = MailEvent::message_sent(
            42,
            "RedFox",
            vec!["BlueLake".to_string()],
            "Hello",
            "thread-1",
            "my-project",
        );
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(80, 20, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 80, 20), Some(&event));
    }

    #[test]
    fn render_inspector_http_request() {
        let event = MailEvent::http_request("GET", "/mcp/", 200, 15, "10.0.0.1");
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(60, 15, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 60, 15), Some(&event));
    }

    #[test]
    fn render_inspector_reservation_granted() {
        let event = MailEvent::reservation_granted(
            "RedFox",
            vec!["src/lib.rs".to_string(), "src/main.rs".to_string()],
            true,
            3600,
            "my-project",
        );
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(80, 20, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 80, 20), Some(&event));
    }

    #[test]
    fn render_inspector_agent_registered() {
        let event = MailEvent::agent_registered("RedFox", "claude-code", "opus-4.6", "my-project");
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(60, 15, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 60, 15), Some(&event));
    }

    #[test]
    fn render_inspector_health_pulse() {
        let event = MailEvent::health_pulse(DbStatSnapshot {
            projects: 3,
            agents: 5,
            messages: 100,
            file_reservations: 10,
            contact_links: 2,
            ack_pending: 1,
            agents_list: vec![],
            timestamp_micros: 0,
        });
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(60, 20, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 60, 20), Some(&event));
    }

    #[test]
    fn render_inspector_server_started() {
        let event = MailEvent::server_started("http://127.0.0.1:8765/mcp/", "db=mail.db pool=5");
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(80, 15, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 80, 15), Some(&event));
    }

    #[test]
    fn render_inspector_server_shutdown() {
        let event = MailEvent::server_shutdown();
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(60, 10, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 60, 10), Some(&event));
    }

    #[test]
    fn kind_label_all_variants() {
        assert_eq!(
            kind_label(MailEventKind::ToolCallStart),
            "Tool Call (start)"
        );
        assert_eq!(kind_label(MailEventKind::ToolCallEnd), "Tool Call (end)");
        assert_eq!(kind_label(MailEventKind::MessageSent), "Message Sent");
        assert_eq!(kind_label(MailEventKind::HttpRequest), "HTTP Request");
        assert_eq!(kind_label(MailEventKind::ServerStarted), "Server Started");
        assert_eq!(kind_label(MailEventKind::ServerShutdown), "Server Shutdown");
    }

    #[test]
    fn source_label_all_variants() {
        assert_eq!(source_label(EventSource::Tooling), "source:tooling");
        assert_eq!(source_label(EventSource::Http), "source:http");
        assert_eq!(source_label(EventSource::Mail), "source:mail");
    }

    #[test]
    fn detail_body_tool_call_start_shows_params() {
        let event = MailEvent::tool_call_start("send_message", json!({"key": "value"}), None, None);
        let body = detail_body(&event);
        assert!(body.contains("Tool: send_message"));
        assert!(body.contains("Parameters:"));
        assert!(body.contains("\"key\""));
    }

    #[test]
    fn detail_body_tool_call_end_shows_per_table() {
        let event = MailEvent::tool_call_end(
            "fetch_inbox",
            100,
            Some("3 messages".to_string()),
            5,
            2.5,
            vec![("messages".to_string(), 3), ("projects".to_string(), 2)],
            None,
            None,
        );
        let body = detail_body(&event);
        assert!(body.contains("Duration: 100ms"));
        assert!(body.contains("messages: 3"));
        assert!(body.contains("Result:"));
    }

    #[test]
    fn detail_body_http_request_shows_all_fields() {
        let event = MailEvent::http_request("POST", "/mcp/", 201, 42, "192.168.1.1");
        let body = detail_body(&event);
        assert!(body.contains("POST /mcp/"));
        assert!(body.contains("Status: 201"));
        assert!(body.contains("Duration: 42ms"));
        assert!(body.contains("Client: 192.168.1.1"));
    }

    #[test]
    fn detail_body_reservation_shows_paths() {
        let event = MailEvent::reservation_granted(
            "RedFox",
            vec!["a.rs".to_string(), "b.rs".to_string()],
            false,
            600,
            "proj",
        );
        let body = detail_body(&event);
        assert!(body.contains("a.rs"));
        assert!(body.contains("b.rs"));
        assert!(body.contains("Exclusive: no"));
        assert!(body.contains("TTL: 600s"));
    }

    #[test]
    fn detail_body_redacted_tool_call() {
        let mut event =
            MailEvent::tool_call_start("send_message", json!({"secret": "value"}), None, None);
        // Simulate redaction flag.
        if let MailEvent::ToolCallStart { redacted, .. } = &mut event {
            *redacted = true;
        }
        let body = detail_body(&event);
        assert!(body.contains("⚠ Params redacted"));
        assert!(!body.contains("Parameters:"));
    }

    #[test]
    fn render_inspector_minimum_size() {
        let event = MailEvent::http_request("GET", "/", 200, 1, "127.0.0.1");
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(30, 5, &mut pool);
        render_inspector(&mut frame, Rect::new(0, 0, 30, 5), Some(&event));
    }
}
