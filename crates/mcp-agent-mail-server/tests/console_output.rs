mod common;

use mcp_agent_mail_server::console::{
    BannerParams, render_startup_banner, render_tool_call_end, render_tool_call_start,
};

#[test]
fn startup_banner_sections_present_after_normalization() {
    let params = BannerParams {
        app_environment: "development",
        endpoint: "http://localhost:8765/mcp",
        database_url: "postgres://user:pass@localhost/db",
        storage_root: "/tmp/storage",
        auth_enabled: true,
        tools_log_enabled: true,
        tool_calls_log_enabled: true,
        console_theme: "Cyberpunk Aurora",
        web_ui_url: "http://localhost:8765/mail",
        projects: 3,
        agents: 5,
        messages: 42,
        file_reservations: 2,
        contact_links: 1,
    };
    let lines = render_startup_banner(&params);
    let joined = common::normalize_console_text(&lines.join("\n"));

    assert!(joined.contains("Server Configuration"));
    assert!(joined.contains("Database Statistics"));
    assert!(joined.contains("Web UI"));
    assert!(joined.contains("Stats Showcase"));

    // Ensure banner sanitization is applied (userinfo password redaction).
    assert!(joined.contains("postgres://user:<redacted>@localhost/db"));
    assert!(!joined.contains("postgres://user:pass@localhost/db"));
}

#[test]
fn tool_call_start_masks_params_after_normalization() {
    let params = serde_json::json!({
        "project_key": "/data/backend",
        "agent_name": "BlueLake",
        "bearer_token": "secret123"
    });
    let lines = render_tool_call_start("health_check", &params, None, None);
    let joined = common::normalize_console_text(&lines.join("\n"));

    assert!(joined.contains("TOOL CALL"));
    assert!(joined.contains("health_check"));
    assert!(joined.contains("Parameters:"));

    // Sensitive values masked; identity signals preserved.
    assert!(!joined.contains("secret123"));
    assert!(joined.contains("<redacted>"));
    assert!(joined.contains("/data/backend"));
    assert!(joined.contains("BlueLake"));
}

#[test]
fn tool_call_end_masks_result_json_after_normalization() {
    let result = r#"{"bearer_token":"secret123","ok":true}"#;
    let lines = render_tool_call_end("test_tool", 10, Some(result), 0, 0.0, &[], 2000);
    let joined = common::normalize_console_text(&lines.join("\n"));

    assert!(joined.contains("test_tool"));
    assert!(joined.contains("completed in"));
    assert!(joined.contains("Result:"));
    assert!(!joined.contains("secret123"));
    assert!(joined.contains("<redacted>"));
}
