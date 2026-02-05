// Note: unsafe required for env::set_var in Rust 2024
#![allow(unsafe_code)]

use fastmcp::{Budget, CallToolParams, Content, Cx, ReadResourceParams};
use fastmcp_core::SessionState;
use mcp_agent_mail_conformance::{Case, ExpectedError, Fixtures, Normalize};
use serde_json::Value;

fn normalize_pair(mut actual: Value, mut expected: Value, norm: &Normalize) -> (Value, Value) {
    for ptr in &norm.ignore_json_pointers {
        if let Some(v) = actual.pointer_mut(ptr) {
            *v = Value::Null;
        }
        if let Some(v) = expected.pointer_mut(ptr) {
            *v = Value::Null;
        }
    }

    for (ptr, replacement) in &norm.replace {
        if let Some(v) = actual.pointer_mut(ptr) {
            *v = replacement.clone();
        }
        if let Some(v) = expected.pointer_mut(ptr) {
            *v = replacement.clone();
        }
    }

    (actual, expected)
}

fn decode_json_from_tool_content(content: &[Content]) -> Result<Value, String> {
    if content.len() != 1 {
        return Err(format!(
            "expected exactly 1 content item, got {}",
            content.len()
        ));
    }

    match &content[0] {
        Content::Text { text } => match serde_json::from_str(text) {
            Ok(v) => Ok(v),
            Err(_) => Ok(Value::String(text.clone())),
        },
        Content::Resource { resource } => {
            let text = resource
                .text
                .as_deref()
                .ok_or_else(|| "tool returned Resource content without text".to_string())?;
            match serde_json::from_str(text) {
                Ok(v) => Ok(v),
                Err(_) => Ok(Value::String(text.to_string())),
            }
        }
        Content::Image { mime_type, .. } => Err(format!(
            "tool returned Image content (mime_type={mime_type}); JSON decode not supported yet"
        )),
    }
}

fn decode_json_from_resource_contents(
    uri: &str,
    contents: &[fastmcp::ResourceContent],
) -> Result<Value, String> {
    if contents.len() != 1 {
        return Err(format!(
            "expected exactly 1 resource content item for {uri}, got {}",
            contents.len()
        ));
    }
    let item = &contents[0];
    let text = item
        .text
        .as_deref()
        .ok_or_else(|| format!("resource {uri} returned no text"))?;
    match serde_json::from_str(text) {
        Ok(v) => Ok(v),
        Err(_) => Ok(Value::String(text.to_string())),
    }
}

fn assert_expected_error(got: &str, expect: &ExpectedError) {
    if let Some(substr) = &expect.message_contains {
        assert!(
            got.contains(substr),
            "expected error message to contain {substr:?}, got {got:?}"
        );
    }
}

fn args_from_case(case: &Case) -> Option<Value> {
    match &case.input {
        Value::Null => None,
        Value::Object(map) if map.is_empty() => None,
        other => Some(other.clone()),
    }
}

#[test]
fn load_and_validate_fixture_schema() {
    let fixtures = Fixtures::load_default().expect("failed to load fixtures");
    assert!(
        fixtures.tools.contains_key("health_check"),
        "fixtures should include at least health_check"
    );
    assert!(
        fixtures
            .resources
            .contains_key("resource://config/environment"),
        "fixtures should include resource://config/environment"
    );
}

#[test]
fn run_fixtures_against_rust_server_router() {
    let tmp = tempfile::TempDir::new().expect("failed to create tempdir");
    // Use a file-backed SQLite DB for conformance.
    // `sqlite:///:memory:` creates a *separate* database per connection, which breaks our pooled
    // access patterns (updates may be invisible to later reads).
    // SAFETY: This test sets process env vars before any other access to DATABASE_URL.
    let db_path = tmp.path().join("db.sqlite3");
    let db_url = format!("sqlite://{}", db_path.display());
    let storage_root = tmp.path().join("archive");
    unsafe {
        std::env::set_var("DATABASE_URL", db_url);
        std::env::set_var("WORKTREES_ENABLED", "1");
        std::env::set_var(
            "STORAGE_ROOT",
            storage_root
                .to_str()
                .expect("storage_root must be valid UTF-8"),
        );
    }

    let fixtures = Fixtures::load_default().expect("failed to load fixtures");
    let router = mcp_agent_mail_server::build_server().into_router();

    let cx = Cx::for_testing();
    let budget = Budget::INFINITE;
    let mut req_id: u64 = 1;

    for (tool_name, tool_fixture) in &fixtures.tools {
        for case in &tool_fixture.cases {
            let params = CallToolParams {
                name: tool_name.clone(),
                arguments: args_from_case(case),
                meta: None,
            };

            let result = router.handle_tools_call(
                &cx,
                req_id,
                params,
                &budget,
                SessionState::new(),
                None,
                None,
            );
            req_id += 1;

            match (&case.expect.ok, &case.expect.err) {
                (Some(expected_ok), None) => {
                    let call_result = result.unwrap_or_else(|e| {
                        panic!(
                            "tool {tool_name} case {}: unexpected router error: {e}",
                            case.name
                        )
                    });
                    if call_result.is_error {
                        // Print error content for debugging
                        let err_text = call_result
                            .content
                            .first()
                            .and_then(|c| match c {
                                Content::Text { text } => Some(text.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        panic!(
                            "tool {tool_name} case {}: expected ok, got error: {err_text}",
                            case.name
                        );
                    }

                    let actual = decode_json_from_tool_content(&call_result.content)
                        .unwrap_or_else(|e| panic!("tool {tool_name} case {}: {e}", case.name));
                    let (actual, expected) =
                        normalize_pair(actual, expected_ok.clone(), &case.normalize);
                    assert_eq!(
                        actual, expected,
                        "tool {tool_name} case {}: output mismatch",
                        case.name
                    );
                }
                (None, Some(expected_err)) => match result {
                    Ok(call_result) => {
                        assert!(
                            call_result.is_error,
                            "tool {tool_name} case {}: expected error, got ok",
                            case.name
                        );
                        let got = match &call_result.content.first() {
                            Some(Content::Text { text }) => text.as_str(),
                            _ => "<non-text error>",
                        };
                        assert_expected_error(got, expected_err);
                    }
                    Err(e) => {
                        assert_expected_error(&e.message, expected_err);
                    }
                },
                _ => panic!(
                    "tool {tool_name} case {}: invalid fixture expectation (must contain exactly one of ok/err)",
                    case.name
                ),
            }
        }
    }

    for (uri, resource_fixture) in &fixtures.resources {
        for case in &resource_fixture.cases {
            let params = ReadResourceParams {
                uri: uri.clone(),
                meta: None,
            };
            let result = router.handle_resources_read(
                &cx,
                req_id,
                &params,
                &budget,
                SessionState::new(),
                None,
                None,
            );
            req_id += 1;

            match (&case.expect.ok, &case.expect.err) {
                (Some(expected_ok), None) => {
                    let read_result = result.unwrap_or_else(|e| {
                        panic!(
                            "resource {uri} case {}: unexpected router error: {e}",
                            case.name
                        )
                    });
                    let actual = decode_json_from_resource_contents(uri, &read_result.contents)
                        .unwrap_or_else(|e| panic!("resource {uri} case {}: {e}", case.name));
                    let (actual, expected) =
                        normalize_pair(actual, expected_ok.clone(), &case.normalize);
                    assert_eq!(
                        actual, expected,
                        "resource {uri} case {}: output mismatch",
                        case.name
                    );
                }
                (None, Some(expected_err)) => match result {
                    Ok(read_result) => {
                        let got = read_result
                            .contents
                            .first()
                            .and_then(|c| c.text.as_deref())
                            .unwrap_or("<non-text error>");
                        assert_expected_error(got, expected_err);
                    }
                    Err(e) => {
                        assert_expected_error(&e.message, expected_err);
                    }
                },
                _ => panic!(
                    "resource {uri} case {}: invalid fixture expectation (must contain exactly one of ok/err)",
                    case.name
                ),
            }
        }
    }
}
