#!/usr/bin/env bash
# test_rate_limit.sh - E2E test suite for HTTP rate limiting parity
#
# Verifies (br-1bm.2.5):
# - Basic allow/deny sequences for tools rate limiting
# - Per-tool isolation (endpoint keying)
# - Forwarded headers do not affect identity key (peer addr wins)
# - JWT sub identity overrides peer addr for key derivation
# - Optional Redis backend smoke (best-effort, if REDIS_URL is set)
#
# Artifacts:
# - Server logs: tests/artifacts/rate_limit/<timestamp>/server_*.log
# - Per-case transcripts: *_status.txt, *_headers.txt, *_body.json, *_curl_stderr.txt
# - Decision trace: decision_trace.json (+ trace.jsonl)

set -euo pipefail

E2E_SUITE="rate_limit"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/e2e_lib.sh
source "${SCRIPT_DIR}/../../scripts/e2e_lib.sh"

e2e_init_artifacts
e2e_banner "HTTP Rate Limiting E2E Test Suite"

if ! command -v curl >/dev/null 2>&1; then
    e2e_log "curl not found; skipping suite"
    e2e_skip "curl required"
    e2e_save_artifact "env_dump.txt" "$(e2e_dump_env 2>&1)"
    e2e_summary
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    e2e_log "python3 not found; skipping suite"
    e2e_skip "python3 required"
    e2e_save_artifact "env_dump.txt" "$(e2e_dump_env 2>&1)"
    e2e_summary
    exit 0
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pick_port() {
python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# Create an HS256 JWT without external deps (PyJWT not required).
# Args:
#   $1: secret
#   $2: payload JSON (string)
make_jwt_hs256() {
    python3 - <<'PY' "$1" "$2"
import base64, json, hmac, hashlib, sys
secret = sys.argv[1].encode("utf-8")
payload = json.loads(sys.argv[2])
header = {"alg":"HS256","typ":"JWT"}

def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")

def compact(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

segments = [b64url(compact(header)), b64url(compact(payload))]
signing_input = b".".join(segments)
sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
segments.append(b64url(sig))
print(b".".join(segments).decode("ascii"))
PY
}

TRACE_JSONL="${E2E_ARTIFACT_DIR}/trace.jsonl"
touch "$TRACE_JSONL"

trace_add() {
    local run_label="$1"
    local case_id="$2"
    local tool_name="$3"
    local expected_status="$4"
    local actual_status="$5"
    local note="${6:-}"
    python3 - <<'PY' "$run_label" "$case_id" "$tool_name" "$expected_status" "$actual_status" "$note" >>"$TRACE_JSONL"
import json, sys
run_label, case_id, tool_name, exp, act, note = sys.argv[1:]
out = {
  "run": run_label,
  "case": case_id,
  "tool": tool_name,
  "expected_status": int(exp),
  "actual_status": int(act),
}
if note:
  out["note"] = note
print(json.dumps(out))
PY
}

http_post_tool() {
    local case_id="$1"
    local url="$2"
    local tool_name="$3"
    shift 3

    local headers_file="${E2E_ARTIFACT_DIR}/${case_id}_headers.txt"
    local body_file="${E2E_ARTIFACT_DIR}/${case_id}_body.json"
    local status_file="${E2E_ARTIFACT_DIR}/${case_id}_status.txt"
    local curl_stderr_file="${E2E_ARTIFACT_DIR}/${case_id}_curl_stderr.txt"

    local payload
    payload="$(python3 - <<PY "$tool_name"
import json,sys
tool=sys.argv[1]
print(json.dumps({"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":tool,"arguments":{}}}))
PY
)"
    e2e_save_artifact "${case_id}_request.json" "${payload}"

    local args=(
        -sS
        -D "${headers_file}"
        -o "${body_file}"
        -w "%{http_code}"
        -X POST
        "${url}"
        -H "content-type: application/json"
        --data "${payload}"
    )
    for h in "$@"; do
        args+=(-H "$h")
    done

    set +e
    local status
    status="$(curl "${args[@]}" 2>"${curl_stderr_file}")"
    local rc=$?
    set -e

    echo "${status}" > "${status_file}"
    if [ "$rc" -ne 0 ]; then
        e2e_fail "${case_id}: curl failed rc=${rc}"
        return 1
    fi
    return 0
}

start_server() {
    local label="$1"
    local port="$2"
    local db_path="$3"
    local storage_root="$4"
    local bin="$5"
    shift 5

    local server_log="${E2E_ARTIFACT_DIR}/server_${label}.log"
    e2e_log "Starting server (${label}): 127.0.0.1:${port}"
    e2e_log "  log: ${server_log}"

    (
        export DATABASE_URL="sqlite:////${db_path}"
        export STORAGE_ROOT="${storage_root}"
        export HTTP_HOST="127.0.0.1"
        export HTTP_PORT="${port}"
        export HTTP_ALLOW_LOCALHOST_UNAUTHENTICATED="0"
        export HTTP_RBAC_ENABLED="0"
        export HTTP_RATE_LIMIT_ENABLED="1"
        export HTTP_RATE_LIMIT_TOOLS_PER_MINUTE="1"
        export HTTP_RATE_LIMIT_TOOLS_BURST="1"

        # Optional overrides passed as KEY=VALUE pairs in remaining args.
        while [ $# -gt 0 ]; do
            export "$1"
            shift
        done

        "${bin}" serve --host 127.0.0.1 --port "${port}"
    ) >"${server_log}" 2>&1 &
    echo $!
}

stop_server() {
    local pid="$1"
    if kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        sleep 0.2
        kill -9 "${pid}" 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# e2e_ensure_binary is verbose (logs to stdout); take the last line as the path.
BIN="$(e2e_ensure_binary "mcp-agent-mail" | tail -n 1)"

# ---------------------------------------------------------------------------
# Run 1: Memory backend (Bearer token auth)
# ---------------------------------------------------------------------------

e2e_banner "Run 1: Memory backend (static bearer token)"

WORK_MEM="$(e2e_mktemp "e2e_rate_limit_mem")"
DB_MEM="${WORK_MEM}/db.sqlite3"
STORAGE_MEM="${WORK_MEM}/storage_root"
PORT_MEM="$(pick_port)"
URL_MEM="http://127.0.0.1:${PORT_MEM}/api/"
TOKEN="e2e-token"

PID_MEM="$(start_server "memory" "${PORT_MEM}" "${DB_MEM}" "${STORAGE_MEM}" "${BIN}" \
    "HTTP_BEARER_TOKEN=${TOKEN}" \
    "HTTP_JWT_ENABLED=0" \
    "HTTP_RATE_LIMIT_BACKEND=memory" \
)"
trap 'stop_server "${PID_MEM}"' EXIT

if ! e2e_wait_port 127.0.0.1 "${PORT_MEM}" 10; then
    e2e_fail "memory server failed to start (port not open)"
    e2e_save_artifact "env_dump.txt" "$(e2e_dump_env 2>&1)"
    e2e_summary
    exit 1
fi

AUTHZ="Authorization: Bearer ${TOKEN}"

e2e_case_banner "Basic allow/deny on same tool (memory)"
http_post_tool "mem_case1_req1" "${URL_MEM}" "health_check" "${AUTHZ}"
S1="$(cat "${E2E_ARTIFACT_DIR}/mem_case1_req1_status.txt")"
trace_add "memory" "basic_1" "health_check" "200" "${S1}"
e2e_assert_eq "req1 HTTP 200" "200" "${S1}"

http_post_tool "mem_case1_req2" "${URL_MEM}" "health_check" "${AUTHZ}"
S2="$(cat "${E2E_ARTIFACT_DIR}/mem_case1_req2_status.txt")"
trace_add "memory" "basic_2" "health_check" "429" "${S2}"
e2e_assert_eq "req2 HTTP 429" "429" "${S2}"

e2e_case_banner "Per-tool isolation (memory)"
http_post_tool "mem_case2_tool_a_1" "${URL_MEM}" "tool_a" "${AUTHZ}"
SA1="$(cat "${E2E_ARTIFACT_DIR}/mem_case2_tool_a_1_status.txt")"
trace_add "memory" "per_tool_a_1" "tool_a" "200" "${SA1}"
e2e_assert_eq "tool_a first HTTP 200" "200" "${SA1}"

http_post_tool "mem_case2_tool_b_1" "${URL_MEM}" "tool_b" "${AUTHZ}"
SB1="$(cat "${E2E_ARTIFACT_DIR}/mem_case2_tool_b_1_status.txt")"
trace_add "memory" "per_tool_b_1" "tool_b" "200" "${SB1}"
e2e_assert_eq "tool_b first HTTP 200" "200" "${SB1}"

http_post_tool "mem_case2_tool_a_2" "${URL_MEM}" "tool_a" "${AUTHZ}"
SA2="$(cat "${E2E_ARTIFACT_DIR}/mem_case2_tool_a_2_status.txt")"
trace_add "memory" "per_tool_a_2" "tool_a" "429" "${SA2}"
e2e_assert_eq "tool_a second HTTP 429" "429" "${SA2}"

http_post_tool "mem_case2_tool_b_2" "${URL_MEM}" "tool_b" "${AUTHZ}"
SB2="$(cat "${E2E_ARTIFACT_DIR}/mem_case2_tool_b_2_status.txt")"
trace_add "memory" "per_tool_b_2" "tool_b" "429" "${SB2}"
e2e_assert_eq "tool_b second HTTP 429" "429" "${SB2}"

e2e_case_banner "Forwarded headers do not affect identity key (memory)"
http_post_tool "mem_case3_fwd_1" "${URL_MEM}" "forwarded_test" "${AUTHZ}" "X-Forwarded-For: 1.2.3.4"
SF1="$(cat "${E2E_ARTIFACT_DIR}/mem_case3_fwd_1_status.txt")"
trace_add "memory" "forwarded_1" "forwarded_test" "200" "${SF1}" "X-Forwarded-For=1.2.3.4"
e2e_assert_eq "forwarded req1 HTTP 200" "200" "${SF1}"

http_post_tool "mem_case3_fwd_2" "${URL_MEM}" "forwarded_test" "${AUTHZ}" "X-Forwarded-For: 5.6.7.8"
SF2="$(cat "${E2E_ARTIFACT_DIR}/mem_case3_fwd_2_status.txt")"
trace_add "memory" "forwarded_2" "forwarded_test" "429" "${SF2}" "X-Forwarded-For=5.6.7.8"
e2e_assert_eq "forwarded req2 HTTP 429" "429" "${SF2}"

stop_server "${PID_MEM}"
trap - EXIT

# ---------------------------------------------------------------------------
# Run 2: JWT backend (sub identity)
# ---------------------------------------------------------------------------

e2e_banner "Run 2: JWT backend (sub identity)"

WORK_JWT="$(e2e_mktemp "e2e_rate_limit_jwt")"
DB_JWT="${WORK_JWT}/db.sqlite3"
STORAGE_JWT="${WORK_JWT}/storage_root"
PORT_JWT="$(pick_port)"
URL_JWT="http://127.0.0.1:${PORT_JWT}/api/"
JWT_SECRET="e2e-secret"

PID_JWT="$(start_server "jwt" "${PORT_JWT}" "${DB_JWT}" "${STORAGE_JWT}" "${BIN}" \
    "HTTP_BEARER_TOKEN=" \
    "HTTP_JWT_ENABLED=1" \
    "HTTP_JWT_SECRET=${JWT_SECRET}" \
)"
trap 'stop_server "${PID_JWT}"' EXIT

if ! e2e_wait_port 127.0.0.1 "${PORT_JWT}" 10; then
    e2e_fail "jwt server failed to start (port not open)"
    e2e_save_artifact "env_dump.txt" "$(e2e_dump_env 2>&1)"
    e2e_summary
    exit 1
fi

JWT1="$(make_jwt_hs256 "${JWT_SECRET}" '{"sub":"user-123"}')"
JWT2="$(make_jwt_hs256 "${JWT_SECRET}" '{"sub":"user-456"}')"

AUTHZ1="Authorization: Bearer ${JWT1}"
AUTHZ2="Authorization: Bearer ${JWT2}"

e2e_case_banner "JWT sub identity isolates buckets"
http_post_tool "jwt_case1_user1_1" "${URL_JWT}" "health_check" "${AUTHZ1}"
J1="$(cat "${E2E_ARTIFACT_DIR}/jwt_case1_user1_1_status.txt")"
trace_add "jwt" "sub_user1_1" "health_check" "200" "${J1}" "sub=user-123"
e2e_assert_eq "user1 first HTTP 200" "200" "${J1}"

http_post_tool "jwt_case1_user2_1" "${URL_JWT}" "health_check" "${AUTHZ2}"
J2="$(cat "${E2E_ARTIFACT_DIR}/jwt_case1_user2_1_status.txt")"
trace_add "jwt" "sub_user2_1" "health_check" "200" "${J2}" "sub=user-456"
e2e_assert_eq "user2 first HTTP 200" "200" "${J2}"

http_post_tool "jwt_case1_user1_2" "${URL_JWT}" "health_check" "${AUTHZ1}"
J3="$(cat "${E2E_ARTIFACT_DIR}/jwt_case1_user1_2_status.txt")"
trace_add "jwt" "sub_user1_2" "health_check" "429" "${J3}" "sub=user-123"
e2e_assert_eq "user1 second HTTP 429" "429" "${J3}"

stop_server "${PID_JWT}"
trap - EXIT

# ---------------------------------------------------------------------------
# Run 3: Optional Redis backend smoke
# ---------------------------------------------------------------------------

if [ -n "${REDIS_URL:-}" ]; then
    e2e_banner "Run 3: Redis backend smoke (REDIS_URL set)"

    WORK_REDIS="$(e2e_mktemp "e2e_rate_limit_redis")"
    DB_REDIS="${WORK_REDIS}/db.sqlite3"
    STORAGE_REDIS="${WORK_REDIS}/storage_root"
    PORT_REDIS="$(pick_port)"
    URL_REDIS="http://127.0.0.1:${PORT_REDIS}/api/"

    PID_REDIS="$(start_server "redis" "${PORT_REDIS}" "${DB_REDIS}" "${STORAGE_REDIS}" "${BIN}" \
        "HTTP_BEARER_TOKEN=${TOKEN}" \
        "HTTP_JWT_ENABLED=0" \
        "HTTP_RATE_LIMIT_BACKEND=redis" \
        "HTTP_RATE_LIMIT_REDIS_URL=${REDIS_URL}" \
    )"
    trap 'stop_server "${PID_REDIS}"' EXIT

    if ! e2e_wait_port 127.0.0.1 "${PORT_REDIS}" 10; then
        e2e_fail "redis server failed to start (port not open)"
        e2e_save_artifact "env_dump.txt" "$(e2e_dump_env 2>&1)"
        e2e_summary
        exit 1
    fi

    e2e_case_banner "Basic allow/deny on same tool (redis)"
    http_post_tool "redis_case1_req1" "${URL_REDIS}" "redis_tool" "${AUTHZ}"
    R1="$(cat "${E2E_ARTIFACT_DIR}/redis_case1_req1_status.txt")"
    trace_add "redis" "basic_1" "redis_tool" "200" "${R1}"
    e2e_assert_eq "redis req1 HTTP 200" "200" "${R1}"

    http_post_tool "redis_case1_req2" "${URL_REDIS}" "redis_tool" "${AUTHZ}"
    R2="$(cat "${E2E_ARTIFACT_DIR}/redis_case1_req2_status.txt")"
    trace_add "redis" "basic_2" "redis_tool" "429" "${R2}"
    e2e_assert_eq "redis req2 HTTP 429" "429" "${R2}"

    # Best-effort Redis state snapshot (requires redis-cli with -u support).
    if command -v redis-cli >/dev/null 2>&1; then
        REDIS_KEY="rl:tools:redis_tool:127.0.0.1"
        set +e
        redis-cli -u "${REDIS_URL}" TTL "${REDIS_KEY}" >"${E2E_ARTIFACT_DIR}/redis_ttl.txt" 2>"${E2E_ARTIFACT_DIR}/redis_ttl_stderr.txt"
        redis-cli -u "${REDIS_URL}" HMGET "${REDIS_KEY}" tokens ts >"${E2E_ARTIFACT_DIR}/redis_hmget.txt" 2>"${E2E_ARTIFACT_DIR}/redis_hmget_stderr.txt"
        set -e
    else
        e2e_log "redis-cli not found; skipping Redis state snapshot"
        e2e_skip "redis-cli not available for state snapshot"
    fi

    stop_server "${PID_REDIS}"
    trap - EXIT
else
    e2e_log "REDIS_URL not set; skipping redis backend smoke"
    e2e_skip "REDIS_URL not set"
fi

# ---------------------------------------------------------------------------
# Emit trace JSON + summary
# ---------------------------------------------------------------------------

python3 - <<'PY' "$TRACE_JSONL" "${E2E_ARTIFACT_DIR}/decision_trace.json"
import json, sys
src, dest = sys.argv[1], sys.argv[2]
items = []
with open(src, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        items.append(json.loads(line))
with open(dest, "w", encoding="utf-8") as f:
    json.dump(items, f, indent=2, sort_keys=True)
PY

e2e_save_artifact "env_dump.txt" "$(e2e_dump_env 2>&1)"
e2e_summary

