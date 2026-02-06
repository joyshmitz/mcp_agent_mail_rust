#!/usr/bin/env bash
# e2e_console.sh - PTY/TTY-focused E2E suite for rich console output.
#
# Run via:
#   ./scripts/e2e_test.sh console
#
# This suite validates that rich console output is enabled by default in real
# terminals, and that envfile-persisted `CONSOLE_*` settings are loaded.
#
# Artifacts:
#   tests/artifacts/console/<timestamp>/*

set -euo pipefail

# Safety: default to keeping temp dirs so the shared harness doesn't run `rm -rf`.
: "${AM_E2E_KEEP_TMP:=1}"

E2E_SUITE="${E2E_SUITE:-console}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./e2e_lib.sh
source "${SCRIPT_DIR}/e2e_lib.sh"

e2e_init_artifacts
e2e_banner "Console (PTY) E2E Test Suite"

e2e_save_artifact "env_dump.txt" "$(e2e_dump_env 2>&1)"

for cmd in script timeout python3; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        e2e_log "${cmd} not found; skipping suite"
        e2e_skip "${cmd} required"
        e2e_summary
        exit 0
    fi
done

e2e_fatal() {
    local msg="$1"
    e2e_fail "${msg}"
    e2e_summary || true
    exit 1
}

pick_port() {
python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

normalize_transcript() {
    local in_path="$1"
    local out_path="$2"
    python3 - <<'PY' "$in_path" "$out_path"
import re
import sys

in_path = sys.argv[1]
out_path = sys.argv[2]

data = open(in_path, "rb").read()

# Strip OSC sequences (BEL or ST terminator).
data = re.sub(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", b"", data)
# Strip CSI sequences (colors + cursor movement).
data = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data)
# Strip single-character ESC sequences (best-effort).
data = re.sub(rb"\x1b[@-_]", b"", data)

text = data.decode("utf-8", errors="replace")

# Remove util-linux `script` wrapper lines for stable assertions.
lines = []
for line in text.splitlines():
    if line.startswith("Script started on "):
        continue
    if line.startswith("Script done on "):
        continue
    lines.append(line)
text = "\n".join(lines) + "\n"

with open(out_path, "w", encoding="utf-8") as f:
    f.write(text)
PY
}

start_server_pty() {
    local label="$1"
    local port="$2"
    local db_path="$3"
    local storage_root="$4"
    local bin="$5"
    shift 5

    local typescript="${E2E_ARTIFACT_DIR}/server_${label}.typescript"
    e2e_log "Starting PTY server (${label}): 127.0.0.1:${port}"
    e2e_log "  typescript: ${typescript}"

    local timeout_s="${AM_E2E_SERVER_TIMEOUT_S:-15}"

    # Run the server in a PTY so stdout/stderr are treated as a real terminal.
    # Use `timeout` to guarantee the process eventually exits even if a test fails.
    (
        script -q -f -c "env \
DATABASE_URL=sqlite:////${db_path} \
STORAGE_ROOT=${storage_root} \
HTTP_HOST=127.0.0.1 \
HTTP_PORT=${port} \
HTTP_RBAC_ENABLED=0 \
HTTP_RATE_LIMIT_ENABLED=0 \
HTTP_JWT_ENABLED=0 \
HTTP_ALLOW_LOCALHOST_UNAUTHENTICATED=0 \
${*} \
timeout ${timeout_s}s ${bin} serve --host 127.0.0.1 --port ${port}" \
            "${typescript}"
    ) >/dev/null 2>&1 &

    echo $!
}

stop_server_pty() {
    local pid="$1"
    if kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        sleep 0.2
        kill -9 "${pid}" 2>/dev/null || true
    fi
}

BIN="$(e2e_ensure_binary "mcp-agent-mail" | tail -n 1)"

e2e_case_banner "default_rich_console_enabled (LOG_RICH_ENABLED unset)"
WORK1="$(e2e_mktemp "e2e_console_default_rich")"
DB1="${WORK1}/db.sqlite3"
STORAGE1="${WORK1}/storage"
mkdir -p "${STORAGE1}"
PORT1="$(pick_port)"

PID1="$(start_server_pty "default_rich" "${PORT1}" "${DB1}" "${STORAGE1}" "${BIN}")"
if ! e2e_wait_port 127.0.0.1 "${PORT1}" 10; then
    stop_server_pty "${PID1}"
    e2e_fatal "server failed to start (port not open)"
fi
sleep 0.6
stop_server_pty "${PID1}"
sleep 0.3

NORM1="${E2E_ARTIFACT_DIR}/server_default_rich.normalized.txt"
normalize_transcript "${E2E_ARTIFACT_DIR}/server_default_rich.typescript" "${NORM1}"
OUT1="$(cat "${NORM1}")"
e2e_assert_contains "banner includes Server Configuration" "${OUT1}" "Server Configuration"
e2e_assert_contains "banner includes Database Statistics" "${OUT1}" "Database Statistics"
e2e_assert_contains "banner includes Web UI" "${OUT1}" "Web UI"

e2e_case_banner "banner_suppressed_when_rich_disabled"
WORK2="$(e2e_mktemp "e2e_console_no_rich")"
DB2="${WORK2}/db.sqlite3"
STORAGE2="${WORK2}/storage"
mkdir -p "${STORAGE2}"
PORT2="$(pick_port)"

PID2="$(start_server_pty "no_rich" "${PORT2}" "${DB2}" "${STORAGE2}" "${BIN}" "LOG_RICH_ENABLED=false")"
if ! e2e_wait_port 127.0.0.1 "${PORT2}" 10; then
    stop_server_pty "${PID2}"
    e2e_fatal "server failed to start (port not open)"
fi
sleep 0.6
stop_server_pty "${PID2}"
sleep 0.3

NORM2="${E2E_ARTIFACT_DIR}/server_no_rich.normalized.txt"
normalize_transcript "${E2E_ARTIFACT_DIR}/server_no_rich.typescript" "${NORM2}"
OUT2="$(cat "${NORM2}")"
e2e_assert_not_contains "banner marker absent when rich disabled" "${OUT2}" "Server Configuration"

e2e_case_banner "persisted_console_settings_are_loaded"
WORK3="$(e2e_mktemp "e2e_console_persist")"
DB3="${WORK3}/db.sqlite3"
STORAGE3="${WORK3}/storage"
mkdir -p "${STORAGE3}"
PORT3="$(pick_port)"

PERSIST_ENV="${WORK3}/console.env"
cat > "${PERSIST_ENV}" <<'EOF'
CONSOLE_UI_HEIGHT_PERCENT=50
CONSOLE_UI_ANCHOR=top
CONSOLE_THEME=darcula
EOF

PID3="$(start_server_pty "persisted" "${PORT3}" "${DB3}" "${STORAGE3}" "${BIN}" "CONSOLE_PERSIST_PATH=${PERSIST_ENV}")"
if ! e2e_wait_port 127.0.0.1 "${PORT3}" 10; then
    stop_server_pty "${PID3}"
    e2e_fatal "server failed to start (port not open)"
fi
sleep 0.6
stop_server_pty "${PID3}"
sleep 0.3

NORM3="${E2E_ARTIFACT_DIR}/server_persisted.normalized.txt"
normalize_transcript "${E2E_ARTIFACT_DIR}/server_persisted.typescript" "${NORM3}"
OUT3="$(cat "${NORM3}")"
e2e_assert_contains "banner includes console layout line" "${OUT3}" "Console:"
e2e_assert_contains "console layout reflects persisted percent" "${OUT3}" "50%"

e2e_summary

