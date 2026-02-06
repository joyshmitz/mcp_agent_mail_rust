#!/usr/bin/env bash
# test_http.sh - E2E test suite wrapper for unified HTTP server parity.
#
# Runs the implementation in scripts/e2e_http.sh so the suite can be invoked via:
#   ./scripts/e2e_test.sh http

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Safety: default to keeping temp dirs so shared harness cleanup doesn't run `rm -rf`.
: "${AM_E2E_KEEP_TMP:=1}"

bash "${SCRIPT_DIR}/../../scripts/e2e_http.sh"

