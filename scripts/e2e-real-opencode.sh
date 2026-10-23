#!/usr/bin/env bash
# Run OCT end-to-end parity tests against a real, isolated OpenCode V2 server.
#
# Creates temporary HOME/XDG roots and a temporary server password, starts
# `opencode serve` on loopback, runs the parity suite, and removes everything.
# It never reads or copies the user's opencode.db, auth.json, or credentials.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v opencode >/dev/null 2>&1; then
  echo "opencode is not installed; skipping real E2E parity" >&2
  exit 0
fi

BASE="$(mktemp -d "${TMPDIR:-/tmp}/oct-e2e.XXXXXX")"
PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
PASSWORD="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
PID=""

cleanup() {
  if [[ -n "$PID" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$BASE"
}
trap cleanup EXIT

mkdir -p "$BASE"/{home,data,config,cache,state,work}
(
  cd "$BASE/work"
  exec env \
    HOME="$BASE/home" \
    XDG_DATA_HOME="$BASE/data" \
    XDG_CONFIG_HOME="$BASE/config" \
    XDG_CACHE_HOME="$BASE/cache" \
    XDG_STATE_HOME="$BASE/state" \
    OPENCODE_PASSWORD="$PASSWORD" \
    opencode serve --hostname 127.0.0.1 --port "$PORT"
) >"$BASE/server.log" 2>&1 &
PID=$!

for _ in $(seq 1 80); do
  if curl -fsS -u "opencode:$PASSWORD" "http://127.0.0.1:$PORT/api/info" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "opencode serve exited before becoming ready" >&2
    sed -e 's/password.*/password <redacted>/I' "$BASE/server.log" | tail -20 >&2 || true
    exit 1
  fi
  sleep 0.25
done

if ! curl -fsS -u "opencode:$PASSWORD" "http://127.0.0.1:$PORT/api/info" >/dev/null 2>&1; then
  echo "opencode serve did not become ready" >&2
  sed -e 's/password.*/password <redacted>/I' "$BASE/server.log" | tail -20 >&2 || true
  exit 1
fi

echo "real OpenCode server ready on loopback; running parity tests"
OCT_REQUIRE_REAL_PTY=1 \
OCT_REAL_UPSTREAM="http://127.0.0.1:$PORT" \
OPENCODE_PASSWORD="$PASSWORD" \
  cargo test -p oct-integration-tests --test parity --test opencode_v2 --test pty_real --test pty_e2ee_real -- --test-threads=1
