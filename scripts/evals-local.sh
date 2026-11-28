#!/usr/bin/env bash
# Run the local route of internal/evals against a loopback llama-server (ADR-0082, ADR-0173).
#
# Usage:
#   scripts/evals-local.sh            Run live evals, write a temporary score report, and restore cassette.json on exit.
#   scripts/evals-local.sh --record   Run live evals and keep the newly recorded cassette.json in the working tree.
#   scripts/evals-local.sh --update   Record cassette.json, update baseline.json, history.jsonl, and docs/evals.md, then verify floors.
set -euo pipefail

mode="check"
if [ "$#" -gt 1 ]; then
  echo "usage: $0 [--record | --update]" >&2
  exit 2
fi
if [ "$#" -eq 1 ]; then
  case "$1" in
    --record)
      mode="record"
      ;;
    --update)
      mode="update"
      ;;
    -h|--help)
      sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "usage: $0 [--record | --update]" >&2
      exit 2
      ;;
  esac
fi

readonly MODEL_URL="https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/bc640142c66e1fdd12af0bd68f40445458f3869b/Qwen3-4B-Q4_K_M.gguf"
readonly MODEL_SHA256="7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
readonly CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/ipso-evals"
readonly MODEL_FILE="${CACHE_DIR}/Qwen3-4B-Q4_K_M.gguf"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found in PATH: $1" >&2
    exit 1
  fi
}

verify_sha256() {
  local file="$1" want="$2" got
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    got="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    echo "error: sha256sum or shasum is required" >&2
    exit 1
  fi
  if [ "$got" != "$want" ]; then
    echo "error: sha256 mismatch for ${file}: got ${got}, want ${want}" >&2
    return 1
  fi
}

port_in_use() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:8080 -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  local rc=0
  curl -s --connect-timeout 1 --max-time 1 http://127.0.0.1:8080/ >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 7 ]
}

for cmd in llama-server go curl openssl git; do
  require_cmd "$cmd"
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "$repo_root"

cassette_path="internal/evals/testdata/cassette.json"
if [ ! -f "$cassette_path" ]; then
  echo "error: ${cassette_path} not found under ${repo_root}" >&2
  exit 1
fi

if [ "$mode" = "check" ]; then
  if [ -n "$(git status --porcelain -- "$cassette_path")" ]; then
    echo "error: ${cassette_path} has uncommitted changes; commit, stash, or pass --record/--update" >&2
    exit 1
  fi
fi

if port_in_use; then
  echo "error: 127.0.0.1:8080 is already in use; stop the running listener before running local evals" >&2
  exit 1
fi

mkdir -p "$CACHE_DIR"
if [ ! -f "$MODEL_FILE" ]; then
  echo "Downloading pinned model to ${MODEL_FILE}..."
  tmp_model="${MODEL_FILE}.tmp.$$"
  trap 'rm -f "$tmp_model"' EXIT INT TERM
  curl --fail --location --show-error --proto '=https' --tlsv1.2 --output "$tmp_model" "$MODEL_URL"
  verify_sha256 "$tmp_model" "$MODEL_SHA256"
  mv "$tmp_model" "$MODEL_FILE"
  trap - EXIT INT TERM
else
  verify_sha256 "$MODEL_FILE" "$MODEL_SHA256"
fi

tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"
work_dir="$(mktemp -d "${tmp_base}/ipso-evals-local.XXXXXX")"
llama_log="${work_dir}/llama.log"
report_path="${tmp_base}/ipso-evals-scores-$(date +%Y%m%d-%H%M%S)-$$.json"
cassette_backup=""
server_pid=""

cleanup() {
  local exit_code=$?
  set +e
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ -n "$cassette_backup" ] && [ -f "$cassette_backup" ]; then
    if ! cp "$cassette_backup" "$cassette_path"; then
      echo "warning: failed to restore ${cassette_path} from ${cassette_backup}" >&2
    fi
  fi
  rm -rf "$work_dir"
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

if [ "$mode" = "check" ]; then
  cassette_backup="${work_dir}/cassette.json.bak"
  cp "$cassette_path" "$cassette_backup"
fi

key="$(openssl rand -hex 24)"
LLAMA_API_KEY="$key" llama-server \
  -m "$MODEL_FILE" \
  --alias qwen3-4b-q4_k_m \
  --host 127.0.0.1 \
  --port 8080 \
  --ctx-size 8192 \
  --parallel 1 \
  --no-cache-prompt \
  --seed 0 \
  --chat-template-kwargs '{"enable_thinking":false}' \
  >"$llama_log" 2>&1 &
server_pid=$!

ready=0
for _ in $(seq 1 180); do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "error: llama-server exited during startup:" >&2
    cat "$llama_log" >&2
    exit 1
  fi
  if curl -fsS --max-time 2 http://127.0.0.1:8080/health >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [ "$ready" -ne 1 ]; then
  echo "error: llama-server did not become healthy within 180s:" >&2
  cat "$llama_log" >&2
  exit 1
fi

test_args=(-run '^TestEvals$' -count=1 -timeout 120m -v -route local -record -report "$report_path")
if [ "$mode" = "update" ]; then
  test_args+=(-update)
fi

IPSO_LLM_LOCAL="$key" \
IPSO_LLM_MISTRAL="not-used-by-the-eval-tenant" \
go test ./internal/evals "${test_args[@]}"

if [ "$mode" = "update" ]; then
  go test ./internal/evals -count=1
fi

echo "Score report written to ${report_path}"
