#!/usr/bin/env bash
# 5-node zipfs integration: cluster config, libp2p dial-noise mesh, replicated content via HTTP.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
export COMPOSE_FILE

if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: required command 'curl' not found in PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: required command 'python3' not found in PATH" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: required command 'docker compose' is not available" >&2
  exit 1
fi
cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Building and starting stack (first build may take several minutes)..."
docker compose -f "${COMPOSE_FILE}" up -d --build

echo "Waiting for gateways on 8081–8085..."
deadline=$((SECONDS + 180))
while (( SECONDS < deadline )); do
  ok=true
  for p in 8081 8082 8083 8084 8085; do
    curl -sf --max-time 3 "http://127.0.0.1:${p}/api/v0/id" >/dev/null || ok=false
  done
  if $ok; then
    break
  fi
  sleep 2
done

for p in 8081 8082 8083 8084 8085; do
  curl -sf --max-time 5 "http://127.0.0.1:${p}/api/v0/id" >/dev/null || {
    echo "ERROR: gateway not ready on port ${p}" >&2
    exit 1
  }
done

echo "Checking distinct PeerIDs..."
ids=()
for p in 8081 8082 8083 8084 8085; do
  id="$(curl -sf --max-time 10 "http://127.0.0.1:${p}/api/v0/id" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ID"])')"
  ids+=("${id}")
done
uniq="$(printf '%s\n' "${ids[@]}" | sort -u | wc -l | tr -d ' ')"
if [[ "${uniq}" != "5" ]]; then
  echo "ERROR: expected 5 unique PeerIDs, got ${uniq}" >&2
  printf '  %s\n' "${ids[@]}" >&2
  exit 1
fi
echo "  OK: 5 unique PeerIDs"

echo "Libp2p dial-noise (all ordered pairs i!=j)..."
for i in 1 2 3 4 5; do
  for j in 1 2 3 4 5; do
    if [[ "${i}" -eq "${j}" ]]; then
      continue
    fi
    svc_i="zipfs${i}"
    host_j="zipfs${j}"
    if ! out="$(docker compose -f "${COMPOSE_FILE}" exec -T "${svc_i}" zipfs net dial-noise "${host_j}" 4001 2>&1)"; then
      echo "ERROR: dial-noise ${svc_i} -> ${host_j} failed" >&2
      echo "${out}" >&2
      exit 1
    fi
    if [[ "${out}" != *"remote PeerID:"* ]]; then
      echo "ERROR: dial-noise ${svc_i} -> ${host_j}: unexpected output" >&2
      echo "${out}" >&2
      exit 1
    fi
  done
done
echo "  OK: 20 Noise handshakes"

echo "Upload on zipfs1, expect /ipfs/<cid> on zipfs2–zipfs5..."
payload="integration-$(date +%s)-$$"
CID="$(
  curl -sf --max-time 30 -X POST -F "file=@-;filename=test.txt" \
    "http://127.0.0.1:8081/api/v0/add" <<<"${payload}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["Hash"])'
)"
echo "  CID=${CID}"

for p in 8082 8083 8084 8085; do
  got=false
  deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${p}/ipfs/${CID}" || true)"
    if [[ "${code}" == "200" ]]; then
      body="$(curl -sf --max-time 10 "http://127.0.0.1:${p}/ipfs/${CID}")"
      if [[ "${body}" != "${payload}" ]]; then
        echo "ERROR: body mismatch on port ${p}" >&2
        exit 1
      fi
      echo "  OK: node ${p} served content"
      got=true
      break
    fi
    sleep 2
  done
  if [[ "${got}" != "true" ]]; then
    echo "ERROR: timeout waiting for CID on port ${p}" >&2
    exit 1
  fi
done

echo "All integration checks passed."
