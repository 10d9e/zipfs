#!/bin/sh
set -e

# Ensure data directories exist
mkdir -p "$IPFS_PATH/blocks" "$IPFS_PATH/manifests"

# Dialable swarm address for DHT ADD_PROVIDER / Identify (default 0.0.0.0 listen maps to 127.0.0.1, which other containers cannot use).
# Set SWARM_ANNOUNCE_IP explicitly, or leave unset to pick the first non-loopback IPv4 from `hostname -i` (typical Docker bridge IP).
detect_swarm_ip() {
  for ip in $(hostname -i 2>/dev/null); do
    case "$ip" in
      127.*|::1) continue ;;
    esac
    case "$ip" in *:*) continue ;; esac
    printf '%s' "$ip"
    return 0
  done
  return 1
}

# Write cluster config if CLUSTER_PEERS is set
if [ -n "$CLUSTER_PEERS" ]; then
  if [ -n "${SWARM_ANNOUNCE_IP:-}" ]; then
    _ann_ip="$SWARM_ANNOUNCE_IP"
  else
    _ann_ip=$(detect_swarm_ip || true)
  fi
  if [ -n "$_ann_ip" ]; then
    announce_line='"announce_addrs": ["/ip4/'"${_ann_ip}"'/tcp/'"${SWARM_PORT:-4001}"'"],'
  else
    printf '%s\n' "WARNING: Failed to determine a non-loopback IPv4 address for swarm announce; writing empty announce_addrs. Identify may fall back to 127.0.0.1, which is not dialable from other containers/hosts. Set SWARM_ANNOUNCE_IP explicitly." >&2
    announce_line='"announce_addrs": [],'
  fi
  cat > "$IPFS_PATH/config.json" <<CONF
{
  "gateway_port": ${GATEWAY_PORT:-${PORT:-8080}},
  "listen_addrs": ["/ip4/0.0.0.0/tcp/${SWARM_PORT:-4001}"],
  ${announce_line}
  "cluster_peers": [${CLUSTER_PEERS}],
  "cluster_secret": "${CLUSTER_SECRET}",
  "cluster_mode": "${CLUSTER_MODE:-replicate}",
  "replication_factor": ${REPLICATION_FACTOR:-2},
  "self_heal_interval_secs": ${SELF_HEAL_INTERVAL:-60},
  "reprovide_interval_secs": ${REPROVIDE_INTERVAL_SECS:-60}
}
CONF
  echo "Cluster config written to $IPFS_PATH/config.json"
  cat "$IPFS_PATH/config.json"
fi

exec zipfs daemon
