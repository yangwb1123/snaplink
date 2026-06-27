#!/usr/bin/env sh
# One-shot Redis Cluster bootstrap: 3 masters + 1 replica each (6 nodes).
# Idempotent: exits cleanly if the cluster is already formed, so re-running the
# redis-init service (or re-applying on a VM) is safe.
set -eu

if redis-cli -h redis-1a -a "$SSO_REDIS_PASSWORD" cluster info 2>/dev/null | grep -q 'cluster_state:ok'; then
  echo "redis cluster already formed"
  exit 0
fi

# Order matters: the first three become masters, the last three their replicas.
# --cluster-replicas 1 pairs them; redis assigns replicas to a different master
# than their own host when topology allows.
redis-cli -a "$SSO_REDIS_PASSWORD" --cluster create \
  redis-1a:6379 redis-2a:6379 redis-3a:6379 \
  redis-1b:6379 redis-2b:6379 redis-3b:6379 \
  --cluster-replicas 1 --cluster-yes
