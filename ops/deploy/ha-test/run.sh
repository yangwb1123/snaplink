#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
compose_file="$repo_dir/ops/deploy/ha-test/compose.yaml"

cleanup() {
  docker compose -p snaplink-ha-test -f "$compose_file" down -v --remove-orphans
}
trap cleanup EXIT INT TERM

docker compose -p snaplink-ha-test -f "$compose_file" up -d --wait
SNAPLINK_HA_TEST=1 go test "$repo_dir/test/ha" -run TestRealMultiReplicaFailureRecovery -count=1 -v

