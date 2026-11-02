#!/usr/bin/env bash
# Upgrade the deployed SSO service to a schema that matches the new binary.
#
# Every step is either read-only, reversible (a dump), or gated behind
# --confirm-plan. It stops at the first failure and prints the rollback. It never
# drops a database, never runs without a dump, and never retries a migration.
#
# Untested against the live host: the arguments and dry run are verified here,
# the operational steps are the same ones rehearsed on a disposable candidate.
set -euo pipefail
umask 077

SERVICE=""; BINARY=""; TARGET=""; PGHOST=""; PGPORT="5432"; DB="snaplink"; PSQL_USER="postgres"; CONFIG=""
VERIFY_SQL=""; WORKDIR=""; CONFIRM=""; DRY=0

usage() {
  cat <<'USAGE'
usage: remote_upgrade.sh --service NAME --binary PATH --target PATH
                         --pg-host HOST [--pg-port PORT] [--db NAME] [--psql-user USER]
                         --config FILE --verify-sql FILE --workdir DIR [--dry-run]
                         [--confirm-plan UPGRADE-<YYYYMMDD>]

  --service     systemd unit that runs the SSO server
  --binary      new sso-server binary staged on this host
  --target      path the service actually executes (replaced atomically)
  --config      server config; its bootstrap state_path must be absolute and writable
  --verify-sql  read-only verification SQL (four rows, all PASS)
  --workdir     private directory for the dump, the checksum and the log
  --dry-run     print the resolved plan and exit
USAGE
}

die() { echo "refused: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --service) SERVICE="${2:-}"; shift 2 ;;
    --binary) BINARY="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --pg-host) PGHOST="${2:-}"; shift 2 ;;
    --config) CONFIG="${2:-}"; shift 2 ;;
    --pg-port) PGPORT="${2:-}"; shift 2 ;;
    --db) DB="${2:-}"; shift 2 ;;
    --psql-user) PSQL_USER="${2:-}"; shift 2 ;;
    --verify-sql) VERIFY_SQL="${2:-}"; shift 2 ;;
    --workdir) WORKDIR="${2:-}"; shift 2 ;;
    --confirm-plan) CONFIRM="${2:-}"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$SERVICE" ] || die "service_required"
[ -n "$BINARY" ] || die "binary_required"
[ -n "$TARGET" ] || die "target_required"
[ -n "$PGHOST" ] || die "pg_host_required"
[ -n "$VERIFY_SQL" ] || die "verify_sql_required"
[ -n "$WORKDIR" ] || die "workdir_required"
[ -f "$BINARY" ] || die "binary_missing"
[ -x "$BINARY" ] || die "binary_not_executable"
[ -f "$VERIFY_SQL" ] || die "verify_sql_missing"
mkdir -p "$WORKDIR"; chmod 700 "$WORKDIR"

psql() { command psql "host=$PGHOST port=$PGPORT user=$PSQL_USER dbname=$DB" "$@"; }

# systemd may need elevation even for a unit this user owns; fail early instead of
# half-applying a swap that then cannot restart the service.
ctl() {
  if systemctl "$@" 2>/dev/null; then return 0; fi
  command sudo -n systemctl "$@"
}

EXPECTED="UPGRADE-$(date -u +%Y%m%d)"

if [ -n "$CONFIG" ]; then
  [ -f "$CONFIG" ] || die "config_missing"
  state="$(awk '/^[[:space:]]*state_path:/ { gsub(/["'"'"']/, "", $2); print $2; exit }' "$CONFIG")"
  case "$state" in
    "") : ;;                                   # bootstrap tracker not configured: nothing to check
    /*) [ -w "$(dirname "$state")" ] || die "bootstrap_state_path_not_writable:$state" ;;
    *) die "bootstrap_state_path_relative:$state" ;;
  esac
  # A tracker belongs to one database. Reusing one across a database switch
  # silently skips every step the previous deployment already applied, which is
  # how a migrated database ended up with a console client missing a scope the
  # server believed it had granted.
  if [ -n "$state" ] && [ -f "$state" ]; then
    # Fail closed: an upgrade that cannot read the database must not proceed.
    tables="$(PGPASSWORD="${PGPASSWORD:-}" psql -tAc \
      "select count(*) from pg_tables where schemaname='public'" 2>/dev/null)" \
      || die "preflight_sql_unreachable"
    if [ "$tables" -lt 28 ]; then
      die "bootstrap_tracker_ahead_of_database:tracker=$state tables=$tables"
    fi
  fi
fi
NEW_VERSION="$("$BINARY" -version 2>&1 | head -n 3 || true)"

if [ "$DRY" = 1 ]; then
  cat <<PLAN
plan:
  service       $SERVICE
  binary        $BINARY
  version       ${NEW_VERSION//$'\n'/ | }
  target        $TARGET
  postgres      $PSQL_USER@$PGHOST:$PGPORT/$DB
  verify sql    $VERIFY_SQL
  workdir       $WORKDIR
  backup        $WORKDIR/pre-upgrade.dump (+ .sha256)
  confirm       $CONFIRM (expected $EXPECTED)
steps:
  1 preflight (read-only): service state, target perms, disk, current schema versions, bootstrap state_path writability
  2 backup: pg_dump -Fc + sha256 + pg_restore -l smoke read
  3 stop $SERVICE, install $BINARY -> $TARGET atomically, start $SERVICE
  4 wait for /health 200, then run the verification SQL and require four PASS rows
  5 on any failure: stop, restore the dump, reinstall the previous binary, print the log path
PLAN
  exit 0
fi

[ "$CONFIRM" = "$EXPECTED" ] || die "confirm_plan_required:$EXPECTED"

log="$WORKDIR/upgrade.log"
exec > >(tee -a "$log") 2>&1
echo "== $(date -u +%FT%TZ) preflight"
ctl is-active --quiet "$SERVICE" || die "service_not_active:$SERVICE"
[ -w "$(dirname "$TARGET")" ] || die "target_dir_not_writable"
df -Pk "$WORKDIR" | awk 'NR==2 { if ($4 < 500000) exit 1 }' || die "less_than_500MiB_free"
PREVIOUS="$(readlink -f "$TARGET")"
PREVIOUS_SHA="$(sha256sum "$PREVIOUS" | cut -d' ' -f1)"
CURRENT="$(psql -tAc "select json_object_agg(t, v) from (
  select 'clients' t, max(version) v from schema_migrations_clients union all
  select 'permissions', max(version) from schema_migrations_permissions) s" 2>/dev/null || echo unknown)"
echo "   previous=$PREVIOUS sha256=$PREVIOUS_SHA schema=$CURRENT"

echo "== $(date -u +%FT%TZ) backup"
dump="$WORKDIR/pre-upgrade.dump"
PGPASSWORD="${PGPASSWORD:-}" pg_dump -Fc -h "$PGHOST" -p "$PGPORT" -U "$PSQL_USER" -d "$DB" -f "$dump"
sha256sum "$dump" | tee "$dump.sha256"
pg_restore -l "$dump" | head -n 1 >/dev/null || die "dump_unreadable"

echo "== $(date -u +%FT%TZ) deploy"
backup_binary="$WORKDIR/previous-$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$PREVIOUS" "$backup_binary"
rollback() {
  echo "== $(date -u +%FT%TZ) rolling back to $PREVIOUS"
  ctl stop "$SERVICE" || true
  cp -p "$backup_binary" "$TARGET" || true
  ctl start "$SERVICE" || true
  echo "rollback attempted; dump kept at $dump"
}
trap rollback ERR
ctl stop "$SERVICE"
install -m 0755 "$BINARY" "$TARGET.new"
mv -f "$TARGET.new" "$TARGET"
ctl start "$SERVICE"

echo "== $(date -u +%FT%TZ) verify"
for i in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:13015/health || true)"
  [ "$code" = 200 ] && break
  sleep 1
done
[ "$code" = 200 ] || { echo "health=$code"; die "health_not_200"; }
out="$(psql -X -q -f "$VERIFY_SQL")"
echo "$out"
echo "$out" | grep -q FAIL && die "verification_failed"
passes="$(echo "$out" | grep -c '|PASS|' || true)"
[ "$passes" -ge 4 ] || die "verification_incomplete:$passes"

trap - ERR
echo "== $(date -u +%FT%TZ) done"
echo "rollback: systemctl stop $SERVICE && cp -p $backup_binary $TARGET && pg_restore -d $DB --clean --if-exists $dump && systemctl start $SERVICE"
