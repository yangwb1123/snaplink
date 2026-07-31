package serverbuildsign

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/interfaces/sso"

	"github.com/yangwb1123/snaplink/platform/migrate"

	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
)

// serverbuildstore.BuildClientCertExtractor picks the RFC 8705 mTLS extractor backend.
//   - "" / "tls" — DefaultTLSPeerCertExtractor (in-process TLS only)
//   - "header"   — HeaderClientCertExtractor (reverse-proxy edge)
//
// serverbuildstore.ConvertClientJWKs maps cmd-config JWK entries to sso.JWK. Drops
// nothing — every parameter the SDK consumes is exposed in YAML.
// AppendReadyCheck registers v as a /readyz dependency when it
// implements Ping(ctx). All SQLite-backed stores satisfy this via
// the corresponding sqlite package; memory backends don't, so the
// type assertion silently no-ops for them — exactly the cadence we
// want (no readiness signal from a process-local map). name shows up
// in the /readyz response so operators can tell which dependency
// failed.
func AppendReadyCheck(opts []sso.Option, name string, v any) []sso.Option {
	p, ok := v.(interface{ Ping(context.Context) error })
	if !ok {
		return opts
	}
	return append(opts, sso.WithReadyCheck(name, p.Ping))
}

// CheckSQLiteSchema calls migrate.CheckSchema on the store's underlying
// database when v exposes a DB() *sql.DB method (every SQLite store does).
// Memory backends don't implement DB() so the check silently no-ops for
// them — the same additive pattern as AppendReadyCheck. Returns a fatal
// error when the live schema is ahead of binaryMax; this is a BOOT GATE,
// not a /readyz check, because a schema mismatch corrupts data before any
// request is served.
func CheckSQLiteSchema(ctx context.Context, v any, namespace string, binaryMax int) error {
	d, ok := v.(interface{ DB() *sql.DB })
	if !ok {
		return nil
	}
	db := d.DB()
	if db == nil {
		return nil
	}
	return migrate.CheckSchema(ctx, db, namespace, binaryMax)
}

// AppendStorageHealthSource collects v as a per-store entry for the
// /api/v1/admin/storage-health report (WithStorageHealth). It mirrors
// AppendReadyCheck's gating: only stores exposing Ping(ctx) are added, so
// process-local memory backends silently no-op (no reachability signal to
// report) and the report contains exactly the SQLite-backed stores — the
// same set /readyz aggregates, but with per-store detail.
//
// When the store exposes a SQLite DB() *sql.DB, the source also carries a
// SchemaVersions closure. Postgres-wire stores expose DB too, but
// migrate.Status is SQLite-specific; they remain Ping-only instead of
// returning a false sqlite_master error from the admin report.
func AppendStorageHealthSource(sources []sso.StorageHealthSource, name string, v any) []sso.StorageHealthSource {
	p, ok := v.(interface{ Ping(context.Context) error })
	if !ok {
		return sources
	}
	src := sso.StorageHealthSource{Name: name, Ping: p.Ping}
	if d, ok := v.(interface{ DB() *sql.DB }); ok {
		db := d.DB()
		if db != nil && isSQLiteDB(db) {
			src.SchemaVersions = func(ctx context.Context) (map[string]int, error) {
				st, err := migrate.Status(ctx, db)
				if err != nil {
					return nil, err
				}
				out := make(map[string]int, len(st))
				for _, ns := range st {
					out[ns.Namespace] = ns.Version
				}
				return out, nil
			}
		}
	}
	return append(sources, src)
}

func isSQLiteDB(db *sql.DB) bool {
	if db == nil {
		return false
	}
	return strings.Contains(strings.ToLower(fmt.Sprintf("%T", db.Driver())), "sqlite")
}

// AppendRateLimitReadyChecks registers a /readyz check for the
// policy's Default limiter and every prefix-rule limiter. Memory
// limiters silently no-op (no Ping method); the SQLite limiter
// exposes its database handle here so a wedged cluster-shared
// token-bucket trips /readyz before requests start failing.
//
// Per-prefix check names sanitize the prefix into kebab case so they
// surface readably in the /readyz JSON payload — `/token/revoke`
// becomes `sqlite-ratelimit-token-revoke`. Empty / unrecognized
// prefixes fall back to a positional `rule-N` name so two
// configurations can't collide.
func AppendRateLimitReadyChecks(opts []sso.Option, p ratelimit.Policy) []sso.Option {
	opts = AppendReadyCheck(opts, "sqlite-ratelimit-default", p.Default)
	for i, rule := range p.Prefixes {
		name := SanitizeReadyCheckSuffix(rule.Prefix)
		if name == "" {
			name = fmt.Sprintf("rule-%d", i)
		}
		opts = AppendReadyCheck(opts, "sqlite-ratelimit-"+name, rule.Limiter)
	}
	return opts
}

// SanitizeReadyCheckSuffix turns an arbitrary string into a kebab-
// safe suffix for a ReadyCheck name. Alphanumerics pass through;
// every other rune collapses into a single `-` separator. Used by
// AppendRateLimitReadyChecks to derive stable, JSON-payload-friendly
// names from operator-supplied URL prefixes.
func SanitizeReadyCheckSuffix(s string) string {
	var b strings.Builder
	dashOK := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dashOK = true
		default:
			if dashOK {
				b.WriteByte('-')
				dashOK = false
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}
