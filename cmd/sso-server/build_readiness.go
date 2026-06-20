package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/snaplink/sso/interfaces/sso"

	"github.com/snaplink/sso/platform/migrate"

	"github.com/snaplink/sso/interfaces/ratelimit"
)

// buildClientCertExtractor picks the RFC 8705 mTLS extractor backend.
//   - "" / "tls" — DefaultTLSPeerCertExtractor (in-process TLS only)
//   - "header"   — HeaderClientCertExtractor (reverse-proxy edge)
//
// convertClientJWKs maps cmd-config JWK entries to sso.JWK. Drops
// nothing — every parameter the SDK consumes is exposed in YAML.
// appendReadyCheck registers v as a /readyz dependency when it
// implements Ping(ctx). All SQLite-backed stores satisfy this via
// the corresponding sqlite package; memory backends don't, so the
// type assertion silently no-ops for them — exactly the cadence we
// want (no readiness signal from a process-local map). name shows up
// in the /readyz response so operators can tell which dependency
// failed.
func appendReadyCheck(opts []sso.Option, name string, v any) []sso.Option {
	p, ok := v.(interface{ Ping(context.Context) error })
	if !ok {
		return opts
	}
	return append(opts, sso.WithReadyCheck(name, p.Ping))
}

// checkSQLiteSchema calls migrate.CheckSchema on the store's underlying
// database when v exposes a DB() *sql.DB method (every SQLite store does).
// Memory backends don't implement DB() so the check silently no-ops for
// them — the same additive pattern as appendReadyCheck. Returns a fatal
// error when the live schema is ahead of binaryMax; this is a BOOT GATE,
// not a /readyz check, because a schema mismatch corrupts data before any
// request is served.
func checkSQLiteSchema(ctx context.Context, v any, namespace string, binaryMax int) error {
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

// appendStorageHealthSource collects v as a per-store entry for the
// /api/v1/admin/storage-health report (WithStorageHealth). It mirrors
// appendReadyCheck's gating: only stores exposing Ping(ctx) are added, so
// process-local memory backends silently no-op (no reachability signal to
// report) and the report contains exactly the SQLite-backed stores — the
// same set /readyz aggregates, but with per-store detail.
//
// When the store also exposes DB() *sql.DB (every SQLite store does) the
// source carries a SchemaVersions closure that runs migrate.Status on that
// store's handle, so the report shows each store's migrate-namespace ->
// applied-version map. A store without an accessible *sql.DB is Ping-only
// (no schema_versions). name is operator-facing and MUST NOT carry a DSN or
// secret — the report never surfaces the connection string, only this label
// plus a generic reachability error.
func appendStorageHealthSource(sources []sso.StorageHealthSource, name string, v any) []sso.StorageHealthSource {
	p, ok := v.(interface{ Ping(context.Context) error })
	if !ok {
		return sources
	}
	src := sso.StorageHealthSource{Name: name, Ping: p.Ping}
	if d, ok := v.(interface{ DB() *sql.DB }); ok {
		db := d.DB()
		if db != nil {
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

// appendRateLimitReadyChecks registers a /readyz check for the
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
func appendRateLimitReadyChecks(opts []sso.Option, p ratelimit.Policy) []sso.Option {
	opts = appendReadyCheck(opts, "sqlite-ratelimit-default", p.Default)
	for i, rule := range p.Prefixes {
		name := sanitizeReadyCheckSuffix(rule.Prefix)
		if name == "" {
			name = fmt.Sprintf("rule-%d", i)
		}
		opts = appendReadyCheck(opts, "sqlite-ratelimit-"+name, rule.Limiter)
	}
	return opts
}

// sanitizeReadyCheckSuffix turns an arbitrary string into a kebab-
// safe suffix for a ReadyCheck name. Alphanumerics pass through;
// every other rune collapses into a single `-` separator. Used by
// appendRateLimitReadyChecks to derive stable, JSON-payload-friendly
// names from operator-supplied URL prefixes.
func sanitizeReadyCheckSuffix(s string) string {
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
