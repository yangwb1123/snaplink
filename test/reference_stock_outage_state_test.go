package ssotest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yangwb1123/snaplink/infrastructure/postgres"
)

// Deliberately narrower than the product DSN parser: this fault fixture must
// have exactly one explicit TCP target, never a service or fallback route.
func refOutageDSN(raw, endpoint string) (string, error) {
	bad := errors.New("outage fixture requires a single explicit loopback PostgreSQL URL")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "postgres" || u.Opaque != "" || u.Fragment != "" || u.Path == "" || u.Path == "/" {
		return "", bad
	}
	validEndpoint := func(address string) bool {
		host, port, err := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		n, portErr := strconv.Atoi(port)
		return err == nil && ip != nil && ip.IsLoopback() && portErr == nil && n > 0 && n <= 65535
	}
	if !validEndpoint(u.Host) || !validEndpoint(endpoint) {
		return "", bad
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", bad
	}
	for key, values := range query {
		switch key {
		case "sslmode", "search_path", "connect_timeout", "application_name", "default_query_exec_mode":
			if len(values) != 1 {
				return "", bad
			}
		default:
			return "", bad
		}
	}
	u.Host = endpoint
	bound := u.String()
	cfg, err := pgx.ParseConfig(bound)
	if err != nil || net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))) != endpoint {
		return "", bad
	}
	for _, fallback := range cfg.Fallbacks {
		if net.JoinHostPort(fallback.Host, strconv.Itoa(int(fallback.Port))) != endpoint {
			return "", bad
		}
	}
	return bound, nil
}

func TestStockPostgresOutageDSNBinding(t *testing.T) {
	original := "postgres://fixture:private%2Fvalue@127.0.0.1:5432/db?sslmode=disable&search_path=isolated&connect_timeout=2"
	for _, endpoint := range []string{"127.0.0.1:23456", "[::1]:23456"} {
		bound, err := refOutageDSN(original, endpoint)
		refProcessCheck(t, err, "bind fixture DSN")
		before, _ := url.Parse(original)
		after, _ := url.Parse(bound)
		if after.Host != endpoint || before.User.String() != after.User.String() || before.Path != after.Path || before.RawQuery != after.RawQuery {
			t.Fatal("DSN rebinding lost non-target configuration")
		}
	}
	for _, raw := range []string{
		"host=127.0.0.1 port=5432", "postgres://localhost:5432/db", "postgres://192.0.2.1:5432/db",
		"postgres://127.0.0.1/db", "postgres://127.0.0.1:0/db", "postgres://127.0.0.1:65536/db",
		"postgres://127.0.0.1:5432,127.0.0.2:5433/db", original + "#fragment", original + "&host=127.0.0.2",
		original + "&port=5555", original + "&hostaddr=127.0.0.2", original + "&service=other", original + "&servicefile=other",
		original + "&target_session_attrs=read-write", original + "&sslmode=prefer", original + "&%68ost=127.0.0.2",
		original + "&options=-csearch_path=other", original + "&bad=%zz",
	} {
		if bound, err := refOutageDSN(raw, "127.0.0.1:23456"); err == nil || bound != "" {
			t.Fatal("unsafe or ambiguous DSN bypass accepted (value withheld)")
		}
	}
	for _, endpoint := range []string{"localhost:5432", "192.0.2.1:5432", "127.0.0.1:0", "127.0.0.1:5432,127.0.0.2:5433"} {
		if _, err := refOutageDSN(original, endpoint); err == nil {
			t.Fatal("non-explicit loopback gate endpoint accepted")
		}
	}
}

func TestStockPostgresOutageSchemaGuard(t *testing.T) {
	h := &referenceProcesses{}
	if !h.canDropSchema() {
		t.Fatal("nil additional predicate changed empty fixture behavior")
	}
	joined := false
	h.schemaTeardownSafe = func() bool { return joined }
	if h.canDropSchema() {
		t.Fatal("schema DROP allowed before proxy join")
	}
	child := &refProcess{done: make(chan struct{})}
	h.children = []*refProcess{child}
	joined = true
	if h.canDropSchema() {
		t.Fatal("proxy join overrode original child Wait guard")
	}
	close(child.done)
	joined = false
	if h.canDropSchema() {
		t.Fatal("child Wait overrode proxy join guard")
	}
	joined = true
	if !h.canDropSchema() {
		t.Fatal("complete child/proxy teardown failed to authorize DROP")
	}
	h.schemaTeardownSafe = nil
	if !h.canDropSchema() {
		t.Fatal("nil predicate changed reaped fixture behavior")
	}
}

type refOutageState map[string][]map[string]json.RawMessage

func refOutageObserver(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	u, err := url.Parse(dsn)
	refProcessCheck(t, err, "parse private observer configuration")
	schema := u.Query().Get("search_path")
	if !regexp.MustCompile(`^refprocess_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatal("observer is not bound to an isolated reference schema")
	}
	db, err := postgres.Open(postgres.Config{DSN: dsn, MaxOpenConns: 1, MaxIdleConns: 1})
	refProcessCheck(t, err, "open direct state observer")
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var actual string
	refProcessCheck(t, db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&actual), "check direct observer schema")
	if actual != schema {
		t.Fatal("observer search_path resolved to a different schema")
	}
	return db
}

// Fixed SQL only, a read-only repeatable-read snapshot, and full row values:
// equality includes storage identity, security fields and exact nanosecond TTLs.
func refOutageSnapshot(t *testing.T, ctx context.Context, db *sql.DB) refOutageState {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	refProcessCheck(t, err, "start read-only outage snapshot")
	defer tx.Rollback()
	out := refOutageState{}
	queries := []struct{ table, sql string }{
		{"codes", "SELECT to_jsonb(t)::text FROM auth_codes t ORDER BY code"},
		{"refresh", "SELECT to_jsonb(t)::text FROM refresh_tokens t ORDER BY token"},
		{"families", "SELECT to_jsonb(t)::text FROM refresh_token_families t ORDER BY token"},
		{"sessions", "SELECT to_jsonb(t)::text FROM sessions t ORDER BY id"},
	}
	for _, query := range queries {
		rows, err := tx.QueryContext(ctx, query.sql)
		refProcessCheck(t, err, "read protected outage state")
		for rows.Next() {
			var raw string
			refProcessCheck(t, rows.Scan(&raw), "read protected outage row")
			var row map[string]json.RawMessage
			refProcessCheck(t, json.Unmarshal([]byte(raw), &row), "decode protected outage row")
			out[query.table] = append(out[query.table], row)
		}
		err = rows.Err()
		_ = rows.Close()
		refProcessCheck(t, err, "finish protected outage rows")
	}
	refProcessCheck(t, tx.Commit(), "finish read-only outage snapshot")
	return out
}

func refOutageLookup(t *testing.T, fixture *refStockFixture, kind, raw string) string {
	t.Helper()
	key, err := os.ReadFile(fixture.keyFile)
	refProcessCheck(t, err, "read private lookup binding")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(kind + "\x00" + raw))
	return "h1:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (state refOutageState) row(t *testing.T, table, key, value string) map[string]json.RawMessage {
	t.Helper()
	for _, row := range state[table] {
		var actual string
		if json.Unmarshal(row[key], &actual) == nil && actual == value {
			return row
		}
	}
	t.Fatal("expected protected row missing (identities withheld)")
	return nil
}

func refOutageText(t *testing.T, row map[string]json.RawMessage, key string) string {
	t.Helper()
	var value string
	refProcessCheck(t, json.Unmarshal(row[key], &value), "read protected string field")
	return value
}

func refOutageInt(t *testing.T, row map[string]json.RawMessage, key string) int64 {
	t.Helper()
	var value int64
	refProcessCheck(t, json.Unmarshal(row[key], &value), "read protected integer field")
	return value
}

func refOutageSame(t *testing.T, before, after refOutageState) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("outage requests changed protected rows, security bindings, ledger or TTLs (values withheld)")
	}
	t.Log("direct read-only PG snapshot: all code/refresh/family/session rows unchanged")
}

func refOutageBindingsEqual(t *testing.T, before, after map[string]json.RawMessage) {
	t.Helper()
	for _, key := range strings.Fields("user_id client_id provider scopes attributes family_id jti resources authorization_details sid amr acr auth_time confirmation_jkt family_created_at roles") {
		if !reflect.DeepEqual(before[key], after[key]) {
			t.Fatal("refresh rotation changed authentication/authorization/family binding: " + key)
		}
	}
	if refOutageInt(t, after, "generation") != refOutageInt(t, before, "generation")+1 {
		t.Fatal("refresh generation did not advance exactly once")
	}
}
