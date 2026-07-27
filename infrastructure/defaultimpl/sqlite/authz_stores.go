package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/connections/provider"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rebac"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

// ============================================================================
// ReBAC (Relationship-Based Access Control) Tuple Store
// ============================================================================

const rebacSchema = `
CREATE TABLE IF NOT EXISTS rebac_tuples (
    object   TEXT NOT NULL,
    relation TEXT NOT NULL,
    subject  TEXT NOT NULL,
    PRIMARY KEY (object, relation, subject)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_rebac_tuples_subject ON rebac_tuples(subject);
`

var rebacMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: rebacSchema},
}

// ReBACStore is a SQLite-backed [rebac.RelationTupleStore].
type ReBACStore struct{ db *sql.DB }

// NewReBACStore opens or creates a SQLite ReBAC tuple store at dsn.
func NewReBACStore(dsn string) (*ReBACStore, error) {
	db, err := SharedDB(dsn)
	if err != nil {
		return nil, fmt.Errorf("rebac sqlite: shared db: %w", err)
	}
	s := &ReBACStore{db: db}
	if err := migrate.Run(context.Background(), s.db, "rebac_tuples", rebacMigrations); err != nil {
		return nil, fmt.Errorf("rebac sqlite: migrate: %w", err)
	}
	return s, nil
}

func (s *ReBACStore) Write(_ context.Context, t rebac.Tuple) error {
	if err := t.Validate(); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO rebac_tuples (object, relation, subject) VALUES (?, ?, ?)`,
		t.Object, t.Relation, t.Subject,
	)
	return err
}

func (s *ReBACStore) Delete(_ context.Context, t rebac.Tuple) error {
	_, err := s.db.Exec(
		`DELETE FROM rebac_tuples WHERE object = ? AND relation = ? AND subject = ?`,
		t.Object, t.Relation, t.Subject,
	)
	return err
}

func (s *ReBACStore) Read(_ context.Context, filter rebac.TupleFilter) ([]rebac.Tuple, error) {
	var clauses []string
	var args []any
	if filter.Object != "" {
		clauses = append(clauses, "object = ?")
		args = append(args, filter.Object)
	}
	if filter.Relation != "" {
		clauses = append(clauses, "relation = ?")
		args = append(args, filter.Relation)
	}
	if filter.Subject != "" {
		clauses = append(clauses, "subject = ?")
		args = append(args, filter.Subject)
	}
	q := `SELECT object, relation, subject FROM rebac_tuples`
	if len(clauses) > 0 {
		q += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rebac.Tuple
	for rows.Next() {
		var t rebac.Tuple
		if err := rows.Scan(&t.Object, &t.Relation, &t.Subject); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if out == nil {
		out = []rebac.Tuple{}
	}
	return out, rows.Err()
}

var _ rebac.RelationTupleStore = (*ReBACStore)(nil)

// ============================================================================
// Provider (third-party login) Store
// ============================================================================

const providerSchema = `
CREATE TABLE IF NOT EXISTS providers (
    id           TEXT NOT NULL PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT '',
    type         TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    icon_url     TEXT NOT NULL DEFAULT '',
    button_label TEXT NOT NULL DEFAULT '',
    button_color TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 1,
    config       TEXT NOT NULL DEFAULT '{}',
    created_at   INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_providers_tenant ON providers(tenant_id);
`

var providerMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: providerSchema},
}

// ProviderStore is a SQLite-backed [provider.Store].
type ProviderStore struct{ db *sql.DB }

// NewProviderStore opens or creates a SQLite provider store at dsn.
func NewProviderStore(dsn string) (*ProviderStore, error) {
	db, err := SharedDB(dsn)
	if err != nil {
		return nil, fmt.Errorf("provider sqlite: shared db: %w", err)
	}
	s := &ProviderStore{db: db}
	if err := migrate.Run(context.Background(), s.db, "providers", providerMigrations); err != nil {
		return nil, fmt.Errorf("provider sqlite: migrate: %w", err)
	}
	return s, nil
}

func (s *ProviderStore) Create(_ context.Context, p *provider.Provider) error {
	cfg, err := json.Marshal(p.Config)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = s.db.Exec(
		`INSERT INTO providers (id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.TenantID, string(p.Type), p.DisplayName,
		p.IconURL, p.ButtonLabel, p.ButtonColor, btoi(p.Enabled),
		string(cfg), now, now,
	)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return provider.ErrProviderExists
	}
	return err
}

func (s *ProviderStore) Get(_ context.Context, id string) (*provider.Provider, error) {
	row := s.db.QueryRow(
		`SELECT id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at
		 FROM providers WHERE id = ?`, id,
	)
	return scanProvider(row)
}

func (s *ProviderStore) Update(_ context.Context, p *provider.Provider) error {
	cfg, err := json.Marshal(p.Config)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	res, err := s.db.Exec(
		`UPDATE providers SET type=?, display_name=?, icon_url=?, button_label=?, button_color=?, enabled=?, config=?, updated_at=?
		 WHERE id=?`,
		string(p.Type), p.DisplayName, p.IconURL, p.ButtonLabel, p.ButtonColor,
		btoi(p.Enabled), string(cfg), now, p.ID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return provider.ErrNoSuchProvider
	}
	return nil
}

func (s *ProviderStore) Delete(_ context.Context, id string) error {
	_, err := s.db.Exec(`DELETE FROM providers WHERE id = ?`, id)
	return err
}

func (s *ProviderStore) ListByTenant(_ context.Context, tenantID string) ([]*provider.Provider, error) {
	rows, err := s.db.Query(
		`SELECT id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at
		 FROM providers WHERE tenant_id = ? OR tenant_id = '' ORDER BY display_name`, tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviders(rows)
}

func (s *ProviderStore) ListGlobal(_ context.Context) ([]*provider.Provider, error) {
	rows, err := s.db.Query(
		`SELECT id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at
		 FROM providers WHERE tenant_id = '' ORDER BY display_name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviders(rows)
}

func (s *ProviderStore) ListByIDs(_ context.Context, ids []string) ([]*provider.Provider, error) {
	if len(ids) == 0 {
		return []*provider.Provider{}, nil
	}
	args := make([]any, len(ids))
	ph := make([]string, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	q := fmt.Sprintf(
		`SELECT id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at
		 FROM providers WHERE id IN (%s)`, strings.Join(ph, ","))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviders(rows)
}

func scanProvider(scanner interface{ Scan(dest ...any) error }) (*provider.Provider, error) {
	var (
		id, tid, ptype, dn, iurl, bl, bc string
		enabled                          int
		cj                               string
		cat, uat                         int64
	)
	if err := scanner.Scan(&id, &tid, &ptype, &dn, &iurl, &bl, &bc, &enabled, &cj, &cat, &uat); err != nil {
		if err == sql.ErrNoRows {
			return nil, provider.ErrNoSuchProvider
		}
		return nil, err
	}
	cfg := make(map[string]string)
	if cj != "" && cj != "{}" {
		json.Unmarshal([]byte(cj), &cfg)
	}
	return &provider.Provider{
		ID: id, TenantID: tid, Type: provider.ProviderType(ptype),
		DisplayName: dn, IconURL: iurl, ButtonLabel: bl, ButtonColor: bc,
		Enabled: enabled != 0, Config: cfg,
		CreatedAt: time.Unix(cat, 0), UpdatedAt: time.Unix(uat, 0),
	}, nil
}

func scanProviders(rows *sql.Rows) ([]*provider.Provider, error) {
	var out []*provider.Provider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []*provider.Provider{}
	}
	return out, rows.Err()
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

const devSchema = `CREATE TABLE IF NOT EXISTS devices (id TEXT NOT NULL PRIMARY KEY,user_id TEXT NOT NULL,fingerprint TEXT NOT NULL,type TEXT NOT NULL DEFAULT '',platform TEXT NOT NULL DEFAULT '',os_version TEXT NOT NULL DEFAULT '',browser_name TEXT NOT NULL DEFAULT '',browser_version TEXT NOT NULL DEFAULT '',device_name TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',raw_user_agent TEXT NOT NULL DEFAULT '',first_seen_at INTEGER NOT NULL DEFAULT 0,last_seen_at INTEGER NOT NULL DEFAULT 0,last_ip TEXT NOT NULL DEFAULT '',last_location TEXT NOT NULL DEFAULT '',login_count INTEGER NOT NULL DEFAULT 0,trust_score REAL NOT NULL DEFAULT 0.5,suspicious INTEGER NOT NULL DEFAULT 0,UNIQUE(user_id,fingerprint));CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);`
const devInsert = `INSERT OR REPLACE INTO devices (id,user_id,fingerprint,type,platform,os_version,browser_name,browser_version,device_name,notes,raw_user_agent,first_seen_at,last_seen_at,last_ip,last_location,login_count,trust_score,suspicious) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
const devSelect = `SELECT id,user_id,fingerprint,type,platform,os_version,browser_name,browser_version,device_name,notes,raw_user_agent,first_seen_at,last_seen_at,last_ip,last_location,login_count,trust_score,suspicious FROM devices`

type DeviceStore struct{ db *sql.DB }
func NewDeviceStore(dsn string) (*DeviceStore, error) {
	db, err := SharedDB(dsn); if err != nil { return nil, err }
	if err := migrate.Run(context.Background(), db, "devices", []migrate.Migration{{Version: 1, Name: "baseline", SQL: devSchema}}); err != nil { return nil, err }
	return &DeviceStore{db: db}, nil
}
func (s *DeviceStore) Get(_ context.Context, id string) (*device.Device, error) { return scanDev(s.db.QueryRow(devSelect+` WHERE id=?`, id)) }
func (s *DeviceStore) GetByFingerprint(_ context.Context, u, f string) (*device.Device, error) { return scanDev(s.db.QueryRow(devSelect+` WHERE user_id=? AND fingerprint=?`, u, f)) }
func (s *DeviceStore) Upsert(_ context.Context, d *device.Device) error {
	if d.ID == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		d.ID = "dev_" + hex.EncodeToString(b)
	}
	_, e := s.db.Exec(devInsert, d.ID, d.UserID, d.Fingerprint, string(d.Type), d.Platform, d.OSVersion, d.BrowserName, d.BrowserVersion, d.DeviceName, d.Notes, d.RawUserAgent, time.Now().Unix(), time.Now().Unix(), d.LastIP, d.LastLocation, 1, d.TrustScore, btoi(d.Suspicious))
	return e
}
func (s *DeviceStore) ListByUser(_ context.Context, uid string) ([]*device.Device, error) { r, e := s.db.Query(devSelect+` WHERE user_id=? ORDER BY last_seen_at DESC`, uid); if e != nil { return nil, e }; defer r.Close(); return scanDevs(r) }
func (s *DeviceStore) ListAll(_ context.Context) ([]*device.Device, error) { r, e := s.db.Query(devSelect+` ORDER BY last_seen_at DESC`); if e != nil { return nil, e }; defer r.Close(); return scanDevs(r) }
func (s *DeviceStore) Delete(_ context.Context, id string) error { _, e := s.db.Exec(`DELETE FROM devices WHERE id=?`, id); return e }
func (s *DeviceStore) DeleteByUser(_ context.Context, uid string) error { _, e := s.db.Exec(`DELETE FROM devices WHERE user_id=?`, uid); return e }

func scanDev(r interface{ Scan(...any) error }) (*device.Device, error) {
	var i, u, f, t, p, ov, bn, bv, dn, no, ua, lip, ll string; var fsa, lsa int64; var sp int; var lc int; var ts float64
	if e := r.Scan(&i, &u, &f, &t, &p, &ov, &bn, &bv, &dn, &no, &ua, &fsa, &lsa, &lip, &ll, &lc, &ts, &sp); e != nil {
		if e == sql.ErrNoRows { return nil, device.ErrNoSuchDevice }; return nil, e
	}
	return &device.Device{ID: i, UserID: u, Fingerprint: f, Type: device.DeviceType(t), Platform: p, OSVersion: ov, BrowserName: bn, BrowserVersion: bv, DeviceName: dn, Notes: no, RawUserAgent: ua, FirstSeenAt: time.Unix(fsa, 0), LastSeenAt: time.Unix(lsa, 0), LastIP: lip, LastLocation: ll, LoginCount: lc, TrustScore: ts, TrustLabel: device.TrustLabelForScore(ts), Suspicious: sp != 0}, nil
}
func scanDevs(r *sql.Rows) ([]*device.Device, error) {
	var o []*device.Device
	for r.Next() { d, e := scanDev(r); if e != nil { return nil, e }; o = append(o, d) }
	if o == nil { o = []*device.Device{} }; return o, r.Err()
}

const strSchema = `CREATE TABLE IF NOT EXISTS ssf_streams (id TEXT NOT NULL PRIMARY KEY,issuer TEXT NOT NULL DEFAULT '',subject TEXT NOT NULL DEFAULT '',events TEXT NOT NULL DEFAULT '[]',delivery_method TEXT NOT NULL DEFAULT '',delivery_endpoint TEXT NOT NULL DEFAULT '',delivery_auth TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0);CREATE INDEX IF NOT EXISTS idx_streams_subject ON ssf_streams(subject);`
const strInsert = `INSERT OR REPLACE INTO ssf_streams (id,issuer,subject,events,delivery_method,delivery_endpoint,delivery_auth,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)`
const strSelect = `SELECT id,issuer,subject,events,delivery_method,delivery_endpoint,delivery_auth,created_at,updated_at FROM ssf_streams`

type StreamStore struct{ db *sql.DB }
func NewStreamStore(dsn string) (*StreamStore, error) {
	db, err := SharedDB(dsn); if err != nil { return nil, err }
	if err := migrate.Run(context.Background(), db, "ssf_streams", []migrate.Migration{{Version: 1, Name: "baseline", SQL: strSchema}}); err != nil { return nil, err }
	return &StreamStore{db: db}, nil
}
func (s *StreamStore) Create(ctx context.Context, st *caep.Stream) error {
	ev, _ := json.Marshal(st.Events); now := time.Now().Unix()
	_, e := s.db.ExecContext(ctx, strInsert, st.ID, st.Issuer, st.Subject, string(ev), strDM(st), strDE(st), strDA(st), now, now)
	if e != nil && strings.Contains(e.Error(), "UNIQUE") { return caep.ErrStreamExists }; return e
}
func (s *StreamStore) Get(ctx context.Context, id string) (*caep.Stream, error) { return scanStr(s.db.QueryRowContext(ctx, strSelect+` WHERE id=?`, id)) }
func (s *StreamStore) Update(ctx context.Context, st *caep.Stream) error {
	ev, _ := json.Marshal(st.Events)
	r, e := s.db.ExecContext(ctx, `UPDATE ssf_streams SET issuer=?,subject=?,events=?,delivery_method=?,delivery_endpoint=?,delivery_auth=?,updated_at=? WHERE id=?`, st.Issuer, st.Subject, string(ev), strDM(st), strDE(st), strDA(st), time.Now().Unix(), st.ID)
	if e != nil { return e }; if n, _ := r.RowsAffected(); n == 0 { return caep.ErrStreamNotFound }; return nil
}
func (s *StreamStore) Delete(ctx context.Context, id string) error { _, e := s.db.ExecContext(ctx, `DELETE FROM ssf_streams WHERE id=?`, id); return e }
func (s *StreamStore) List(ctx context.Context, sub string) ([]*caep.Stream, error) {
	q := strSelect + ` ORDER BY created_at DESC`
	if sub != "" { q = strSelect + ` WHERE subject=? ORDER BY created_at DESC`; r, e := s.db.QueryContext(ctx, q, sub); if e != nil { return nil, e }; defer r.Close(); return scanStrs(r) }
	r, e := s.db.QueryContext(ctx, q); if e != nil { return nil, e }; defer r.Close(); return scanStrs(r)
}
func strDM(s *caep.Stream) string { if s.Delivery != nil { return s.Delivery.Method }; return "" }
func strDE(s *caep.Stream) string { if s.Delivery != nil { return s.Delivery.Endpoint }; return "" }
func strDA(s *caep.Stream) string { if s.Delivery != nil { return s.Delivery.Authorization }; return "" }
func scanStr(r interface{ Scan(...any) error }) (*caep.Stream, error) {
	var i, is, su, ej, dm, de, da string; var cat, uat int64
	if e := r.Scan(&i, &is, &su, &ej, &dm, &de, &da, &cat, &uat); e != nil {
		if e == sql.ErrNoRows { return nil, caep.ErrStreamNotFound }; return nil, e
	}
	st := &caep.Stream{ID: i, Issuer: is, Subject: su, CreatedAt: time.Unix(cat, 0), UpdatedAt: time.Unix(uat, 0)}
	if ej != "" && ej != "[]" { json.Unmarshal([]byte(ej), &st.Events) }
	if dm != "" { st.Delivery = &caep.StreamDelivery{Method: dm, Endpoint: de, Authorization: da} }
	return st, nil
}
func scanStrs(r *sql.Rows) ([]*caep.Stream, error) {
	var o []*caep.Stream
	for r.Next() { s, e := scanStr(r); if e != nil { return nil, e }; o = append(o, s) }
	if o == nil { o = []*caep.Stream{} }; return o, r.Err()
}
