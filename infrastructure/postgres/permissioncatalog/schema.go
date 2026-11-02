// Package permissioncatalog implements the PostgreSQL resource-catalog extension.
// Its parent provider owns pool lifetime and forward-only schema migrations.
package permissioncatalog

import "database/sql"

const Schema = `
CREATE TABLE IF NOT EXISTS permissions_resources (
 id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL DEFAULT '',
 client_id TEXT NOT NULL DEFAULT '',
 type TEXT NOT NULL,
 name TEXT NOT NULL,
 requires_auth INTEGER NOT NULL DEFAULT 0,
 description TEXT NOT NULL DEFAULT '',
 attributes_json TEXT NOT NULL DEFAULT '{}',
 required_permissions_json TEXT NOT NULL DEFAULT '[]',
 require_mode TEXT NOT NULL DEFAULT '',
 created_at BIGINT NOT NULL,
 updated_at BIGINT NOT NULL,
 dispatch_key BYTEA NOT NULL DEFAULT '',
 dispatch_method TEXT NOT NULL DEFAULT '',
 dispatch_segments INTEGER NOT NULL DEFAULT 0,
 UNIQUE(tenant_id,client_id,type,name)
);
CREATE INDEX IF NOT EXISTS idx_permissions_resources_scope ON permissions_resources(tenant_id,client_id,type,name);
CREATE INDEX IF NOT EXISTS idx_permissions_resources_dispatch ON permissions_resources(tenant_id,client_id,dispatch_method,dispatch_segments);
CREATE INDEX IF NOT EXISTS idx_permissions_resources_dispatch_key ON permissions_resources(tenant_id,client_id,type,dispatch_key);
`

const columns = `id,tenant_id,client_id,type,name,requires_auth,description,
attributes_json,required_permissions_json,require_mode,created_at,updated_at,
dispatch_key,dispatch_method,dispatch_segments`

const maxCatalogRows = 100_000
const maxCatalogJSONBytes = 16 << 20

type Catalog struct{ db *sql.DB }

// New attaches operations only; migration is an explicit parent-provider step.
func New(db *sql.DB) *Catalog { return &Catalog{db: db} }
