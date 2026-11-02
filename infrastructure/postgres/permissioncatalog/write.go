package permissioncatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/permissions/resourcecatalog"
)

func (p *Catalog) RegisterResource(ctx context.Context, r *permissions.Resource) error {
	if r == nil {
		return permissions.ErrInvalidResource
	}
	if err := r.Validate(); err != nil {
		return err
	}
	attrs, err := json.Marshal(r.Attributes)
	if err != nil {
		return err
	}
	required, err := json.Marshal(r.RequiredPermissions)
	if err != nil {
		return err
	}
	now, created := time.Now().UTC(), r.CreatedAt
	if created.IsZero() {
		created = now
	}
	d := resourcecatalog.DispatchFor(r.Type, r.Attributes)
	auth := 0
	if r.RequiresAuth {
		auth = 1
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO permissions_resources (`+columns+`)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
 ON CONFLICT(id) DO UPDATE SET tenant_id=excluded.tenant_id,client_id=excluded.client_id,
 type=excluded.type,name=excluded.name,requires_auth=excluded.requires_auth,
 description=excluded.description,attributes_json=excluded.attributes_json,
 required_permissions_json=excluded.required_permissions_json,require_mode=excluded.require_mode,
 updated_at=excluded.updated_at,dispatch_key=excluded.dispatch_key,
 dispatch_method=excluded.dispatch_method,dispatch_segments=excluded.dispatch_segments`,
		r.ID, r.TenantID, r.ClientID, string(r.Type), r.Name, auth, r.Description,
		string(attrs), string(required), string(r.RequireMode), created.UnixNano(), now.UnixNano(), []byte(d.Key), d.Method, d.Segments)
	var conflict *pgconn.PgError
	if errors.As(err, &conflict) && conflict.Code == "23505" {
		return permissions.ErrResourceExists
	}
	if err != nil {
		return fmt.Errorf("permissions/postgres: register resource: %w", err)
	}
	return nil
}

func (p *Catalog) DeleteResource(ctx context.Context, id string) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM permissions_resources WHERE id=$1", id)
	return err
}

var (
	_ permissions.ResourceProvider      = (*Catalog)(nil)
	_ permissions.ResourceCatalogLister = (*Catalog)(nil)
)
