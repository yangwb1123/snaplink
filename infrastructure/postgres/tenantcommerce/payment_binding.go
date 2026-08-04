package tenantcommerce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func verifyPaymentSourceBindingTx(
	ctx context.Context, tx *sql.Tx, evidence *commerce.PaymentSourceEvidence, order *commerce.PaymentOrder,
) error {
	if evidence == nil {
		return nil
	}
	if order == nil || !evidence.Authorizes(order.TenantID, order.Provider) {
		return commerce.ErrPaymentSourceUnauthorized
	}
	var clientID, tenantID, sourceSystem string
	var enabled bool
	var revision uint64
	var dimensions int
	err := tx.QueryRowContext(ctx, `SELECT client_id, tenant_id, source_system, enabled,
revision, jsonb_array_length(allowed_dimensions) FROM usage_source_bindings
WHERE id=$1 FOR SHARE`, evidence.BindingID).Scan(
		&clientID, &tenantID, &sourceSystem, &enabled, &revision, &dimensions,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return commerce.ErrPaymentSourceUnauthorized
	}
	if err != nil {
		return fmt.Errorf("tenantcommerce/postgres: verify payment source binding: %w", err)
	}
	if !enabled || dimensions != 0 || clientID != evidence.ClientID || tenantID != evidence.TenantID ||
		sourceSystem != evidence.SourceSystem || revision != evidence.Revision {
		return commerce.ErrPaymentSourceUnauthorized
	}
	return nil
}
