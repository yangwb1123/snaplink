package tenantcommerce

import (
	"context"
	"fmt"
	"reflect"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

const planColumns = `id, version, name, status, billing_interval, currency,
price_minor, grace_period_days, features, limits, created_at_ns`

func (s *Store) PutPlan(ctx context.Context, plan *commerce.Plan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	features, err := encodeJSON(plan.Features)
	if err != nil {
		return err
	}
	limits, err := encodeJSON(plan.Limits)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO tenant_commerce_plans (
id, version, name, status, billing_interval, currency, price_minor,
grace_period_days, features, limits, created_at_ns
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CAST($9 AS JSONB),CAST($10 AS JSONB),$11)
ON CONFLICT (id, version) DO NOTHING`,
		plan.ID, plan.Version, plan.Name, plan.Status, plan.Interval, plan.Price.Currency,
		plan.Price.MinorUnits, plan.GracePeriodDays, features, limits, timeNano(plan.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("tenantcommerce/postgres: put plan: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 1 {
		return err
	}
	current, err := s.GetPlan(ctx, plan.ID, plan.Version)
	if err != nil {
		return err
	}
	if !samePlan(current, plan) {
		return commerce.ErrPlanConflict
	}
	return nil
}

func (s *Store) GetPlan(ctx context.Context, id string, version uint64) (*commerce.Plan, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+planColumns+`
FROM tenant_commerce_plans WHERE id = $1 AND version = $2`, id, version)
	plan, err := scanPlan(row)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: get plan: %w", notFound(err, commerce.ErrPlanNotFound))
	}
	return plan, nil
}

func (s *Store) ListPlans(ctx context.Context) ([]*commerce.Plan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+planColumns+`
FROM tenant_commerce_plans ORDER BY id, version`)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: list plans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	plans := make([]*commerce.Plan, 0)
	for rows.Next() {
		plan, scanErr := scanPlan(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("tenantcommerce/postgres: scan plan: %w", scanErr)
		}
		plans = append(plans, plan)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: list plans: %w", err)
	}
	return plans, nil
}

func samePlan(left, right *commerce.Plan) bool {
	return left.ID == right.ID && left.Version == right.Version && left.Name == right.Name &&
		left.Status == right.Status && left.Interval == right.Interval && left.Price == right.Price &&
		left.GracePeriodDays == right.GracePeriodDays && reflect.DeepEqual(left.Features, right.Features) &&
		reflect.DeepEqual(left.Limits, right.Limits) && left.CreatedAt.Equal(right.CreatedAt)
}
