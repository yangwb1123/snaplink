package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

const maxCatalogBytes = 2 << 20

type catalogPublisher interface {
	PublishPlan(context.Context, *tenantcommerce.Plan) error
}

func publishCatalog(ctx context.Context, path string, publisher catalogPublisher) error {
	if path == "" {
		return nil
	}
	plans, err := loadCatalog(path)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		if err := publisher.PublishPlan(ctx, plan); err != nil {
			return fmt.Errorf("publish catalog plan %s:%d: %w", plan.ID, plan.Version, err)
		}
	}
	return nil
}

func loadCatalog(path string) ([]*tenantcommerce.Plan, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open catalog: %w", err)
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxCatalogBytes+1))
	if err != nil || len(body) > maxCatalogBytes {
		return nil, errors.New("catalog exceeds size limit or cannot be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var plans []*tenantcommerce.Plan
	if err := decoder.Decode(&plans); err != nil || plans == nil {
		return nil, errors.New("catalog must be a strict JSON array")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("catalog contains trailing JSON")
	}
	for _, plan := range plans {
		if plan == nil || plan.CreatedAt.IsZero() {
			return nil, errors.New("catalog plans require a stable created_at")
		}
	}
	return plans, nil
}

func applySourceBindings(ctx context.Context, path string, store ledger.SourceBindingStore) error {
	if path == "" {
		return nil
	}
	bindings, err := loadSourceBindings(path)
	if err != nil {
		return err
	}
	// Apply disables before enables so an explicit handover is independent of
	// JSON order and never creates a transient second enabled client binding.
	slices.SortStableFunc(bindings, func(left, right *ledger.SourceBinding) int {
		if left.Enabled == right.Enabled {
			return 0
		}
		if left.Enabled {
			return 1
		}
		return -1
	})
	for _, binding := range bindings {
		if err := applySourceBinding(ctx, store, binding); err != nil {
			return fmt.Errorf("apply source binding %s: %w", binding.ID, err)
		}
	}
	return validateBoundClients(ctx, store, bindings)
}

func loadSourceBindings(path string) ([]*ledger.SourceBinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open source bindings: %w", err)
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxCatalogBytes+1))
	if err != nil || len(body) > maxCatalogBytes {
		return nil, errors.New("source bindings exceed size limit or cannot be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var bindings []*ledger.SourceBinding
	if err := decoder.Decode(&bindings); err != nil || bindings == nil {
		return nil, errors.New("source bindings must be a strict JSON array")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("source bindings contain trailing JSON")
	}
	return validateSourceBindingFile(bindings)
}

func validateSourceBindingFile(bindings []*ledger.SourceBinding) ([]*ledger.SourceBinding, error) {
	ids := make(map[string]struct{}, len(bindings))
	enabledClients := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if binding == nil || binding.Validate() != nil {
			return nil, errors.New("source bindings contain an invalid binding")
		}
		if _, duplicate := ids[binding.ID]; duplicate {
			return nil, errors.New("source bindings contain a duplicate id")
		}
		ids[binding.ID] = struct{}{}
		if !binding.Enabled {
			continue
		}
		if _, duplicate := enabledClients[binding.ClientID]; duplicate {
			return nil, errors.New("source bindings enable one client more than once")
		}
		enabledClients[binding.ClientID] = struct{}{}
	}
	return bindings, nil
}

func applySourceBinding(
	ctx context.Context, store ledger.SourceBindingStore, desired *ledger.SourceBinding,
) error {
	current, err := findSourceBinding(ctx, store, desired.ClientID, desired.ID)
	if err != nil {
		return err
	}
	if sameSourceBinding(current, desired) {
		return nil
	}
	expected, err := expectedSourceRevision(current, desired)
	if err != nil {
		return err
	}
	stored, err := store.SaveSourceBinding(ctx, desired, expected)
	if err == nil && sameSourceBinding(stored, desired) {
		return nil
	}
	if err == nil {
		return ledger.ErrSourceBindingConflict
	}
	if !errors.Is(err, ledger.ErrSourceBindingConflict) {
		return err
	}
	concurrent, readErr := findSourceBinding(ctx, store, desired.ClientID, desired.ID)
	if readErr != nil {
		return readErr
	}
	if sameSourceBinding(concurrent, desired) {
		return nil
	}
	return ledger.ErrSourceBindingConflict
}

func findSourceBinding(
	ctx context.Context, store ledger.SourceBindingStore, clientID, id string,
) (*ledger.SourceBinding, error) {
	bindings, err := store.ListSourceBindingsByClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if binding != nil && binding.ID == id {
			return binding, nil
		}
	}
	return nil, nil
}

func expectedSourceRevision(current, desired *ledger.SourceBinding) (uint64, error) {
	if current == nil {
		if desired.Revision == 1 {
			return 0, nil
		}
		return 0, ledger.ErrSourceBindingConflict
	}
	if current.Validate() != nil || !sameSourceIdentity(current, desired) ||
		desired.Revision != current.Revision+1 ||
		!desired.UpdatedAt.After(current.UpdatedAt) {
		return 0, ledger.ErrSourceBindingConflict
	}
	return current.Revision, nil
}

func sameSourceIdentity(left, right *ledger.SourceBinding) bool {
	return left != nil && right != nil && left.ID == right.ID && left.ClientID == right.ClientID &&
		left.TenantID == right.TenantID && left.SourceSystem == right.SourceSystem &&
		left.CreatedAt.Equal(right.CreatedAt)
}

func sameSourceBinding(left, right *ledger.SourceBinding) bool {
	return sameSourceIdentity(left, right) && left.Enabled == right.Enabled &&
		left.Revision == right.Revision && left.UpdatedAt.Equal(right.UpdatedAt) &&
		slices.Equal(left.AllowedDimensions, right.AllowedDimensions)
}

func validateBoundClients(
	ctx context.Context, store ledger.SourceBindingStore, desired []*ledger.SourceBinding,
) error {
	checked := make(map[string]struct{}, len(desired))
	for _, binding := range desired {
		if _, ok := checked[binding.ClientID]; ok {
			continue
		}
		checked[binding.ClientID] = struct{}{}
		bindings, err := store.ListSourceBindingsByClient(ctx, binding.ClientID)
		if err != nil {
			return err
		}
		enabled := 0
		for _, candidate := range bindings {
			if candidate != nil && candidate.Enabled {
				enabled++
			}
		}
		if enabled > 1 {
			return ledger.ErrSourceBindingUnauthorized
		}
	}
	return nil
}
