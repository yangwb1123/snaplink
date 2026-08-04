package commercehttp

import (
	"context"
	"errors"
	"reflect"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

var (
	ErrCommandServiceRequired   = errors.New("commerce http: command service required")
	ErrQueryServiceRequired     = errors.New("commerce http: query service required")
	ErrRouterRequired           = errors.New("commerce http: router required")
	ErrPaymentOrderGateRequired = errors.New("commerce http: payment order scope gate required")
	ErrPaymentEventGateRequired = errors.New("commerce http: payment event scope gate required")
	ErrPaymentSourceRequired    = errors.New("commerce http: payment source resolver required")
)

// CommandService is the mutation surface implemented by commerce.Service.
// Keeping the transport on this narrow interface also permits a typed remote
// command client in a separately deployed billing service.
type CommandService interface {
	PublishPlan(context.Context, *tenantcommerce.Plan) error
	CreateSubscription(context.Context, tenantcommerce.CreateSubscriptionCommand) (
		*tenantcommerce.Subscription, *tenantcommerce.EntitlementSnapshot, error,
	)
	ChangePlan(context.Context, tenantcommerce.ChangePlanCommand) (
		*tenantcommerce.Subscription, *tenantcommerce.EntitlementSnapshot, error,
	)
	TransitionSubscription(context.Context, tenantcommerce.TransitionSubscriptionCommand) (
		*tenantcommerce.Subscription, *tenantcommerce.EntitlementSnapshot, error,
	)
	RenewSubscription(context.Context, tenantcommerce.RenewSubscriptionCommand) (
		*tenantcommerce.Subscription, *tenantcommerce.EntitlementSnapshot, error,
	)
	PostLedgerEntry(context.Context, tenantcommerce.PostLedgerCommand) (
		*tenantcommerce.LedgerEntry, *tenantcommerce.Wallet, error,
	)
	CreateTopUpOrder(context.Context, tenantcommerce.CreateTopUpCommand) (*tenantcommerce.PaymentOrder, error)
	ApplyPaymentEvent(context.Context, *tenantcommerce.PaymentEvent) (
		*tenantcommerce.PaymentOrder, *tenantcommerce.LedgerEntry, *tenantcommerce.Wallet, error,
	)
	ApplyAuthorizedPaymentEvent(context.Context, tenantcommerce.PaymentSourceEvidence, *tenantcommerce.PaymentEvent) (
		*tenantcommerce.PaymentOrder, *tenantcommerce.LedgerEntry, *tenantcommerce.Wallet, error,
	)
}

type PaymentSourceResolver interface {
	Resolve(context.Context, string) (*usageledger.SourceBinding, error)
}

// QueryService is the read model required by the management handlers. The
// commerce Store implementations satisfy it directly.
type QueryService interface {
	GetPlan(context.Context, string, uint64) (*tenantcommerce.Plan, error)
	ListPlans(context.Context) ([]*tenantcommerce.Plan, error)
	ListSubscriptionsByTenant(context.Context, string) ([]*tenantcommerce.Subscription, error)
	CurrentEntitlement(context.Context, string) (*tenantcommerce.EntitlementSnapshot, error)
	GetWallet(context.Context, string, string) (*tenantcommerce.Wallet, error)
	ListLedgerEntries(context.Context, string, string, int) ([]*tenantcommerce.LedgerEntry, error)
	GetPaymentOrder(context.Context, string) (*tenantcommerce.PaymentOrder, error)
	ListPaymentOrdersByTenant(context.Context, string) ([]*tenantcommerce.PaymentOrder, error)
	ListPaymentEvents(context.Context, string) ([]*tenantcommerce.PaymentEvent, error)
	ReconcilePayments(context.Context, string) (*tenantcommerce.ReconciliationReport, error)
}

type MutationOutcome string

const (
	MutationSucceeded MutationOutcome = "success"
	MutationFailed    MutationOutcome = "failure"
)

// MutationRecord is a bounded, credential-free audit projection. It is an
// observation hook only: the commerce ledger and transactional outbox remain
// the financial and integration sources of truth.
type MutationRecord struct {
	Operation    string
	TenantID     string
	ResourceType string
	ResourceID   string
	Outcome      MutationOutcome
	ErrorCode    string
}

type MutationObserver interface {
	ObserveCommerceMutation(context.Context, MutationRecord)
}

type MutationObserverFunc func(context.Context, MutationRecord)

func (f MutationObserverFunc) ObserveCommerceMutation(ctx context.Context, record MutationRecord) {
	f(ctx, record)
}

// Deps deliberately accepts the command and query sides separately. Embedded
// deployments normally wire commerce.Service + commerce.Store; an external
// service can supply clients without changing handler behavior.
type Deps struct {
	Commands       CommandService
	Queries        QueryService
	PaymentSources PaymentSourceResolver
	Observer       MutationObserver
}

func (d Deps) validate() error {
	if nilDependency(d.Commands) {
		return ErrCommandServiceRequired
	}
	if nilDependency(d.Queries) {
		return ErrQueryServiceRequired
	}
	return nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
