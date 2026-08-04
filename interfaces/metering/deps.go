package meteringhttp

import (
	"context"
	"errors"
	"reflect"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

var (
	ErrUsageServiceRequired = errors.New("metering http: usage service required")
	ErrEntitlementsRequired = errors.New("metering http: entitlement reader required")
	ErrSourceResolverNeeded = errors.New("metering http: source resolver required")
	ErrRouterRequired       = errors.New("metering http: router required")
)

type UsageService interface {
	AppendAuthorized(context.Context, usageledger.SourceBindingEvidence, usageledger.UsageCommand) (
		*usageledger.UsageFact, *usageledger.Counter, error,
	)
	ReserveAuthorized(context.Context, usageledger.SourceBindingEvidence, usageledger.ReservationCommand) (
		*usageledger.Reservation, *usageledger.Counter, error,
	)
	CommitAuthorized(
		context.Context, usageledger.SourceBindingEvidence, string, usageledger.AuthorizedCommitCommand,
	) (
		*usageledger.Reservation, *usageledger.Counter, error,
	)
	ReleaseAuthorized(context.Context, usageledger.SourceBindingEvidence, string) (
		*usageledger.Reservation, error,
	)
}

type SourceResolver interface {
	Resolve(context.Context, string) (*usageledger.SourceBinding, error)
}

type MutationOutcome string

const (
	MutationSucceeded MutationOutcome = "success"
	MutationFailed    MutationOutcome = "failure"
)

type MutationRecord struct {
	Operation    string
	TenantID     string
	SourceSystem string
	Dimension    usageledger.Dimension
	ResourceID   string
	Outcome      MutationOutcome
	ErrorCode    string
}

type MutationObserver interface {
	ObserveMeteringMutation(context.Context, MutationRecord)
}

type Deps struct {
	Usage        UsageService
	Entitlements commerce.EntitlementReader
	Sources      SourceResolver
	Observer     MutationObserver
}

func (d Deps) validate() error {
	if nilDependency(d.Usage) {
		return ErrUsageServiceRequired
	}
	if nilDependency(d.Entitlements) {
		return ErrEntitlementsRequired
	}
	if nilDependency(d.Sources) {
		return ErrSourceResolverNeeded
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
