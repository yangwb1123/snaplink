package main

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"sync"
	"time"
)

type relayWorker struct {
	store       relayStore
	billing     billingGateway
	bindings    map[string]*tenantBinding
	owner       string
	poll        time.Duration
	lease       time.Duration
	batch       int
	concurrency int
	logger      *log.Logger
	metrics     *adapterMetrics
	slots       chan struct{}
	work        sync.WaitGroup
}

type relayStore interface {
	ClaimInbox(context.Context, string, time.Duration, int) ([]inboxClaim, error)
	ResolveClaim(context.Context, inboxClaim) (trustedDelivery, error)
	AckInbox(context.Context, trustedDelivery) error
	NackInbox(context.Context, inboxClaim, time.Duration, string) error
	QuarantineInbox(context.Context, inboxClaim, string) error
}

func newRelayWorker(
	config runtimeConfig, store relayStore, billing billingGateway, owner string, logger *log.Logger,
	metrics *adapterMetrics,
) *relayWorker {
	if metrics == nil {
		metrics = &adapterMetrics{}
	}
	return &relayWorker{
		store: store, billing: billing, bindings: config.TenantBindings, owner: owner,
		poll: config.PollInterval, lease: config.ClaimLease, batch: config.BatchSize,
		concurrency: config.DeliveryConcurrency, logger: logger, metrics: metrics,
		slots: make(chan struct{}, config.DeliveryConcurrency),
	}
}

func (w *relayWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	w.claim(ctx)
	for {
		select {
		case <-ctx.Done():
			w.work.Wait()
			return
		case <-ticker.C:
			w.claim(ctx)
		}
	}
}

func (w *relayWorker) claim(ctx context.Context) {
	limit := w.batch
	available := w.concurrency - len(w.slots)
	if available == 0 {
		return
	}
	if limit > available {
		limit = available
	}
	claims, err := w.store.ClaimInbox(ctx, w.owner, w.lease, limit)
	if err != nil {
		if ctx.Err() == nil {
			w.logger.Printf("relay claim failed category=database")
		}
		return
	}
	for _, claim := range claims {
		w.slots <- struct{}{}
		w.work.Add(1)
		go w.process(claim)
	}
}

func (w *relayWorker) process(claim inboxClaim) {
	defer w.work.Done()
	defer func() { <-w.slots }()
	ctx, cancel := context.WithTimeout(context.Background(), w.lease-time.Second)
	defer cancel()
	delivery, err := w.store.ResolveClaim(ctx, claim)
	if err == nil {
		err = w.deliver(ctx, delivery)
	}
	if err != nil {
		if errors.Is(err, errClaimLost) {
			return
		}
		if permanentDeliveryError(err) {
			w.quarantine(ctx, claim, deliveryCategory(err))
			return
		}
		w.repark(ctx, claim, deliveryCategory(err))
		return
	}
	if err := w.store.AckInbox(ctx, delivery); err != nil && !errors.Is(err, errClaimLost) {
		w.logger.Printf("relay acknowledgement failed event_id=%s category=database", claim.EventID)
		return
	}
	w.metrics.relayDelivered.Add(1)
}

func (w *relayWorker) deliver(ctx context.Context, delivery trustedDelivery) error {
	binding := w.bindings[delivery.TenantID]
	if binding == nil {
		return &deliveryError{category: "binding", permanent: true, err: errMappingNotFound}
	}
	order, err := w.billing.GetOrder(ctx, binding, delivery.OrderID)
	if err != nil {
		return err
	}
	if err := validateDeliveryOrder(order, delivery); err != nil {
		return &deliveryError{
			category: "order_state", permanent: !errors.Is(err, errDeliveryNotReady), err: err,
		}
	}
	return w.billing.Deliver(ctx, binding, delivery)
}

func (w *relayWorker) quarantine(ctx context.Context, claim inboxClaim, category string) {
	if err := w.store.QuarantineInbox(ctx, claim, category); err != nil && !errors.Is(err, errClaimLost) {
		w.logger.Printf("relay quarantine failed event_id=%s category=database", claim.EventID)
		return
	}
	w.logger.Printf("relay quarantined event_id=%s category=%s", claim.EventID, category)
	w.metrics.relayQuarantined.Add(1)
}

func (w *relayWorker) repark(ctx context.Context, claim inboxClaim, category string) {
	delay := deliveryBackoff(claim.AttemptCount, claim.Digest)
	if err := w.store.NackInbox(ctx, claim, delay, category); err != nil && !errors.Is(err, errClaimLost) {
		w.logger.Printf("relay repark failed event_id=%s category=database", claim.EventID)
		return
	}
	w.logger.Printf("relay deferred event_id=%s category=%s", claim.EventID, category)
	w.metrics.relayRetried.Add(1)
}

func validateDeliveryOrder(order paymentOrder, delivery trustedDelivery) error {
	if !validOrderIdentity(order, delivery.TenantID, delivery.OrderID) || order.Currency != delivery.Currency ||
		(order.ProviderOrderID != "" && order.ProviderOrderID != delivery.ProviderOrderID) {
		return errCheckoutConflict
	}
	switch delivery.Type {
	case eventCaptured:
		return validateCaptureOrder(order, delivery)
	case eventRefunded, eventChargeback:
		return validateRefundOrder(order, delivery)
	case eventChargebackRev:
		return validateChargebackReversal(order, delivery)
	default:
		return errInvalidProviderFact
	}
}

func validateCaptureOrder(order paymentOrder, delivery trustedDelivery) error {
	if delivery.AmountMinor != order.AmountMinor {
		return errCheckoutConflict
	}
	if order.Status != "pending" && order.Status != "succeeded" {
		return errDeliveryNotReady
	}
	return nil
}

func validateRefundOrder(order paymentOrder, delivery trustedDelivery) error {
	validStatus := order.Status == "succeeded" || order.Status == "partially_refunded" || order.Status == "refunded"
	if delivery.AmountMinor <= 0 || delivery.AmountMinor > order.AmountMinor {
		return errCheckoutConflict
	}
	if !validStatus {
		return errDeliveryNotReady
	}
	return nil
}

func validateChargebackReversal(order paymentOrder, delivery trustedDelivery) error {
	if delivery.AmountMinor <= 0 || delivery.AmountMinor > order.AmountMinor {
		return errCheckoutConflict
	}
	if order.Status == "succeeded" || order.Status == "pending" {
		return errDeliveryNotReady
	}
	if delivery.AmountMinor > order.RefundedMinor {
		return errDeliveryNotReady
	}
	return nil
}

func deliveryCategory(err error) string {
	var classified *deliveryError
	if errors.As(err, &classified) && validErrorCategory(classified.category) {
		return classified.category
	}
	if errors.Is(err, errMappingNotFound) {
		return "mapping"
	}
	if errors.Is(err, errCheckoutConflict) {
		return "mapping_conflict"
	}
	return "database"
}

func permanentDeliveryError(err error) bool {
	var classified *deliveryError
	if errors.As(err, &classified) {
		return classified.permanent
	}
	return errors.Is(err, errCheckoutConflict) || errors.Is(err, errInvalidProviderFact)
}

func validErrorCategory(value string) bool {
	return value != "" && len(value) <= 64
}

func deliveryBackoff(attempt int64, digest []byte) time.Duration {
	exponent := attempt
	if exponent > 8 {
		exponent = 8
	}
	delay := time.Second * time.Duration(1<<uint(exponent))
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	var seed uint64
	if len(digest) >= 8 {
		seed = binary.BigEndian.Uint64(digest[:8])
	}
	jitterWindow := delay / 4
	if jitterWindow > 0 {
		delay += time.Duration(seed % uint64(jitterWindow))
	}
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}
