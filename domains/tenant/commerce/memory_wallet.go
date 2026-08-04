package commerce

import (
	"context"
	"errors"
	"math"
	"sort"
)

func (s *MemoryStore) PostLedgerEntry(
	ctx context.Context, mutation WalletMutation,
) (*LedgerEntry, *Wallet, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := validateWalletMutation(mutation); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, wallet, ok, err := s.walletReplayLocked(mutation.Entry); ok || err != nil {
		return entry, wallet, err
	}
	key := walletKey{tenantID: mutation.Entry.TenantID, currency: mutation.Entry.Currency}
	current := s.wallets[key]
	if current == nil {
		current = &Wallet{TenantID: key.tenantID, Currency: key.currency, Status: WalletActive}
	}
	if current.Status == WalletFrozen && mutation.Entry.AmountMinor < 0 {
		return nil, nil, ErrWalletFrozen
	}
	balance, err := nextBalance(current.BalanceMinor, mutation.Entry.AmountMinor)
	if err != nil {
		return nil, nil, err
	}
	entry, wallet := nextWalletState(mutation.Entry, current, balance)
	events := cloneOutboxEvents(mutation.Events)
	for _, event := range events {
		event.AggregateVersion = wallet.Version
	}
	events, err = s.prepareOutboxLocked(events)
	if err != nil {
		return nil, nil, err
	}
	s.wallets[key] = wallet
	s.entries[key] = append(s.entries[key], entry)
	s.ledgerKeys[ledgerIdempotencyKey(entry)] = entry
	s.ledgerByID[entry.ID] = entry
	s.commitOutboxLocked(events)
	return cloneLedgerEntry(entry), cloneWallet(wallet), nil
}

func validateWalletMutation(mutation WalletMutation) error {
	if err := mutation.Entry.Validate(); err != nil {
		return err
	}
	if len(mutation.Events) == 0 {
		return errorsNew("wallet outbox event required")
	}
	for _, event := range mutation.Events {
		if err := event.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *MemoryStore) walletReplayLocked(entry *LedgerEntry) (*LedgerEntry, *Wallet, bool, error) {
	current, ok := s.ledgerKeys[ledgerIdempotencyKey(entry)]
	if !ok {
		return nil, nil, false, nil
	}
	key := walletKey{tenantID: entry.TenantID, currency: entry.Currency}
	if !sameLedgerCommand(current, entry) {
		return nil, nil, true, ErrIdempotencyConflict
	}
	return cloneLedgerEntry(current), cloneWallet(s.wallets[key]), true, nil
}

func sameLedgerCommand(left, right *LedgerEntry) bool {
	return left.TenantID == right.TenantID && left.Currency == right.Currency &&
		left.Kind == right.Kind && left.AmountMinor == right.AmountMinor && left.Reference == right.Reference
}

func nextWalletState(entry *LedgerEntry, current *Wallet, balance int64) (*LedgerEntry, *Wallet) {
	nextWallet := cloneWallet(current)
	nextWallet.BalanceMinor = balance
	nextWallet.Version++
	nextWallet.UpdatedAt = entry.CreatedAt
	nextEntry := cloneLedgerEntry(entry)
	nextEntry.BalanceAfter = balance
	nextEntry.WalletVersion = nextWallet.Version
	return nextEntry, nextWallet
}

func nextBalance(balance, amount int64) (int64, error) {
	next, err := nextSignedBalance(balance, amount)
	if err != nil {
		return 0, err
	}
	if next < 0 {
		return 0, ErrInsufficientFunds
	}
	return next, nil
}

func ledgerIdempotencyKey(entry *LedgerEntry) string {
	return commerceKey(entry.TenantID, entry.Currency, entry.IdempotencyKey)
}

func (s *MemoryStore) GetWallet(ctx context.Context, tenantID, currency string) (*Wallet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	wallet := s.wallets[walletKey{tenantID: tenantID, currency: currency}]
	if wallet == nil {
		return &Wallet{TenantID: tenantID, Currency: currency, Status: WalletActive}, nil
	}
	return cloneWallet(wallet), nil
}

func (s *MemoryStore) ListLedgerEntries(
	ctx context.Context, tenantID, currency string, limit int,
) ([]*LedgerEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := s.entries[walletKey{tenantID: tenantID, currency: currency}]
	if limit <= 0 || limit > len(entries) {
		limit = len(entries)
	}
	result := make([]*LedgerEntry, 0, limit)
	for index := len(entries) - 1; index >= len(entries)-limit; index-- {
		result = append(result, cloneLedgerEntry(entries[index]))
	}
	return result, nil
}

func cloneOutboxEvents(events []*OutboxEvent) []*OutboxEvent {
	result := make([]*OutboxEvent, 0, len(events))
	for _, event := range events {
		result = append(result, cloneOutboxEvent(event))
	}
	return result
}

func errorsNew(message string) error { return errors.New("commerce: " + message) }

func (s *MemoryStore) CreatePaymentOrder(
	ctx context.Context, order *PaymentOrder, events []*OutboxEvent,
) (*PaymentOrder, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validatePaymentOrderWrite(order, events); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := paymentOrderIdempotencyKey(order)
	if id, ok := s.paymentOrderKeys[key]; ok {
		current := s.paymentOrders[id]
		if samePaymentOrderCommand(current, order) {
			return clonePaymentOrder(current), nil
		}
		return nil, ErrIdempotencyConflict
	}
	if _, exists := s.paymentOrders[order.ID]; exists {
		return nil, ErrIdempotencyConflict
	}
	prepared, err := s.prepareOutboxLocked(events)
	if err != nil {
		return nil, err
	}
	s.paymentOrders[order.ID] = clonePaymentOrder(order)
	s.paymentOrderKeys[key] = order.ID
	s.commitOutboxLocked(prepared)
	return clonePaymentOrder(order), nil
}

func validatePaymentOrderWrite(order *PaymentOrder, events []*OutboxEvent) error {
	if err := order.Validate(); err != nil {
		return err
	}
	if len(events) == 0 {
		return errorsNew("payment order outbox event required")
	}
	for _, event := range events {
		if err := event.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func paymentOrderIdempotencyKey(order *PaymentOrder) string {
	return commerceKey(order.TenantID, order.Provider, order.IdempotencyKey)
}

func samePaymentOrderCommand(left, right *PaymentOrder) bool {
	return left != nil && left.TenantID == right.TenantID && left.Provider == right.Provider &&
		left.ProviderOrderID == right.ProviderOrderID && left.Currency == right.Currency &&
		left.AmountMinor == right.AmountMinor
}

func (s *MemoryStore) GetPaymentOrder(ctx context.Context, id string) (*PaymentOrder, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	order, ok := s.paymentOrders[id]
	if !ok {
		return nil, ErrPaymentNotFound
	}
	return clonePaymentOrder(order), nil
}

func (s *MemoryStore) ListPaymentOrdersByTenant(
	ctx context.Context, tenantID string,
) ([]*PaymentOrder, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*PaymentOrder, 0)
	for _, order := range s.paymentOrders {
		if order.TenantID == tenantID {
			result = append(result, clonePaymentOrder(order))
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].CreatedAt.Equal(result[right].CreatedAt) {
			return result[left].ID < result[right].ID
		}
		return result[left].CreatedAt.Before(result[right].CreatedAt)
	})
	return result, nil
}

func (s *MemoryStore) ApplyPaymentEvent(
	ctx context.Context, mutation PaymentMutation,
) (*PaymentOrder, *LedgerEntry, *Wallet, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	if err := validatePaymentMutation(mutation); err != nil {
		return nil, nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if order, entry, wallet, ok, err := s.paymentReplayLocked(mutation.PaymentEvent); ok || err != nil {
		return order, entry, wallet, err
	}
	current, ok := s.paymentOrders[mutation.Order.ID]
	if !ok {
		return nil, nil, nil, ErrPaymentNotFound
	}
	if current.Revision != mutation.ExpectedRevision || mutation.Order.Revision != current.Revision+1 {
		return nil, nil, nil, ErrRevisionConflict
	}
	if !samePaymentOrderIdentity(current, mutation.Order) {
		return nil, nil, nil, ErrPaymentStateConflict
	}
	entry, wallet, err := s.preparePaymentWalletLocked(mutation)
	if err != nil {
		return nil, nil, nil, err
	}
	events := cloneOutboxEvents(mutation.Events)
	for _, event := range events {
		if event.AggregateType == "wallet" && wallet != nil {
			event.AggregateVersion = wallet.Version
		}
	}
	events, err = s.prepareOutboxLocked(events)
	if err != nil {
		return nil, nil, nil, err
	}
	s.commitPaymentLocked(mutation, entry, wallet, events)
	return clonePaymentOrder(mutation.Order), cloneLedgerEntry(entry), cloneWallet(wallet), nil
}

func validatePaymentMutation(mutation PaymentMutation) error {
	if err := mutation.Order.Validate(); err != nil {
		return err
	}
	if err := mutation.PaymentEvent.Validate(); err != nil {
		return err
	}
	if mutation.PaymentEvent.OrderID != mutation.Order.ID || len(mutation.Events) == 0 {
		return ErrInvalidPayment
	}
	if mutation.PaymentEvent.AppliedAt.IsZero() {
		return ErrInvalidPayment
	}
	if mutation.Source != nil && !mutation.Source.Authorizes(mutation.Order.TenantID, mutation.Order.Provider) {
		return ErrPaymentSourceUnauthorized
	}
	return validatePaymentLedger(mutation.PaymentEvent, mutation.LedgerEntry)
}

func validatePaymentLedger(event *PaymentEvent, entry *LedgerEntry) error {
	if event.Type == PaymentRejected {
		if entry != nil {
			return ErrInvalidPayment
		}
		return nil
	}
	if err := entry.Validate(); err != nil {
		return err
	}
	if event.Type == PaymentCaptured && (entry.Kind != LedgerTopUp || entry.AmountMinor != event.AmountMinor) {
		return ErrInvalidPayment
	}
	if event.Type == PaymentChargebackReversed &&
		(entry.Kind != LedgerChargebackReversal || entry.AmountMinor != event.AmountMinor) {
		return ErrInvalidPayment
	}
	if event.Type != PaymentCaptured && (entry.Kind != LedgerRefund || entry.AmountMinor != -event.AmountMinor) {
		if event.Type == PaymentChargebackReversed {
			return nil
		}
		return ErrInvalidPayment
	}
	return nil
}

func samePaymentOrderIdentity(current, next *PaymentOrder) bool {
	providerOrderMatches := current.ProviderOrderID == "" || current.ProviderOrderID == next.ProviderOrderID
	return current.ID == next.ID && current.TenantID == next.TenantID && current.Provider == next.Provider &&
		providerOrderMatches && current.Currency == next.Currency && current.AmountMinor == next.AmountMinor &&
		current.IdempotencyKey == next.IdempotencyKey && current.CreatedAt.Equal(next.CreatedAt)
}

func (s *MemoryStore) paymentReplayLocked(
	event *PaymentEvent,
) (*PaymentOrder, *LedgerEntry, *Wallet, bool, error) {
	current, ok := s.paymentEvents[paymentEventKey(event.Provider, event.ID)]
	if !ok {
		return nil, nil, nil, false, nil
	}
	if !samePaymentFact(current, event) {
		return nil, nil, nil, true, ErrIdempotencyConflict
	}
	order := s.paymentOrders[current.OrderID]
	entry := s.ledgerByID[current.LedgerEntryID]
	wallet := s.wallets[walletKey{tenantID: order.TenantID, currency: order.Currency}]
	return clonePaymentOrder(order), cloneLedgerEntry(entry), cloneWallet(wallet), true, nil
}

func (s *MemoryStore) preparePaymentWalletLocked(
	mutation PaymentMutation,
) (*LedgerEntry, *Wallet, error) {
	if mutation.LedgerEntry == nil {
		return nil, nil, nil
	}
	entry := cloneLedgerEntry(mutation.LedgerEntry)
	key := walletKey{tenantID: entry.TenantID, currency: entry.Currency}
	current := s.wallets[key]
	if current == nil {
		current = &Wallet{TenantID: key.tenantID, Currency: key.currency, Status: WalletActive}
	}
	balance, err := nextSignedBalance(current.BalanceMinor, entry.AmountMinor)
	if err != nil {
		return nil, nil, err
	}
	entry, wallet := nextWalletState(entry, current, balance)
	if mutation.PaymentEvent.Type == PaymentChargeback || wallet.BalanceMinor < 0 {
		wallet.Status = WalletFrozen
	} else if mutation.PaymentEvent.Type == PaymentChargebackReversed {
		wallet.Status = WalletActive
	}
	return entry, wallet, nil
}

func (s *MemoryStore) commitPaymentLocked(
	mutation PaymentMutation, entry *LedgerEntry, wallet *Wallet, events []*OutboxEvent,
) {
	order := clonePaymentOrder(mutation.Order)
	event := clonePaymentEvent(mutation.PaymentEvent)
	s.paymentOrders[order.ID] = order
	if entry != nil {
		key := walletKey{tenantID: entry.TenantID, currency: entry.Currency}
		event.LedgerEntryID = entry.ID
		s.wallets[key] = wallet
		s.entries[key] = append(s.entries[key], entry)
		s.ledgerKeys[ledgerIdempotencyKey(entry)] = entry
		s.ledgerByID[entry.ID] = entry
	}
	eventKey := paymentEventKey(event.Provider, event.ID)
	s.paymentEvents[eventKey] = event
	s.orderPaymentEvents[order.ID] = append(s.orderPaymentEvents[order.ID], eventKey)
	s.commitOutboxLocked(events)
}

func paymentEventKey(provider, eventID string) string {
	return commerceKey(provider, eventID)
}

func (s *MemoryStore) GetPaymentEvent(
	ctx context.Context, provider, eventID string,
) (*PaymentEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	event, ok := s.paymentEvents[paymentEventKey(provider, eventID)]
	if !ok {
		return nil, ErrPaymentEventNotFound
	}
	return clonePaymentEvent(event), nil
}

func (s *MemoryStore) ListPaymentEvents(
	ctx context.Context, orderID string,
) ([]*PaymentEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*PaymentEvent, 0, len(s.orderPaymentEvents[orderID]))
	for _, key := range s.orderPaymentEvents[orderID] {
		result = append(result, clonePaymentEvent(s.paymentEvents[key]))
	}
	return result, nil
}

func (s *MemoryStore) ReconcilePayments(
	ctx context.Context, tenantID string,
) (*ReconciliationReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	report := &ReconciliationReport{TenantID: tenantID, Issues: []ReconciliationIssue{}}
	for _, order := range s.paymentOrders {
		if order.TenantID != tenantID {
			continue
		}
		report.OrdersChecked++
		ledgerMinor := s.paymentLedgerTotalLocked(order)
		expected := order.PaidMinor - order.RefundedMinor
		if ledgerMinor != expected {
			report.Issues = append(report.Issues, ReconciliationIssue{
				OrderID: order.ID, ExpectedMinor: expected, LedgerMinor: ledgerMinor,
			})
		}
	}
	return report, nil
}

func (s *MemoryStore) paymentLedgerTotalLocked(order *PaymentOrder) int64 {
	var total int64
	key := walletKey{tenantID: order.TenantID, currency: order.Currency}
	for _, entry := range s.entries[key] {
		if entry.Reference == order.ID {
			total += entry.AmountMinor
		}
	}
	return total
}

func nextSignedBalance(balance, amount int64) (int64, error) {
	if amount > 0 && balance > math.MaxInt64-amount {
		return 0, ErrWalletOverflow
	}
	if amount < 0 && balance < math.MinInt64-amount {
		return 0, ErrWalletOverflow
	}
	return balance + amount, nil
}
