package usageledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

var integrationNow = time.Date(2026, time.August, 4, 12, 0, 0, 123, time.UTC)

func TestSchemaDeclaresInvoiceLedgerBoundaries(t *testing.T) {
	required := []string{
		"UNIQUE (tenant_id, source_system, dimension, idempotency_key)",
		"reserved_quantity BIGINT NOT NULL DEFAULT 0",
		"CHECK (status IN ('pending', 'committed', 'released', 'expired'))",
		"UNIQUE (tenant_id, dimension, period_start_ns, period_end_ns)",
		"UNIQUE (tenant_id, idempotency_key)",
		"idx_usage_ledger_outbox_claim",
		"uq_usage_source_bindings_enabled_client",
		"release_idempotency_key TEXT NOT NULL DEFAULT ''",
		"uq_usage_ledger_reservations_release_key",
	}
	combinedSchema := schema + sourceBindingSchema + releaseIdempotencyMigration
	for _, fragment := range required {
		if !strings.Contains(combinedSchema, fragment) {
			t.Errorf("usage ledger migration missing %q", fragment)
		}
	}
	if MaxVersion() != 3 {
		t.Fatalf("MaxVersion() = %d, want 3", MaxVersion())
	}
}

func integrationStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set; skipping usage ledger integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dialect := postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT"))
	store, err := NewWithDB(db, dialect)
	if err != nil {
		t.Fatal(err)
	}
	truncateUsageLedger(t, db)
	return store
}

func truncateUsageLedger(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `TRUNCATE
usage_source_bindings,
usage_ledger_outbox, usage_ledger_rollups, usage_ledger_reservations,
usage_ledger_facts, usage_ledger_buckets CASCADE`)
	if err != nil {
		t.Fatalf("truncate usage ledger tables: %v", err)
	}
}

func testPeriod() ledger.Period {
	return ledger.MonthlyPeriod(integrationNow)
}

func testLimit(hard int64) commerce.LimitGrant {
	return commerce.LimitGrant{Soft: max(0, hard-2), Hard: hard}
}

func testFact(id, idempotency string, quantity int64) *ledger.UsageFact {
	return &ledger.UsageFact{
		ID: id, TenantID: "tenant-pg", SourceSystem: "aero-vault",
		Dimension: ledger.Dimension(commerce.LimitStorageBytes), Quantity: quantity,
		Period: testPeriod(), IdempotencyKey: idempotency, OccurredAt: integrationNow,
		CreatedAt: integrationNow, Metadata: map[string]string{"resource_type": "object"},
	}
}

func testReservation(
	id, idempotency string, quantity int64, period ledger.Period,
	createdAt, expiresAt time.Time, limit commerce.LimitGrant,
) *ledger.Reservation {
	return &ledger.Reservation{
		ID: id, TenantID: "tenant-pg", SourceSystem: "aero-vault",
		Dimension: ledger.Dimension(commerce.LimitStorageBytes), Quantity: quantity,
		Period: period, IdempotencyKey: idempotency, Status: ledger.ReservationPending,
		Limit: limit, ExpiresAt: expiresAt, Version: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}

func TestPostgresFactsAreIdempotentAndHardLimited(t *testing.T) {
	store := integrationStore(t)
	ctx := context.Background()
	limit := testLimit(10)
	original := testFact("usage-idempotent", "object-idempotent", 2)
	first, _, err := store.AppendFact(ctx, ledger.AppendCommand{Fact: original, Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	replay := testFact("usage-retry-id", "object-idempotent", 2)
	second, _, err := store.AppendFact(ctx, ledger.AppendCommand{Fact: replay, Limit: limit})
	if err != nil || second.ID != first.ID {
		t.Fatalf("fact replay = %+v, %v", second, err)
	}
	changed := testFact("usage-changed", "object-idempotent", 3)
	if _, _, err := store.AppendFact(ctx, ledger.AppendCommand{Fact: changed, Limit: limit}); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v", err)
	}
	collision := testFact(original.ID, "different-command", 2)
	if _, _, err := store.AppendFact(ctx, ledger.AppendCommand{Fact: collision, Limit: limit}); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("fact ID collision error = %v", err)
	}
	runConcurrentFacts(t, store, limit)
	facts, err := store.ListFacts(ctx, "tenant-pg", original.Dimension, testPeriod())
	if err != nil || len(facts) != 9 {
		t.Fatalf("stored fact count = %d, %v", len(facts), err)
	}
}

func runConcurrentFacts(t *testing.T, store *Store, limit commerce.LimitGrant) {
	t.Helper()
	results := make(chan error, 20)
	var wait sync.WaitGroup
	for index := range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			fact := testFact(fmt.Sprintf("usage-%02d", index), fmt.Sprintf("object-%02d", index), 1)
			_, _, err := store.AppendFact(context.Background(), ledger.AppendCommand{Fact: fact, Limit: limit})
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	accepted, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ledger.ErrQuotaExceeded):
			rejected++
		default:
			t.Fatalf("concurrent append error = %v", err)
		}
	}
	if accepted != 8 || rejected != 12 {
		t.Fatalf("concurrent accepted/rejected = %d/%d, want 8/12", accepted, rejected)
	}
}

func TestPostgresReservationCommitReleaseAndExpiry(t *testing.T) {
	store := integrationStore(t)
	ctx := context.Background()
	limit := testLimit(10)
	first := testReservation(
		"reserve-commit", "reserve-object-1", 3, testPeriod(),
		integrationNow, integrationNow.Add(time.Hour), limit,
	)
	_, counter, err := store.Reserve(ctx, ledger.ReserveCommand{Reservation: first, Limit: limit})
	if err != nil || counter.Reserved != 3 {
		t.Fatalf("reserve = %+v, %v", counter, err)
	}
	fact := testFact("usage-commit", "commit-object-1", 3)
	committed, counter, err := store.CommitReservation(ctx, pgReservationIdentity(first), fact)
	if err != nil || committed.Status != ledger.ReservationCommitted ||
		counter.Committed != 3 || counter.Reserved != 0 || counter.Projected != 3 {
		t.Fatalf("commit = %+v, %+v, %v", committed, counter, err)
	}
	binding := pgSourceBinding("release-source", "release-machine", true)
	if _, err := store.SaveSourceBinding(ctx, binding, 0); err != nil {
		t.Fatal(err)
	}
	second := testReservation(
		"reserve-release", "reserve-object-2", 2, testPeriod(),
		integrationNow, integrationNow.Add(time.Hour), limit,
	)
	evidence := binding.Evidence()
	if _, _, err := store.Reserve(ctx, ledger.ReserveCommand{Reservation: second, Limit: limit, Evidence: &evidence}); err != nil {
		t.Fatal(err)
	}
	// The HTTP path supplies a key; it is persisted and replayed without a
	// second state transition, while a different key is a request conflict.
	released, err := store.ReleaseReservationAuthorized(ctx, pgReservationIdentity(second),
		integrationNow.Add(time.Minute), evidence, "release-key")
	if err != nil || released.Status != ledger.ReservationReleased || released.ReleaseIdempotencyKey != "release-key" {
		t.Fatalf("release = %+v, %v", released, err)
	}
	replayed, err := store.ReleaseReservationAuthorized(ctx, pgReservationIdentity(second),
		integrationNow.Add(2*time.Minute), evidence, "release-key")
	if err != nil || replayed.ReleaseIdempotencyKey != "release-key" || replayed.Version != released.Version {
		t.Fatalf("release replay = %+v, %v", replayed, err)
	}
	if _, err := store.ReleaseReservationAuthorized(ctx, pgReservationIdentity(second),
		integrationNow.Add(3*time.Minute), evidence, "other-key"); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("release key conflict = %v", err)
	}
	cross := testReservation(
		"reserve-release-cross", "reserve-object-cross", 1, testPeriod(),
		integrationNow, integrationNow.Add(time.Hour), limit,
	)
	if _, _, err := store.Reserve(ctx, ledger.ReserveCommand{
		Reservation: cross, Limit: limit, Evidence: &evidence,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseReservationAuthorized(ctx, pgReservationIdentity(cross),
		integrationNow.Add(4*time.Minute), evidence, "release-key"); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("cross-reservation key conflict = %v", err)
	}
	if _, err := store.ReleaseReservationAuthorized(ctx, pgReservationIdentity(cross),
		integrationNow.Add(5*time.Minute), evidence, "cross-key"); err != nil {
		t.Fatalf("cross-reservation cleanup = %v", err)
	}
	expired := testReservation(
		"reserve-release-expired", "reserve-object-expired", 1, testPeriod(),
		integrationNow, integrationNow.Add(time.Minute), limit,
	)
	if _, _, err := store.Reserve(ctx, ledger.ReserveCommand{
		Reservation: expired, Limit: limit, Evidence: &evidence,
	}); err != nil {
		t.Fatal(err)
	}
	expiredRelease, err := store.ReleaseReservationAuthorized(ctx, pgReservationIdentity(expired),
		integrationNow.Add(2*time.Minute), evidence, "expired-key")
	if err != nil || expiredRelease.Status != ledger.ReservationExpired ||
		expiredRelease.ReleaseIdempotencyKey != "expired-key" {
		t.Fatalf("expired release = %+v, %v", expiredRelease, err)
	}
	expiredReplay, err := store.ReleaseReservationAuthorized(ctx, pgReservationIdentity(expired),
		integrationNow.Add(3*time.Minute), evidence, "expired-key")
	if err != nil || expiredReplay.Version != expiredRelease.Version {
		t.Fatalf("expired release replay = %+v, %v", expiredReplay, err)
	}
	if _, err := store.ReleaseReservationAuthorized(ctx, pgReservationIdentity(expired),
		integrationNow.Add(4*time.Minute), evidence, "other-expired-key"); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("expired release key conflict = %v", err)
	}
	assertReservationExpiry(t, store, limit)
}

func TestPostgresConcurrentReservationsDoNotOversell(t *testing.T) {
	store := integrationStore(t)
	limit := testLimit(10)
	results := make(chan error, 20)
	var wait sync.WaitGroup
	for index := range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			reservation := testReservation(
				fmt.Sprintf("reserve-%02d", index), fmt.Sprintf("reserve-key-%02d", index),
				1, testPeriod(), integrationNow, integrationNow.Add(time.Hour), limit,
			)
			_, _, err := store.Reserve(context.Background(), ledger.ReserveCommand{
				Reservation: reservation, Limit: limit,
			})
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	assertQuotaResults(t, results, 10, 10)
	assertReservedRows(t, store, 10)
}

func assertQuotaResults(t *testing.T, results <-chan error, wantAccepted, wantRejected int) {
	t.Helper()
	accepted, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ledger.ErrQuotaExceeded):
			rejected++
		default:
			t.Fatalf("concurrent quota operation error = %v", err)
		}
	}
	if accepted != wantAccepted || rejected != wantRejected {
		t.Fatalf("accepted/rejected = %d/%d, want %d/%d",
			accepted, rejected, wantAccepted, wantRejected)
	}
}

func assertReservedRows(t *testing.T, store *Store, want int64) {
	t.Helper()
	var reserved, rows int64
	err := store.db.QueryRowContext(context.Background(), `SELECT
b.reserved_quantity, COUNT(r.id) FROM usage_ledger_buckets b
JOIN usage_ledger_reservations r ON r.tenant_id=b.tenant_id AND r.dimension=b.dimension
AND r.period_start_ns=b.period_start_ns AND r.period_end_ns=b.period_end_ns
WHERE b.tenant_id=$1 GROUP BY b.reserved_quantity`, "tenant-pg").Scan(&reserved, &rows)
	if err != nil || reserved != want || rows != want {
		t.Fatalf("reserved quantity/rows = %d/%d, %v", reserved, rows, err)
	}
}

func assertReservationExpiry(t *testing.T, store *Store, limit commerce.LimitGrant) {
	t.Helper()
	expiring := testReservation(
		"reserve-expire", "reserve-object-3", 4, testPeriod(),
		integrationNow, integrationNow.Add(2*time.Minute), limit,
	)
	if _, _, err := store.Reserve(context.Background(), ledger.ReserveCommand{
		Reservation: expiring, Limit: limit,
	}); err != nil {
		t.Fatal(err)
	}
	count, err := store.SweepExpiredReservations(context.Background(), integrationNow.Add(3*time.Minute), 10)
	if err != nil || count != 1 {
		t.Fatalf("expiry sweep = %d, %v", count, err)
	}
	current, err := store.ReleaseReservation(
		context.Background(), pgReservationIdentity(expiring), integrationNow.Add(4*time.Minute),
	)
	if err != nil || current.Status != ledger.ReservationExpired {
		t.Fatalf("expired replay = %+v, %v", current, err)
	}
}

func TestPostgresClosePeriodAndOutboxAreAtomic(t *testing.T) {
	store := integrationStore(t)
	ctx := context.Background()
	period := ledger.Period{Start: integrationNow.Add(-time.Hour), End: integrationNow.Add(time.Hour)}
	limit := testLimit(10)
	fact := testFact("usage-close", "close-fact", 2)
	fact.Period, fact.OccurredAt = period, integrationNow
	if _, _, err := store.AppendFact(ctx, ledger.AppendCommand{Fact: fact, Limit: limit}); err != nil {
		t.Fatal(err)
	}
	reservation := testReservation(
		"reserve-cross-period", "cross-period", 1, period,
		integrationNow, period.End.Add(time.Hour), limit,
	)
	if _, _, err := store.Reserve(ctx, ledger.ReserveCommand{Reservation: reservation, Limit: limit}); err != nil {
		t.Fatal(err)
	}
	blocked := closeCommand(period, period.End)
	if _, err := store.ClosePeriod(ctx, blocked); !errors.Is(err, ledger.ErrActiveReservations) {
		t.Fatalf("close with active reservation error = %v", err)
	}
	if _, err := store.ReleaseReservation(ctx, pgReservationIdentity(reservation), period.End); err != nil {
		t.Fatal(err)
	}
	command := closeCommand(period, period.End.Add(time.Minute))
	rollup, err := store.ClosePeriod(ctx, command)
	if err != nil || rollup.Quantity != 2 || rollup.FactCount != 1 || rollup.Digest == "" {
		t.Fatalf("rollup = %+v, %v", rollup, err)
	}
	assertClosedAndOutbox(t, store, fact, command, rollup)
}

func pgReservationIdentity(reservation *ledger.Reservation) ledger.ReservationIdentity {
	return ledger.ReservationIdentity{
		ID: reservation.ID, TenantID: reservation.TenantID, SourceSystem: reservation.SourceSystem,
	}
}

func closeCommand(period ledger.Period, at time.Time) ledger.ClosePeriodCommand {
	return ledger.ClosePeriodCommand{
		RollupID: "rollup-pg", EventID: "event-rollup-pg", TenantID: "tenant-pg",
		Dimension: ledger.Dimension(commerce.LimitStorageBytes), Period: period, ClosedAt: at,
	}
}

func assertClosedAndOutbox(
	t *testing.T, store *Store, fact *ledger.UsageFact,
	command ledger.ClosePeriodCommand, rollup *ledger.Rollup,
) {
	t.Helper()
	replay, err := store.ClosePeriod(context.Background(), command)
	if err != nil || replay.ID != rollup.ID {
		t.Fatalf("close replay = %+v, %v", replay, err)
	}
	late := *fact
	late.ID, late.IdempotencyKey = "usage-late", "late-fact"
	if _, _, err := store.AppendFact(context.Background(), ledger.AppendCommand{
		Fact: &late, Limit: testLimit(10),
	}); !errors.Is(err, ledger.ErrPeriodClosed) {
		t.Fatalf("late fact error = %v", err)
	}
	events, err := store.ClaimOutbox(context.Background(), "relay-a", command.ClosedAt, time.Minute, 10)
	if err != nil || len(events) != 1 || events[0].AggregateID != rollup.ID {
		t.Fatalf("rollup outbox = %+v, %v", events, err)
	}
	if err := store.CompleteOutbox(context.Background(), events[0].ID, "relay-b", command.ClosedAt); !errors.Is(err, commerce.ErrOutboxLeaseLost) {
		t.Fatalf("wrong outbox lease owner error = %v", err)
	}
}

func TestPostgresOutboxRetryDeadLetterAndReplay(t *testing.T) {
	store := integrationStore(t)
	period := ledger.Period{Start: integrationNow.Add(-2 * time.Hour), End: integrationNow.Add(-time.Hour)}
	command := closeCommand(period, integrationNow)
	if _, err := store.ClosePeriod(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), "relay-a", integrationNow, time.Minute, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	if err := store.FailOutbox(context.Background(), claimed[0].ID, "relay-a", "unavailable",
		integrationNow, integrationNow.Add(time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	dead, err := store.ListDeadOutbox(context.Background(), 10)
	if err != nil || len(dead) != 1 || dead[0].Status != commerce.OutboxDead {
		t.Fatalf("dead outbox = %+v, %v", dead, err)
	}
	replayAt := integrationNow.Add(2 * time.Minute)
	if err := store.ReplayOutbox(context.Background(), dead[0].ID, replayAt); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.ClaimOutbox(context.Background(), "relay-b", replayAt, time.Minute, 1)
	if err != nil || len(replayed) != 1 || replayed[0].Attempts != 1 {
		t.Fatalf("replayed outbox = %+v, %v", replayed, err)
	}
}

func TestPostgresRollupOutboxConflictRollsBackPeriodClose(t *testing.T) {
	store := integrationStore(t)
	firstPeriod := ledger.Period{Start: integrationNow.Add(-4 * time.Hour), End: integrationNow.Add(-3 * time.Hour)}
	first := closeCommand(firstPeriod, integrationNow.Add(-2*time.Hour))
	if _, err := store.ClosePeriod(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	secondPeriod := ledger.Period{Start: integrationNow.Add(-2 * time.Hour), End: integrationNow.Add(-time.Hour)}
	second := closeCommand(secondPeriod, integrationNow)
	second.RollupID = "rollup-conflict"
	if _, err := store.ClosePeriod(context.Background(), second); !errors.Is(err, commerce.ErrIdempotencyConflict) {
		t.Fatalf("outbox conflict error = %v", err)
	}
	if _, err := store.GetRollup(context.Background(), second.TenantID, second.Dimension, second.Period); !errors.Is(err, ledger.ErrRollupNotFound) {
		t.Fatalf("failed close persisted rollup: %v", err)
	}
	fact := testFact("usage-after-rollback", "after-rollback", 1)
	fact.Period, fact.OccurredAt = secondPeriod, secondPeriod.Start.Add(time.Minute)
	if _, _, err := store.AppendFact(context.Background(), ledger.AppendCommand{
		Fact: fact, Limit: testLimit(10),
	}); err != nil {
		t.Fatalf("failed close left period closed: %v", err)
	}
}

func TestPostgresOutboxSkipLockedAcrossWorkers(t *testing.T) {
	store := integrationStore(t)
	for index := range 3 {
		period := ledger.Period{
			Start: integrationNow.Add(time.Duration(-8+index*2) * time.Hour),
			End:   integrationNow.Add(time.Duration(-7+index*2) * time.Hour),
		}
		command := closeCommand(period, integrationNow)
		command.RollupID, command.EventID = fmt.Sprintf("rollup-%d", index), fmt.Sprintf("event-%d", index)
		if _, err := store.ClosePeriod(context.Background(), command); err != nil {
			t.Fatal(err)
		}
	}
	results := make(chan []*commerce.OutboxEvent, 2)
	errorsChannel := make(chan error, 2)
	var wait sync.WaitGroup
	for _, owner := range []string{"relay-a", "relay-b"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			events, err := store.ClaimOutbox(context.Background(), owner, integrationNow, time.Minute, 2)
			results <- events
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsChannel)
	assertDistinctClaims(t, results, errorsChannel, 3)
}

func assertDistinctClaims(
	t *testing.T, results <-chan []*commerce.OutboxEvent, errorsChannel <-chan error, want int,
) {
	t.Helper()
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	claimed := make(map[string]struct{})
	for events := range results {
		for _, event := range events {
			if _, duplicate := claimed[event.ID]; duplicate {
				t.Fatalf("outbox event %q claimed twice", event.ID)
			}
			claimed[event.ID] = struct{}{}
		}
	}
	if len(claimed) != want {
		t.Fatalf("claimed %d outbox events, want %d", len(claimed), want)
	}
}
