// Package operations persists operator-triggered multi-step mutation state.
package operations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
	StepRunning    = "running"
	StepSucceeded  = "succeeded"
	StepFailed     = "failed"
)

var ErrNotFound = errors.New("operation not found")

type Step struct {
	Name       string    `json:"name"`
	State      string    `json:"state"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

type Operation struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	Target        string    `json:"target"`
	State         string    `json:"state"`
	CurrentStep   string    `json:"current_step,omitempty"`
	Steps         []Step    `json:"steps"`
	Compensations []Step    `json:"compensations"`
	ResultJSON    []byte    `json:"result_json,omitempty"`
	Error         string    `json:"error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Store interface {
	Create(ctx context.Context, operation Operation) error
	Update(ctx context.Context, operation Operation) error
	Get(ctx context.Context, id string) (Operation, error)
	List(ctx context.Context) ([]Operation, error)
}

// MemoryStore is the test/dev implementation. Production cmd wiring uses the
// restart-durable FileStore.
type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]Operation
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]Operation)}
}

func (s *MemoryStore) Create(_ context.Context, operation Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[operation.ID]; exists {
		return errors.New("operations: duplicate id")
	}
	s.items[operation.ID] = operation
	return nil
}

func (s *MemoryStore) Update(_ context.Context, operation Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[operation.ID]; !exists {
		return ErrNotFound
	}
	s.items[operation.ID] = operation
	return nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	operation, exists := s.items[id]
	if !exists {
		return Operation{}, ErrNotFound
	}
	return operation, nil
}

func (s *MemoryStore) List(_ context.Context) ([]Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Operation, 0, len(s.items))
	for _, operation := range s.items {
		out = append(out, operation)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// ListPage implements operations.PaginatedOperationStore: keyset pagination
// over a snapshot sorted by ID ascending — the extension path's new
// deterministic order, deliberately different from List()'s creation-time
// order (the fallback keeps today's store order; see the SPI doc).
// totalHint is the exact row count.
func (s *MemoryStore) ListPage(_ context.Context, q core.PageQuery) ([]Operation, []byte, int, error) {
	s.mu.RLock()
	all := make([]Operation, 0, len(s.items))
	for _, operation := range s.items {
		all = append(all, operation)
	}
	s.mu.RUnlock()
	keyID := func(o Operation) (string, string) { return o.ID, o.ID }
	core.SortKeyset(all, q.Desc, keyID)
	return core.KeysetSlice(all, q, keyID)
}

// Compile-time interface checks.
var (
	_ Store                   = (*MemoryStore)(nil)
	_ PaginatedOperationStore = (*MemoryStore)(nil)
)

func Start(ctx context.Context, store Store, kind, target string) (Operation, error) {
	now := time.Now().UTC()
	operation := Operation{
		ID: newID(), Kind: kind, Target: target, State: StateRunning,
		Steps: []Step{}, Compensations: []Step{}, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.Create(ctx, operation); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func BeginStep(ctx context.Context, store Store, operation *Operation, name string) error {
	now := time.Now().UTC()
	operation.CurrentStep = name
	operation.UpdatedAt = now
	operation.Steps = append(operation.Steps, Step{Name: name, State: StepRunning, StartedAt: now})
	return store.Update(ctx, *operation)
}

func FinishStep(ctx context.Context, store Store, operation *Operation, stepErr error) error {
	if len(operation.Steps) == 0 {
		return errors.New("operation has no current step")
	}
	now := time.Now().UTC()
	step := &operation.Steps[len(operation.Steps)-1]
	step.State, step.FinishedAt = StepSucceeded, now
	if stepErr != nil {
		step.State, step.Error = StepFailed, stepErr.Error()
	}
	operation.UpdatedAt = now
	return store.Update(ctx, *operation)
}

func Finish(
	ctx context.Context, store Store, operation *Operation, result []byte, operationErr error,
) error {
	operation.State = StateSucceeded
	operation.CurrentStep = ""
	operation.ResultJSON = append([]byte(nil), result...)
	operation.UpdatedAt = time.Now().UTC()
	if operationErr != nil {
		operation.State, operation.Error = StateFailed, operationErr.Error()
	}
	return store.Update(ctx, *operation)
}

func AddCompensation(
	ctx context.Context, store Store, operation *Operation, name, state, message string,
) error {
	now := time.Now().UTC()
	operation.Compensations = append(operation.Compensations, Step{
		Name: name, State: state, Error: message, StartedAt: now, FinishedAt: now,
	})
	operation.UpdatedAt = now
	return store.Update(ctx, *operation)
}

func newID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return "op_" + hex.EncodeToString(raw[:])
}
