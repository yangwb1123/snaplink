package grpcadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/operations"
	"github.com/yangwb1123/snaplink/platform/releases"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *SnapshotAdminService) snapshotIsSafety(ctx context.Context, id string) (bool, error) {
	raw, err := s.storage.Get(ctx, id)
	if err != nil {
		return false, mapSnapshotError(err, "get "+id)
	}
	envelope, err := snapshot.PeekEnvelope(raw)
	if err != nil {
		return false, status.Errorf(codes.Internal, "peek %s: %v", id, err)
	}
	return envelope.Kind == snapshot.KindSafetySnapshot, nil
}

func validateRollbackIntent(in *adminv1.RestoreSnapshotRequest, explicitSafety, sourceIsSafety bool) error {
	rollback := in.RollbackOnError != nil && in.RollbackOnError.Value
	if rollback && in.DryRun {
		return status.Error(codes.FailedPrecondition, "rollback_on_error cannot be combined with dry_run")
	}
	if rollback && !explicitSafety {
		return status.Error(codes.FailedPrecondition, "rollback_on_error requires auto_safety_snapshot=true")
	}
	if rollback && sourceIsSafety {
		return status.Error(codes.FailedPrecondition, "restoring a safety snapshot cannot roll back: it is itself the safety net")
	}
	return nil
}

func (s *SnapshotAdminService) startTrackedRestore(
	ctx context.Context, in *adminv1.RestoreSnapshotRequest,
) (operations.Operation, *snapshot.Snapshot, error) {
	operation, err := operations.Start(ctx, s.operations, "snapshot_restore", in.Id)
	if err != nil {
		return operation, nil, status.Errorf(codes.Internal, "start restore operation: %v", err)
	}
	if err := operations.BeginStep(ctx, s.operations, &operation, "load_snapshot"); err != nil {
		return operation, nil, status.Errorf(codes.Internal, "persist restore step: %v", err)
	}
	snap, err := s.pipeline.Load(ctx, s.storage, in.Id)
	if err != nil {
		return operation, nil, s.failRestoreOperation(ctx, &operation, err, "load "+in.Id, nil)
	}
	return operation, snap, nil
}

func (s *SnapshotAdminService) validateTrackedRestore(
	ctx context.Context, operation *operations.Operation, in *adminv1.RestoreSnapshotRequest,
	snap *snapshot.Snapshot, opts *snapshot.RestoreOptions,
) error {
	if err := s.restorer.ValidateRestore(snap, opts); err != nil {
		return s.failRestoreOperation(ctx, operation, err, "restore "+in.Id, nil)
	}
	if err := operations.FinishStep(ctx, s.operations, operation, nil); err != nil {
		return status.Errorf(codes.Internal, "persist restore step: %v", err)
	}
	return nil
}

func (s *SnapshotAdminService) captureTrackedSafety(
	ctx context.Context, operation *operations.Operation, enabled bool,
) (string, error) {
	if !enabled {
		return "", nil
	}
	if err := operations.BeginStep(ctx, s.operations, operation, "capture_safety_snapshot"); err != nil {
		return "", status.Errorf(codes.Internal, "persist restore step: %v", err)
	}
	safetySnap, err := snapshot.CaptureSafetySnapshot(ctx, s.snapshotter, s.pipeline, s.storage)
	if err != nil {
		return "", s.failRestoreOperation(ctx, operation, err, "capture safety snapshot", nil)
	}
	if err := operations.FinishStep(ctx, s.operations, operation, nil); err != nil {
		return "", status.Errorf(codes.Internal, "persist restore step: %v", err)
	}
	return safetySnap.SnapshotID, nil
}

func (s *SnapshotAdminService) applyTrackedRestore(
	ctx context.Context, operation *operations.Operation, in *adminv1.RestoreSnapshotRequest,
	snap *snapshot.Snapshot, opts snapshot.RestoreOptions, safetyID string, captureIntended bool,
) (*snapshot.Report, error) {
	if err := operations.BeginStep(ctx, s.operations, operation, "apply_resources"); err != nil {
		return nil, status.Errorf(codes.Internal, "persist restore step: %v", err)
	}
	report, err := s.restorer.Restore(ctx, snap, opts)
	if err != nil && !opts.RollbackOnError {
		// The ledger must never persist rotated secrets — client IDs
		// only (the RPC response is the sanctioned recovery channel).
		partial, _ := json.Marshal(snapshot.RedactCredentialRecovery(report))
		return nil, s.failRestoreOperation(ctx, operation, err, "restore "+in.Id, partial)
	}
	if err != nil {
		return nil, s.rollbackRestore(ctx, operation, in, opts.Mode, snap, report, safetyID, err, captureIntended)
	}
	if err := operations.FinishStep(ctx, s.operations, operation, nil); err != nil {
		return nil, status.Errorf(codes.Internal, "persist restore step: %v", err)
	}
	return report, nil
}

func (s *SnapshotAdminService) finishTrackedRestore(
	ctx context.Context, operation *operations.Operation, in *adminv1.RestoreSnapshotRequest,
	mode snapshot.RestoreMode, report *snapshot.Report, safetyID string, captureIntended bool,
) (*adminv1.RestoreSnapshotResponse, error) {
	target := fmt.Sprintf("%s mode=%s dry_run=%t", in.Id, mode, in.DryRun)
	recordAdminMeta(ctx, s.recorder, audit.EventSnapshotRestored, target,
		restoreAuditMeta(safetyID, captureIntended, report.Committed, false, ""))
	// The operations ledger persists client IDs and user IDs, never the
	// rotated plaintext secrets — the RPC response is the only sanctioned
	// recovery channel (RedactCredentialRecovery strips them).
	result, _ := json.Marshal(snapshot.RedactCredentialRecovery(report))
	if err := operations.Finish(ctx, s.operations, operation, result, nil); err != nil {
		return nil, status.Errorf(codes.Internal, "finish restore operation: %v", err)
	}
	return &adminv1.RestoreSnapshotResponse{
		Report: reportToProto(report), OperationId: operation.ID,
		Operation: operationToProto(*operation), SafetySnapshotId: safetyID,
	}, nil
}

func reportToProto(r *snapshot.Report) *adminv1.RestoreReport {
	if r == nil {
		return nil
	}
	out := &adminv1.RestoreReport{
		Mode: string(r.Mode), DryRun: r.DryRun,
		Items: make(map[string]*adminv1.CategoryCounts, len(r.Items)),
		Bootstrap: &adminv1.BootstrapAdvance{
			Attempted: r.Bootstrap.Attempted, From: int32(r.Bootstrap.From),
			To: int32(r.Bootstrap.To), NoOp: r.Bootstrap.NoOp, Reason: r.Bootstrap.Reason,
		},
		Errors: append([]string(nil), r.Errors...), Committed: r.Committed,
		RolledBack: r.RolledBack, SafetySnapshotId: r.SafetySnapshotID,
		MfaReenrollmentRequired: append([]string(nil), r.MFAReenrollmentRequired...),
	}
	// CredentialRecovery secrets are RPC-response-only: the wire is the
	// one sanctioned recovery channel, so the plaintext rides here and
	// nowhere persisted (see RedactCredentialRecovery).
	for _, c := range r.CredentialRecovery {
		out.CredentialRecovery = append(out.CredentialRecovery, &adminv1.CredentialRecovery{
			ClientId: c.ClientID, Secret: c.Secret,
		})
	}
	for category, counts := range r.Items {
		out.Items[string(category)] = &adminv1.CategoryCounts{
			Inserted: int32(counts.Inserted), Updated: int32(counts.Updated),
			Deleted: int32(counts.Deleted), Skipped: int32(counts.Skipped),
			RequiresRotation: int32(counts.RequiresRotation),
		}
	}
	return out
}

// ReleaseAdminService exposes the releases.Registry over gRPC.
// Mutating RPCs (Register / Pin / Rollback / Delete) write one audit
// event each. Pinner is held inside the Registry — operators wire
// the right backend at cmd time; this service is unaware.
type ReleaseAdminService struct {
	adminv1.UnimplementedReleaseAdminServiceServer
	registry   *releases.Registry
	store      releases.ReleaseStore
	recorder   *audit.Recorder
	operations operations.Store
}

// NewReleaseAdminService takes the Registry (for Pin/Rollback/Current)
// plus the underlying Store (for Register/List/Get/Delete which don't
// need the Pinner). Both must point at the same backing store.
func NewReleaseAdminService(reg *releases.Registry, store releases.ReleaseStore, recorder *audit.Recorder, operationStores ...operations.Store) *ReleaseAdminService {
	var operationStore operations.Store
	if len(operationStores) > 0 {
		operationStore = operationStores[0]
	} else {
		operationStore = operations.NewMemoryStore()
	}
	return &ReleaseAdminService{
		registry: reg, store: store, recorder: recorder, operations: operationStore,
	}
}

func (s *ReleaseAdminService) ready() error {
	if s.store == nil {
		return status.Error(codes.FailedPrecondition, "release store not configured")
	}
	return nil
}

func (s *ReleaseAdminService) Register(ctx context.Context, in *adminv1.RegisterReleaseRequest) (*adminv1.RegisterReleaseResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if in == nil || in.Release == nil || in.Release.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "release.id required")
	}
	r := protoToRelease(in.Release)
	if r.ReleasedAt.IsZero() {
		r.ReleasedAt = time.Now().UTC()
	}
	if err := s.store.Register(ctx, r); err != nil {
		return nil, mapReleaseError(err, "register "+r.ID)
	}
	recordAdmin(ctx, s.recorder, audit.EventReleaseRegistered, r.ID)
	return &adminv1.RegisterReleaseResponse{Release: releaseToProto(r)}, nil
}

// List dispatches through runListPage (admin_paginate.go): keyset pushdown
// when the store implements releases.PaginatedReleaseStore, else the legacy
// List(ctx) -> fixed id-ascending sort -> offset slice. This proto has no
// order_by/filter fields, so the only thing to wire beyond pagination is the
// fixed deterministic sort — imposed here rather than assumed from the
// backing store (ReleaseStore.List's contract only says implementations
// SHOULD return a stable order, not MUST).
func (s *ReleaseAdminService) List(ctx context.Context, in *adminv1.ListReleasesRequest) (*adminv1.ListReleasesResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	var ext pageLister[*releases.Release]
	if p, ok := s.store.(releases.PaginatedReleaseStore); ok {
		ext = p
	}
	items, next, total, err := runListPage(ctx,
		in.GetPageToken(), in.GetPageSize(), "", "",
		ext,
		func(ctx context.Context) ([]*releases.Release, error) { return s.store.List(ctx) },
		func(items []*releases.Release, _ string) ([]*releases.Release, error) {
			sort.Slice(items, func(i, j int) bool { return releases.CompareReleases(items[i], items[j]) < 0 })
			return items, nil
		},
		nil, "list: %v", nil,
	)
	if err != nil {
		return nil, err
	}
	out := &adminv1.ListReleasesResponse{
		Items:         make([]*adminv1.Release, 0, len(items)),
		TotalSize:     total,
		NextPageToken: next,
	}
	for _, r := range items {
		out.Items = append(out.Items, releaseToProto(r))
	}
	return out, nil
}

func (s *ReleaseAdminService) Get(ctx context.Context, in *adminv1.GetReleaseRequest) (*adminv1.GetReleaseResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	r, err := s.store.Get(ctx, in.Id)
	if err != nil {
		return nil, mapReleaseError(err, "get "+in.Id)
	}
	return &adminv1.GetReleaseResponse{Release: releaseToProto(r)}, nil
}

func (s *ReleaseAdminService) GetCurrent(ctx context.Context, _ *adminv1.GetCurrentReleaseRequest) (*adminv1.GetCurrentReleaseResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	r, err := s.store.Current(ctx)
	if errors.Is(err, releases.ErrNoCurrent) {
		// Empty release is the documented "nothing pinned" answer —
		// not an error, since fresh deployments hit this normally.
		return &adminv1.GetCurrentReleaseResponse{}, nil
	}
	if err != nil {
		return nil, mapReleaseError(err, "current")
	}
	return &adminv1.GetCurrentReleaseResponse{Release: releaseToProto(r)}, nil
}

func (s *ReleaseAdminService) Pin(ctx context.Context, in *adminv1.PinReleaseRequest) (*adminv1.PinReleaseResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if s.registry == nil {
		return nil, status.Error(codes.FailedPrecondition, "release registry not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	rep, operation, err := s.applyReleaseTracked(ctx, in.Id, "release_pin", s.registry.Pin)
	if err != nil {
		return nil, err
	}
	target := fmt.Sprintf("%s previous=%s", rep.ReleaseID, rep.PreviousID)
	recordAdmin(ctx, s.recorder, audit.EventReleasePinned, target)
	return &adminv1.PinReleaseResponse{
		Report: pinReportToProto(rep), OperationId: operation.ID,
		Operation: operationToProto(operation),
	}, nil
}

func (s *ReleaseAdminService) Rollback(ctx context.Context, in *adminv1.RollbackReleaseRequest) (*adminv1.RollbackReleaseResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if s.registry == nil {
		return nil, status.Error(codes.FailedPrecondition, "release registry not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	rep, operation, err := s.applyReleaseTracked(ctx, in.Id, "release_rollback", s.registry.Rollback)
	if err != nil {
		return nil, err
	}
	target := fmt.Sprintf("%s previous=%s", rep.ReleaseID, rep.PreviousID)
	recordAdmin(ctx, s.recorder, audit.EventReleaseRolledBack, target)
	return &adminv1.RollbackReleaseResponse{
		Report: pinReportToProto(rep), OperationId: operation.ID,
		Operation: operationToProto(operation),
	}, nil
}

func (s *ReleaseAdminService) applyReleaseTracked(
	ctx context.Context, id, kind string,
	apply func(context.Context, string) (*releases.PinReport, error),
) (*releases.PinReport, operations.Operation, error) {
	if s.operations == nil {
		return nil, operations.Operation{}, status.Error(
			codes.FailedPrecondition, "durable operation store not configured")
	}
	operation, err := operations.Start(ctx, s.operations, kind, id)
	if err != nil {
		return nil, operation, status.Errorf(codes.Internal, "start release operation: %v", err)
	}
	if err := operations.BeginStep(ctx, s.operations, &operation, "apply_release"); err != nil {
		return nil, operation, status.Errorf(codes.Internal, "persist release step: %v", err)
	}
	report, applyErr := apply(ctx, id)
	_ = operations.FinishStep(ctx, s.operations, &operation, applyErr)
	if applyErr != nil {
		return nil, operation, s.failReleaseOperation(ctx, &operation, applyErr, kind+" "+id)
	}
	result, _ := json.Marshal(report)
	if err := operations.Finish(ctx, s.operations, &operation, result, nil); err != nil {
		return nil, operation, status.Errorf(codes.Internal, "finish release operation: %v", err)
	}
	return report, operation, nil
}

func (s *ReleaseAdminService) failReleaseOperation(
	ctx context.Context, operation *operations.Operation, cause error, prefix string,
) error {
	var rollback *releases.AutoRollbackError
	if errors.As(cause, &rollback) {
		compensationState, compensationError := operations.StepSucceeded, ""
		if rollback.CompensationError != nil {
			compensationState, compensationError = operations.StepFailed, rollback.CompensationError.Error()
		}
		_ = operations.AddCompensation(
			ctx, s.operations, operation, "automatic_rollback",
			compensationState, compensationError)
	}
	mapped := mapReleaseError(cause, prefix)
	_ = operations.Finish(ctx, s.operations, operation, nil, mapped)
	return operationFailureError(*operation, mapped)
}

func (s *ReleaseAdminService) Delete(ctx context.Context, in *adminv1.DeleteReleaseRequest) (*adminv1.DeleteReleaseResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	if err := s.store.Delete(ctx, in.Id); err != nil {
		return nil, mapReleaseError(err, "delete "+in.Id)
	}
	recordAdmin(ctx, s.recorder, audit.EventReleaseDeleted, in.Id)
	return &adminv1.DeleteReleaseResponse{}, nil
}

// ---- mappers ----

func releaseToProto(r *releases.Release) *adminv1.Release {
	if r == nil {
		return nil
	}
	return &adminv1.Release{
		Id:             r.ID,
		Channel:        r.Channel,
		Frontend:       artifactToProto(r.Frontend),
		Backend:        artifactToProto(r.Backend),
		SchemaVersion:  int32(r.SchemaVersion),
		ConfigSnapshot: r.ConfigSnapshot,
		ReleasedAtUnix: r.ReleasedAt.Unix(),
		ReleasedBy:     r.ReleasedBy,
		Notes:          r.Notes,
	}
}

func protoToRelease(in *adminv1.Release) *releases.Release {
	if in == nil {
		return nil
	}
	r := &releases.Release{
		ID:             in.Id,
		Channel:        in.Channel,
		Frontend:       protoToArtifact(in.Frontend),
		Backend:        protoToArtifact(in.Backend),
		SchemaVersion:  int(in.SchemaVersion),
		ConfigSnapshot: in.ConfigSnapshot,
		ReleasedBy:     in.ReleasedBy,
		Notes:          in.Notes,
	}
	if in.ReleasedAtUnix > 0 {
		r.ReleasedAt = time.Unix(in.ReleasedAtUnix, 0).UTC()
	}
	return r
}

func artifactToProto(a releases.Artifact) *adminv1.Artifact {
	return &adminv1.Artifact{
		GitRef: a.GitRef,
		Uri:    a.URI,
		Sha256: a.SHA256,
		Digest: a.Digest,
	}
}

func protoToArtifact(in *adminv1.Artifact) releases.Artifact {
	if in == nil {
		return releases.Artifact{}
	}
	return releases.Artifact{
		GitRef: in.GitRef,
		URI:    in.Uri,
		SHA256: in.Sha256,
		Digest: in.Digest,
	}
}

func pinReportToProto(r *releases.PinReport) *adminv1.PinReport {
	if r == nil {
		return nil
	}
	return &adminv1.PinReport{
		ReleaseId:  r.ReleaseID,
		Mode:       r.Mode.String(),
		PreviousId: r.PreviousID,
	}
}

// mapReleaseError turns release SDK sentinels into gRPC status codes.
func mapReleaseError(err error, prefix string) error {
	switch {
	case errors.Is(err, releases.ErrReleaseNotFound):
		return status.Errorf(codes.NotFound, "%s: not found", prefix)
	case errors.Is(err, releases.ErrReleaseExists):
		return status.Errorf(codes.AlreadyExists, "%s: %v", prefix, err)
	case errors.Is(err, releases.ErrInvalidPair):
		return status.Errorf(codes.InvalidArgument, "%s: %v", prefix, err)
	case errors.Is(err, releases.ErrSchemaRegress):
		return status.Errorf(codes.FailedPrecondition, "%s: %v", prefix, err)
	case errors.Is(err, releases.ErrNoCurrent):
		return status.Errorf(codes.NotFound, "%s: no current release", prefix)
	default:
		return status.Errorf(codes.Internal, "%s: %v", prefix, err)
	}
}
