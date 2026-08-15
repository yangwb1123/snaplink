package grpcadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/operations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SnapshotAdminService exposes the snapshot Snapshotter / Restorer / Storage
// trio over gRPC. Mutating RPCs (Export / Restore / Delete) write one audit
// event each. The Pipeline + Storage pair is mandatory; Snapshotter and
// Restorer are optional — endpoints whose dependency is missing return
// FailedPrecondition.
type SnapshotAdminService struct {
	adminv1.UnimplementedSnapshotAdminServiceServer
	pipeline    *snapshot.Pipeline
	storage     snapshot.Storage
	snapshotter *snapshot.Snapshotter
	restorer    *snapshot.Restorer
	recorder    *audit.Recorder
	operations  operations.Store
}

func NewSnapshotAdminService(p *snapshot.Pipeline, st snapshot.Storage, sn *snapshot.Snapshotter, r *snapshot.Restorer, recorder *audit.Recorder, operationStores ...operations.Store) *SnapshotAdminService {
	var operationStore operations.Store
	if len(operationStores) > 0 {
		operationStore = operationStores[0]
	} else {
		operationStore = operations.NewMemoryStore()
	}
	return &SnapshotAdminService{
		pipeline: p, storage: st, snapshotter: sn, restorer: r,
		recorder: recorder, operations: operationStore,
	}
}

func (s *SnapshotAdminService) ready() error {
	if s.pipeline == nil || s.storage == nil {
		return status.Error(codes.FailedPrecondition, "snapshot subsystem not configured")
	}
	return nil
}

func (s *SnapshotAdminService) Export(ctx context.Context, in *adminv1.ExportSnapshotRequest) (*adminv1.ExportSnapshotResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if s.snapshotter == nil {
		return nil, status.Error(codes.FailedPrecondition, "snapshotter not configured")
	}
	var opts snapshot.ExportOptions
	if in != nil {
		opts.SourceNodeID = in.SourceNodeId
		opts.IncludeCredentialSeeds = in.IncludeCredentialSeeds
		for _, x := range in.Exclude {
			opts.Exclude = append(opts.Exclude, snapshot.ResourceCategory(x))
		}
	}
	snap, err := s.snapshotter.Export(ctx, opts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "export: %v", err)
	}
	if err := s.pipeline.Save(ctx, snap, s.storage, snap.SnapshotID); err != nil {
		return nil, mapSnapshotError(err, "save "+snap.SnapshotID)
	}
	recordAdmin(ctx, s.recorder, audit.EventSnapshotExported, snap.SnapshotID)
	raw, err := s.storage.Get(ctx, snap.SnapshotID)
	if err != nil {
		return nil, mapSnapshotError(err, "size lookup "+snap.SnapshotID)
	}
	return &adminv1.ExportSnapshotResponse{
		Meta:     snapshotMetaFromSnapshot(snap, raw),
		StoredAs: snap.SnapshotID,
	}, nil
}

// List dispatches through runListPage (admin_paginate.go): keyset pushdown
// when the storage implements snapshot.PaginatedSnapshotStorage, else the
// legacy List(ctx) name scan -> fixed name-ascending sort -> offset slice.
// This proto has no order_by/filter fields, so the only thing to wire beyond
// pagination is the fixed deterministic sort — Storage.List documents
// "arbitrary order". The (potentially expensive) per-item Get+PeekEnvelope
// only runs for the PAGE window, not every name, mirroring how
// ListClients/ListUsers only proto-convert the sliced window.
func (s *SnapshotAdminService) List(ctx context.Context, in *adminv1.ListSnapshotsRequest) (*adminv1.ListSnapshotsResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	var ext pageLister[string]
	if p, ok := s.storage.(snapshot.PaginatedSnapshotStorage); ok {
		ext = p
	}
	items, next, total, err := runListPage(ctx,
		in.GetPageToken(), in.GetPageSize(), "", "",
		ext,
		func(ctx context.Context) ([]string, error) { return s.storage.List(ctx) },
		func(items []string, _ string) ([]string, error) {
			sort.Strings(items)
			return items, nil
		},
		nil, "list: %v", nil,
	)
	if err != nil {
		return nil, err
	}
	metas, err := s.snapshotMetas(ctx, items)
	if err != nil {
		return nil, err
	}
	return &adminv1.ListSnapshotsResponse{
		Items:         metas,
		TotalSize:     total,
		NextPageToken: next,
	}, nil
}

func (s *SnapshotAdminService) Get(ctx context.Context, in *adminv1.GetSnapshotRequest) (*adminv1.GetSnapshotResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	raw, err := s.storage.Get(ctx, in.Id)
	if err != nil {
		return nil, mapSnapshotError(err, "get "+in.Id)
	}
	snap, err := s.pipeline.Load(ctx, s.storage, in.Id)
	if err != nil {
		return nil, mapSnapshotError(err, "load "+in.Id)
	}
	// Ordinary admin reads are an inspection surface, never a credential
	// recovery channel. Redact the decoded in-memory copy unconditionally;
	// the sealed stored artifact remains unchanged and therefore restorable.
	snapshot.SnapshotRedactSecrets().Redact(snap)
	resBytes, err := json.Marshal(snap.Resources)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal resources: %v", err)
	}
	return &adminv1.GetSnapshotResponse{
		Meta:          snapshotMetaFromSnapshot(snap, raw),
		ResourcesJson: resBytes,
	}, nil
}

// Restore applies a snapshot to the wired stores.
//
// CACHE LIMITATION: the Restorer writes the RAW underlying stores, so a restore
// on a LIVE replica with warm per-replica caches (client store cache, authz
// policy bundle cache, discovery cache) does NOT evict them or publish the
// cross-replica change events, so this replica AND its peers can serve stale
// pre-restore metadata until each cache's TTL. Restore is intended for
// fresh/maintenance nodes; an operator restoring into a live fleet should cycle
// the affected replicas (or accept TTL-bounded staleness) rather than rely on
// live restore for an incident-response client/role change — use the admin
// client/permission RPCs (which DO invalidate + publish) for that.
func (s *SnapshotAdminService) Restore(ctx context.Context, in *adminv1.RestoreSnapshotRequest) (*adminv1.RestoreSnapshotResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if s.restorer == nil {
		return nil, status.Error(codes.FailedPrecondition, "restorer not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	mode := snapshot.RestoreMode(in.Mode)
	if mode == "" {
		mode = snapshot.ModeMerge
	}
	switch mode {
	case snapshot.ModeMerge, snapshot.ModeOverwrite, snapshot.ModeReplace:
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown mode %q", in.Mode)
	}
	if s.operations == nil {
		return nil, status.Error(codes.FailedPrecondition, "durable operation store not configured")
	}
	return s.restoreTracked(ctx, in, mode)
}

// resolveRestoreSafety validates the D1/D3 tri-state intents BEFORE any
// write (including the operations ledger) and resolves them:
//
//   - auto_safety_snapshot: nil = server default (capture iff mode=replace,
//     non-dry-run, and the source is not itself a safety artifact);
//     false = explicit opt-out; true = capture regardless of mode.
//   - rollback_on_error: nil = false. Requires an explicit
//     auto_safety_snapshot=true (the server default is deliberately NOT
//     enough — rollback is the dangerous path and demands an explicit net),
//     a non-safety source, and a non-dry-run. The failure messages name the
//     requirement so the tri-state asymmetry between the two BoolValue
//     fields is self-explanatory.
//
// The source kind is read from the envelope HEADER (Get + PeekEnvelope), so
// the recursion guard and rollback eligibility resolve without a full Load
// and without creating an operation record. Returns
// (captureIntended, effectiveCapture, rollbackOnError).
func (s *SnapshotAdminService) resolveRestoreSafety(
	ctx context.Context, in *adminv1.RestoreSnapshotRequest, mode snapshot.RestoreMode,
) (bool, bool, bool, error) {
	sourceIsSafety, err := s.snapshotIsSafety(ctx, in.Id)
	if err != nil {
		return false, false, false, err
	}
	rollbackOnError := in.RollbackOnError != nil && in.RollbackOnError.Value
	explicitAutoSafety := in.AutoSafetySnapshot != nil && in.AutoSafetySnapshot.Value
	if err := validateRollbackIntent(in, explicitAutoSafety, sourceIsSafety); err != nil {
		return false, false, false, err
	}
	captureIntended := explicitAutoSafety ||
		(in.AutoSafetySnapshot == nil && mode == snapshot.ModeReplace && !in.DryRun && !sourceIsSafety)
	if captureIntended && s.snapshotter == nil {
		return false, false, false, status.Error(codes.FailedPrecondition, "safety snapshot capture requires a configured snapshotter; pass auto_safety_snapshot=false to opt out")
	}
	return captureIntended, captureIntended && !sourceIsSafety, rollbackOnError, nil
}

// restoreTracked runs one restore as a tracked operation. Steps:
// load_snapshot → [capture_safety_snapshot] → apply_resources →
// [rollback_safety_snapshot on failure with rollback armed]. A replace
// non-dry-run restore captures a D1 safety snapshot before any target-store
// write unless the caller opted out; a failure with rollback armed re-applies
// the net and reports the rollback (see rollbackRestore).
func (s *SnapshotAdminService) restoreTracked(
	ctx context.Context, in *adminv1.RestoreSnapshotRequest, mode snapshot.RestoreMode,
) (*adminv1.RestoreSnapshotResponse, error) {
	captureIntended, effectiveCapture, rollbackOnError, err := s.resolveRestoreSafety(ctx, in, mode)
	if err != nil {
		return nil, err
	}
	operation, snap, err := s.startTrackedRestore(ctx, in)
	if err != nil {
		return nil, err
	}
	opts := snapshot.RestoreOptions{
		Mode:                   mode,
		DryRun:                 in.DryRun,
		AdvanceBootstrap:       in.AdvanceBootstrap,
		Confirm:                in.Confirm,
		AutoSafetySnapshot:     captureIntended,
		RollbackOnError:        rollbackOnError,
		Exclude:                restoreExclude(in),
		RestoreCredentialSeeds: in.RestoreCredentialSeeds,
	}
	if err := s.validateTrackedRestore(ctx, &operation, in, snap, &opts); err != nil {
		return nil, err
	}
	safetyID, err := s.captureTrackedSafety(ctx, &operation, effectiveCapture)
	if err != nil {
		return nil, err
	}
	rep, err := s.applyTrackedRestore(ctx, &operation, in, snap, opts, safetyID, captureIntended)
	if err != nil {
		return nil, err
	}
	return s.finishTrackedRestore(ctx, &operation, in, mode, rep, safetyID, captureIntended)
}

// rollbackRestore runs the D3 rollback after a failed restore: it re-applies
// the D1 safety snapshot in replace mode, records the compensation step,
// fires the control-plane invalidator a second time (the re-apply's own
// success path fired once), and terminates the operation as FAILED. The RPC
// still fails — fail-closed: the caller must know the restore did not take
// effect — but the destination state is safe and the outcome rides the error
// (message + status details + operation record + audit meta).
func (s *SnapshotAdminService) rollbackRestore(
	ctx context.Context,
	operation *operations.Operation,
	in *adminv1.RestoreSnapshotRequest,
	mode snapshot.RestoreMode,
	src *snapshot.Snapshot,
	rep *snapshot.Report,
	safetyID string,
	cause error,
	captureIntended bool,
) error {
	_ = operations.FinishStep(ctx, s.operations, operation, cause) // apply_resources failed
	if err := operations.BeginStep(ctx, s.operations, operation, "rollback_safety_snapshot"); err != nil {
		return status.Errorf(codes.Internal, "persist restore step: %v", err)
	}
	safetySnap, err := s.pipeline.Load(ctx, s.storage, safetyID)
	if err != nil {
		return s.terminateRollback(ctx, operation, in, mode, rep, safetyID, captureIntended,
			fmt.Errorf("rollback failed; target state unknown: %v", err), false)
	}
	// Rollback re-applies the net in replace mode, never captures again
	// (recursion guard), and skips exactly the categories the failed restore
	// could not have touched: the caller's excludes plus categories the
	// source snapshot didn't cover — an excluded netpolicy, for instance, is
	// never rewound by the rollback.
	_, err = s.restorer.Restore(ctx, safetySnap, snapshot.RestoreOptions{
		Mode:               snapshot.ModeReplace,
		Confirm:            safetySnap.SnapshotID,
		AutoSafetySnapshot: false,
		RollbackOnError:    false,
		Exclude:            snapshot.RollbackExcludeFor(src, restoreExclude(in)),
	})
	if err != nil {
		return s.terminateRollback(ctx, operation, in, mode, rep, safetyID, captureIntended,
			fmt.Errorf("rollback failed; target state unknown: %v", err), false)
	}
	return s.terminateRollback(ctx, operation, in, mode, rep, safetyID, captureIntended, cause, true)
}

// terminateRollback finishes the rollback step + compensation ledger, fires
// the second invalidation, writes the final report to ResultJSON, and
// returns the failing RPC error with the rollback report attached as a
// status detail (grpc-gateway renders it into REST error bodies — neither
// transport delivers a response message on a non-OK status). On rollback
// success the error still names the original cause so automation sees the
// restore did not take effect; on rollback failure it says the target state
// is unknown and never claims restored.
func (s *SnapshotAdminService) terminateRollback(
	ctx context.Context,
	operation *operations.Operation,
	in *adminv1.RestoreSnapshotRequest,
	mode snapshot.RestoreMode,
	rep *snapshot.Report,
	safetyID string,
	captureIntended bool,
	cause error,
	rolledBack bool,
) error {
	finalRep := *rep
	finalRep.RolledBack = rolledBack
	finalRep.Committed = false
	finalRep.SafetySnapshotID = safetyID
	// Ledger persistence never carries rotated plaintext secrets.
	result, _ := json.Marshal(snapshot.RedactCredentialRecovery(&finalRep))

	rollbackErr := ""
	if rolledBack {
		_ = operations.FinishStep(ctx, s.operations, operation, nil)
		_ = operations.AddCompensation(ctx, s.operations, operation, "rollback_safety_snapshot", operations.StepSucceeded, "")
		if s.restorer.Invalidator != nil {
			s.restorer.Invalidator.InvalidateRestoredControlPlane()
		}
	} else {
		rollbackErr = cause.Error()
		_ = operations.FinishStep(ctx, s.operations, operation, cause)
		_ = operations.AddCompensation(ctx, s.operations, operation, "rollback_safety_snapshot", operations.StepFailed, rollbackErr)
	}
	target := fmt.Sprintf("%s mode=%s dry_run=%t", in.Id, mode, in.DryRun)
	recordAdminMeta(ctx, s.recorder, audit.EventSnapshotRestored, target,
		restoreAuditMeta(safetyID, captureIntended, false, rolledBack, rollbackErr))

	finalCause := cause
	prefix := "rollback " + safetyID
	if rolledBack {
		finalCause = fmt.Errorf("rolled back to safety snapshot %s: %w", safetyID, cause)
		prefix = "restore " + in.Id
	}
	return withReportDetail(
		s.failRestoreOperation(ctx, operation, finalCause, prefix, result),
		reportToProto(&finalRep),
	)
}

// failRestoreOperation terminates the operation record on the failure path
// and returns the RPC error with operation_id attached via status details
// (the house pattern — REST clients can find the operation even though a
// failing RPC delivers no response body). result, when non-nil, is persisted
// as ResultJSON so GetOperation exposes the partial / rolled-back state. The
// last step is marked failed only if it is still running — the
// rollback-success path finishes its rollback step before terminating.
func (s *SnapshotAdminService) failRestoreOperation(
	ctx context.Context, operation *operations.Operation, cause error, prefix string, result []byte,
) error {
	if len(operation.Steps) > 0 && operation.Steps[len(operation.Steps)-1].State == operations.StepRunning {
		_ = operations.FinishStep(ctx, s.operations, operation, cause)
	}
	mapped := mapSnapshotError(cause, prefix)
	_ = operations.Finish(ctx, s.operations, operation, result, mapped)
	return operationFailureError(*operation, mapped)
}

// withReportDetail attaches a proto report to a failing status so the
// rollback outcome rides the error. gRPC discards the response message on
// non-OK statuses and grpc-gateway renders status details into REST error
// bodies, so this is the only wire path that carries the report on failure.
func withReportDetail(err error, report *adminv1.RestoreReport) error {
	if err == nil || report == nil {
		return err
	}
	st := status.Convert(err)
	withDetails, derr := st.WithDetails(report)
	if derr != nil {
		return err
	}
	return withDetails.Err()
}

// restoreExclude extracts the request's category excludes.
func restoreExclude(in *adminv1.RestoreSnapshotRequest) []snapshot.ResourceCategory {
	var out []snapshot.ResourceCategory
	for _, x := range in.Exclude {
		out = append(out, snapshot.ResourceCategory(x))
	}
	return out
}

// restoreAuditMeta builds the bounded metadata set for the snapshot-restore
// audit event: the safety artifact id, whether capture was intended, the
// committed / rolled-back outcome, and (only on rollback failure) the
// rollback error. Keys stay within the documented bounded cardinality; the
// decision to skip capture is auditable via auto_safety=false.
func restoreAuditMeta(safetyID string, autoSafety, committed, rolledBack bool, rollbackErr string) map[string]string {
	meta := map[string]string{
		"safety_snapshot_id": safetyID,
		"auto_safety":        strconv.FormatBool(autoSafety),
		"committed":          strconv.FormatBool(committed),
		"rolled_back":        strconv.FormatBool(rolledBack),
	}
	if rollbackErr != "" {
		meta["rollback_error"] = rollbackErr
	}
	return meta
}

func (s *SnapshotAdminService) Delete(ctx context.Context, in *adminv1.DeleteSnapshotRequest) (*adminv1.DeleteSnapshotResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	if err := s.storage.Delete(ctx, in.Id); err != nil {
		return nil, mapSnapshotError(err, "delete "+in.Id)
	}
	recordAdmin(ctx, s.recorder, audit.EventSnapshotDeleted, in.Id)
	return &adminv1.DeleteSnapshotResponse{}, nil
}

// snapshotMetaFromSnapshot projects a fully-decoded Snapshot + the on-disk
// envelope bytes into the wire SnapshotMeta. SizeBytes comes from the raw
// envelope; codec/algorithm/kind come from the envelope wrapper.
func snapshotMetaFromSnapshot(snap *snapshot.Snapshot, raw []byte) *adminv1.SnapshotMeta {
	env, _ := snapshot.PeekEnvelope(raw)
	return &adminv1.SnapshotMeta{
		SchemaVersion:           snap.SchemaVersion,
		SnapshotId:              snap.SnapshotID,
		TakenAtUnix:             snap.TakenAtUnix,
		SourceNamespace:         snap.SourceNamespace,
		SourceNodeId:            snap.SourceNodeID,
		SizeBytes:               int64(len(raw)),
		Codec:                   env.Codec,
		EncryptionAlgorithm:     env.Algorithm,
		BootstrapAppliedVersion: int32(snap.BootstrapState.AppliedVersion),
		Kind:                    env.Kind,
	}
}

// mapSnapshotError translates snapshot SDK sentinels into gRPC status codes.
// prefix is included verbatim so REST gateway responses surface the failing
// operation context.
func mapSnapshotError(err error, prefix string) error {
	switch {
	case errors.Is(err, snapshot.ErrSnapshotNotFound):
		return status.Errorf(codes.NotFound, "%s: not found", prefix)
	case errors.Is(err, snapshot.ErrConfirmationRequired),
		errors.Is(err, snapshot.ErrConfirmationMismatch),
		errors.Is(err, snapshot.ErrUnknownSchemaVersion),
		errors.Is(err, snapshot.ErrUnsupportedRestore),
		errors.Is(err, snapshot.ErrRollbackWithoutSafety):
		return status.Errorf(codes.FailedPrecondition, "%s: %v", prefix, err)
	case errors.Is(err, snapshot.ErrChecksumMismatch):
		return status.Errorf(codes.DataLoss, "%s: %v", prefix, err)
	default:
		return status.Errorf(codes.Internal, "%s: %v", prefix, err)
	}
}
