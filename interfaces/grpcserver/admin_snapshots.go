package grpcserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/platform/audit"
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
}

func NewSnapshotAdminService(p *snapshot.Pipeline, st snapshot.Storage, sn *snapshot.Snapshotter, r *snapshot.Restorer, recorder *audit.Recorder) *SnapshotAdminService {
	return &SnapshotAdminService{pipeline: p, storage: st, snapshotter: sn, restorer: r, recorder: recorder}
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

func (s *SnapshotAdminService) List(ctx context.Context, _ *adminv1.ListSnapshotsRequest) (*adminv1.ListSnapshotsResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	names, err := s.storage.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	out := &adminv1.ListSnapshotsResponse{Items: make([]*adminv1.SnapshotMeta, 0, len(names))}
	for _, name := range names {
		raw, err := s.storage.Get(ctx, name)
		if err != nil {
			return nil, mapSnapshotError(err, "get "+name)
		}
		env, err := snapshot.PeekEnvelope(raw)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "peek %s: %v", name, err)
		}
		// Body-derived fields (taken_at_unix, source_namespace,
		// bootstrap_applied_version) live inside the (potentially encrypted)
		// body and are intentionally left zero here. Operators should call
		// Get to populate them.
		out.Items = append(out.Items, &adminv1.SnapshotMeta{
			SnapshotId:          env.SnapshotID,
			SchemaVersion:       snapshot.SchemaVersion,
			Codec:               env.Codec,
			EncryptionAlgorithm: env.Algorithm,
			SizeBytes:           int64(len(raw)),
		})
	}
	return out, nil
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
	resBytes, err := json.Marshal(snap.Resources)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal resources: %v", err)
	}
	return &adminv1.GetSnapshotResponse{
		Meta:          snapshotMetaFromSnapshot(snap, raw),
		ResourcesJson: resBytes,
	}, nil
}

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

	snap, err := s.pipeline.Load(ctx, s.storage, in.Id)
	if err != nil {
		return nil, mapSnapshotError(err, "load "+in.Id)
	}
	opts := snapshot.RestoreOptions{
		Mode:             mode,
		DryRun:           in.DryRun,
		AdvanceBootstrap: in.AdvanceBootstrap,
		Confirm:          in.Confirm,
	}
	for _, x := range in.Exclude {
		opts.Exclude = append(opts.Exclude, snapshot.ResourceCategory(x))
	}
	rep, err := s.restorer.Restore(ctx, snap, opts)
	if err != nil {
		return nil, mapSnapshotError(err, "restore "+in.Id)
	}
	target := fmt.Sprintf("%s mode=%s dry_run=%t", in.Id, mode, in.DryRun)
	recordAdmin(ctx, s.recorder, audit.EventSnapshotRestored, target)
	return &adminv1.RestoreSnapshotResponse{Report: reportToProto(rep)}, nil
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
// envelope; codec/algorithm come from the envelope wrapper.
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
	}
}

func reportToProto(r *snapshot.Report) *adminv1.RestoreReport {
	if r == nil {
		return nil
	}
	out := &adminv1.RestoreReport{
		Mode:   string(r.Mode),
		DryRun: r.DryRun,
		Items:  make(map[string]*adminv1.CategoryCounts, len(r.Items)),
		Bootstrap: &adminv1.BootstrapAdvance{
			Attempted: r.Bootstrap.Attempted,
			From:      int32(r.Bootstrap.From),
			To:        int32(r.Bootstrap.To),
			NoOp:      r.Bootstrap.NoOp,
			Reason:    r.Bootstrap.Reason,
		},
		Errors: append([]string(nil), r.Errors...),
	}
	for cat, c := range r.Items {
		out.Items[string(cat)] = &adminv1.CategoryCounts{
			Inserted: int32(c.Inserted),
			Updated:  int32(c.Updated),
			Deleted:  int32(c.Deleted),
			Skipped:  int32(c.Skipped),
		}
	}
	return out
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
		errors.Is(err, snapshot.ErrUnknownSchemaVersion):
		return status.Errorf(codes.FailedPrecondition, "%s: %v", prefix, err)
	case errors.Is(err, snapshot.ErrChecksumMismatch):
		return status.Errorf(codes.DataLoss, "%s: %v", prefix, err)
	default:
		return status.Errorf(codes.Internal, "%s: %v", prefix, err)
	}
}
