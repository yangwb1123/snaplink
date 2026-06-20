package grpcadmin

import (
	"context"
	"errors"
	"fmt"
	"time"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/releases"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReleaseAdminService exposes the releases.Registry over gRPC.
// Mutating RPCs (Register / Pin / Rollback / Delete) write one audit
// event each. Pinner is held inside the Registry — operators wire
// the right backend at cmd time; this service is unaware.
type ReleaseAdminService struct {
	adminv1.UnimplementedReleaseAdminServiceServer
	registry *releases.Registry
	store    releases.ReleaseStore
	recorder *audit.Recorder
}

// NewReleaseAdminService takes the Registry (for Pin/Rollback/Current)
// plus the underlying Store (for Register/List/Get/Delete which don't
// need the Pinner). Both must point at the same backing store.
func NewReleaseAdminService(reg *releases.Registry, store releases.ReleaseStore, recorder *audit.Recorder) *ReleaseAdminService {
	return &ReleaseAdminService{registry: reg, store: store, recorder: recorder}
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

func (s *ReleaseAdminService) List(ctx context.Context, _ *adminv1.ListReleasesRequest) (*adminv1.ListReleasesResponse, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	out := &adminv1.ListReleasesResponse{Items: make([]*adminv1.Release, 0, len(all))}
	for _, r := range all {
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
	rep, err := s.registry.Pin(ctx, in.Id)
	if err != nil {
		return nil, mapReleaseError(err, "pin "+in.Id)
	}
	target := fmt.Sprintf("%s previous=%s", rep.ReleaseID, rep.PreviousID)
	recordAdmin(ctx, s.recorder, audit.EventReleasePinned, target)
	return &adminv1.PinReleaseResponse{Report: pinReportToProto(rep)}, nil
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
	rep, err := s.registry.Rollback(ctx, in.Id)
	if err != nil {
		return nil, mapReleaseError(err, "rollback "+in.Id)
	}
	target := fmt.Sprintf("%s previous=%s", rep.ReleaseID, rep.PreviousID)
	recordAdmin(ctx, s.recorder, audit.EventReleaseRolledBack, target)
	return &adminv1.RollbackReleaseResponse{Report: pinReportToProto(rep)}, nil
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
