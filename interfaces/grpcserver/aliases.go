package grpcserver

// The admin gRPC service implementations live in the grpcadmin sub-package so
// this directory stays within the per-directory file-count budget; these
// aliases keep the historical grpcserver.* import surface working unchanged for
// SDK consumers that construct and register the admin services themselves.
// Type aliases preserve identity (a *grpcserver.ClientAdminService IS a
// *grpcadmin.ClientAdminService), so the generated RegisterXxxServiceServer
// helpers still accept them.

import "github.com/yangwb1123/snaplink/interfaces/grpcserver/grpcadmin"

type (
	ClientAdminService     = grpcadmin.ClientAdminService
	KeyAdminService        = grpcadmin.KeyAdminService
	KeyAdminConfig         = grpcadmin.KeyAdminConfig
	PermissionAdminService = grpcadmin.PermissionAdminService
	ReleaseAdminService    = grpcadmin.ReleaseAdminService
	SnapshotAdminService   = grpcadmin.SnapshotAdminService
	TenantAdminService     = grpcadmin.TenantAdminService
	TokenAdminService      = grpcadmin.TokenAdminService
	TokenAdminConfig       = grpcadmin.TokenAdminConfig
	UserAdminService       = grpcadmin.UserAdminService
)

var (
	NewClientAdminService     = grpcadmin.NewClientAdminService
	NewKeyAdminService        = grpcadmin.NewKeyAdminService
	NewPermissionAdminService = grpcadmin.NewPermissionAdminService
	NewReleaseAdminService    = grpcadmin.NewReleaseAdminService
	NewSnapshotAdminService   = grpcadmin.NewSnapshotAdminService
	NewTenantAdminService     = grpcadmin.NewTenantAdminService
	NewOperationAdminService  = grpcadmin.NewOperationAdminService
	NewTokenAdminService      = grpcadmin.NewTokenAdminService
	NewUserAdminService       = grpcadmin.NewUserAdminService
)
