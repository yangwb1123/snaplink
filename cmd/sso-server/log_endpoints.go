package main

import (
	"fmt"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func logEndpoints(cfg *config.Config, grpcListen string) {
	fmt.Println("HTTP endpoints:")
	for _, p := range []string{
		sso.PathHealth, sso.PathJWKS,
		sso.PathLogin, sso.PathSendCode, sso.PathCallback,
		sso.PathToken, sso.PathUserInfo, sso.PathLogout,
		sso.PathMyPermissions, sso.PathMyMenus, sso.PathMyRoles,
	} {
		fmt.Printf("  %s\n", p)
	}
	if cfg.Metrics.Enabled {
		fmt.Printf("  %s\n", "/metrics")
	}
	if cfg.Audit.Enabled && cfg.Audit.APIEnabled {
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathAuditEvents)
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathAuditEventByID)
	}
	if cfg.Network.Enabled && cfg.Network.APIEnabled {
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathNetPolicies)
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathNetPolicyByName)
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathNetPolicyClassify)
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathNetPolicyResolveMe)
	}
	logAdminRESTEndpoints(cfg)
	logGRPCServices(cfg, grpcListen)
}

func logAdminRESTEndpoints(cfg *config.Config) {
	if !cfg.Admin.Enabled || !cfg.Admin.APIRESTEnabled {
		return
	}
	printPaths([]string{
		"GET    /api/v1/admin/clients",
		"POST   /api/v1/admin/clients",
		"GET    /api/v1/admin/clients/{id}",
		"PATCH  /api/v1/admin/clients/{id}",
		"DELETE /api/v1/admin/clients/{id}",
		"POST   /api/v1/admin/clients/{id}:rotateSecret",
		"GET    /api/v1/admin/users",
		"POST   /api/v1/admin/users",
		"GET    /api/v1/admin/users/{id}",
		"PATCH  /api/v1/admin/users/{id}",
		"DELETE /api/v1/admin/users/{id}",
		"GET    /api/v1/admin/users/{user_id}/sessions",
		"GET    /api/v1/admin/sessions",
		"POST   /api/v1/admin/sessions:revoke",
		"POST   /api/v1/admin/tokens:issueTemp",
		"GET    /api/v1/admin/permissions/roles",
		"POST   /api/v1/admin/permissions/roles",
		"PATCH  /api/v1/admin/permissions/roles/{code}",
		"DELETE /api/v1/admin/permissions/roles/{code}",
		"GET    /api/v1/admin/permissions/assignments",
		"POST   /api/v1/admin/permissions:assign",
		"POST   /api/v1/admin/permissions:unassign",
		"PUT    /api/v1/admin/permissions/menus",
	})
	if cfg.Snapshot.Enabled {
		printPaths([]string{
			"POST   /api/v1/admin/snapshots",
			"GET    /api/v1/admin/snapshots",
			"GET    /api/v1/admin/snapshots/{id}",
			"POST   /api/v1/admin/snapshots/{id}:restore",
			"DELETE /api/v1/admin/snapshots/{id}",
		})
	}
	if cfg.Releases.Enabled {
		printPaths([]string{
			"POST   /api/v1/admin/releases",
			"GET    /api/v1/admin/releases",
			"GET    /api/v1/admin/releases:current",
			"GET    /api/v1/admin/releases/{id}",
			"POST   /api/v1/admin/releases/{id}:pin",
			"POST   /api/v1/admin/releases/{id}:rollback",
			"DELETE /api/v1/admin/releases/{id}",
		})
	}
}

func logGRPCServices(cfg *config.Config, grpcListen string) {
	if grpcListen == "" {
		return
	}
	fmt.Printf("gRPC services on %s:\n", grpcListen)
	fmt.Println("  snaplink.audit.v1.AuditWriter / Record + StreamEvents")
	fmt.Println("  snaplink.authz.v1.Authorizer / Check + List* + GetMenus")
	fmt.Println("  snaplink.discovery.v1.Discovery / Register + Discover + Watch")
	if cfg.Network.Enabled {
		fmt.Println("  snaplink.netpolicy.v1.PolicyService / Get + List + Apply + Delete + Watch + Classify")
	}
	if !cfg.Admin.Enabled {
		return
	}
	fmt.Println("  snaplink.admin.v1.ClientAdminService / List + Get + Create + Update + Delete + RotateSecret")
	fmt.Println("  snaplink.admin.v1.UserAdminService / List + Get + Create + Update + Delete + ListUserSessions")
	fmt.Println("  snaplink.admin.v1.TokenAdminService / ListSessions + Revoke + IssueTempToken")
	fmt.Println("  snaplink.admin.v1.PermissionAdminService / *")
	if cfg.Snapshot.Enabled {
		fmt.Println("  snaplink.admin.v1.SnapshotAdminService / Export + List + Get + Restore + Delete")
	}
	if cfg.Releases.Enabled {
		fmt.Println("  snaplink.admin.v1.ReleaseAdminService / Register + List + Get + GetCurrent + Pin + Rollback + Delete")
	}
}

func printPaths(paths []string) {
	for _, p := range paths {
		fmt.Printf("  %s\n", p)
	}
}
