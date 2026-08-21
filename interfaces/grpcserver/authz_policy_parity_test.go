package grpcserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/yangwb1123/snaplink/domains/permissions"
	authzv1 "github.com/yangwb1123/snaplink/gen/proto/authz/v1"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
)

func TestAuthzCheckMatchesExportedPolicyBundle(t *testing.T) {
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	roles := []permissions.Role{
		{Code: "operator", Permissions: []string{"billing:*", "audit:read"}},
		{Code: "billing", Permissions: []string{"billing:write"}},
	}
	for _, role := range roles {
		if err := p.AddRole(ctx, "web", role); err != nil {
			t.Fatalf("AddRole %s: %v", role.Code, err)
		}
	}
	if err := p.AssignRoles(ctx, "alice", "web", []string{"operator"}); err != nil {
		t.Fatalf("AssignRoles alice: %v", err)
	}
	if err := p.AssignRoles(ctx, "bob", "web", []string{"billing"}); err != nil {
		t.Fatalf("AssignRoles bob: %v", err)
	}
	if err := p.SetConflictSets(ctx, "web", [][]string{{"operator", "auditor"}}); err != nil {
		t.Fatalf("SetConflictSets: %v", err)
	}
	if err := p.SetActivationConflictSets(ctx, "web", [][]string{{"operator", "billing"}}); err != nil {
		t.Fatalf("SetActivationConflictSets: %v", err)
	}
	if err := p.ActivateRoles(ctx, "alice", "web", "sid-alice", []string{"operator"}); err != nil {
		t.Fatalf("ActivateRoles alice: %v", err)
	}
	if err := p.ActivateRoles(ctx, "bob", "web", "sid-bob", []string{"billing"}); err != nil {
		t.Fatalf("ActivateRoles bob: %v", err)
	}
	if err := p.ActivateRoles(ctx, "empty", "web", "sid-empty", nil); err != nil {
		t.Fatalf("ActivateRoles empty: %v", err)
	}
	for _, resource := range []*permissions.Resource{
		{
			ID: "r-sensitive", TenantID: "tenant-a", ClientID: "web",
			Type: permissions.ResourceTypeHTTPAPI, Name: "sensitive", RequiresAuth: true,
			Attributes:          map[string]string{"method": "POST", "path": "/users/:id"},
			RequiredPermissions: []string{"billing:write", "audit:read"}, RequireMode: permissions.RequireAll,
		},
		{
			ID: "r-public", TenantID: "tenant-a", ClientID: "web",
			Type: permissions.ResourceTypeHTTPAPI, Name: "health", Attributes: map[string]string{
				"method": "GET", "path": "/health",
			},
		},
	} {
		if err := p.RegisterResource(ctx, resource); err != nil {
			t.Fatalf("RegisterResource %s: %v", resource.ID, err)
		}
	}
	bundle, err := permissions.BuildPolicyBundle(ctx, p, "web")
	if err != nil {
		t.Fatalf("BuildPolicyBundle: %v", err)
	}
	service := grpcserver.NewAuthzService(p)
	fixtures := []struct {
		name  string
		roles []string
		input *authzv1.CheckRequest
	}{
		{
			name:  "active operator matches parameterized require-all",
			roles: []string{"operator"},
			input: &authzv1.CheckRequest{
				SubjectId: "alice", ClientId: "web", Permission: "ignored", SessionId: "sid-alice",
				ResourceType: "http_api", TenantId: "tenant-a",
				Attributes: map[string]string{"method": "post", "path": "/users/42"},
			},
		},
		{
			name:  "active billing misses require-all",
			roles: []string{"billing"},
			input: &authzv1.CheckRequest{
				SubjectId: "bob", ClientId: "web", Permission: "ignored", SessionId: "sid-bob",
				ResourceType: "http_api", TenantId: "tenant-a",
				Attributes: map[string]string{"method": "POST", "path": "/users/42"},
			},
		},
		{
			name:  "active billing flat fallback",
			roles: []string{"billing"},
			input: &authzv1.CheckRequest{
				SubjectId: "bob", ClientId: "web", Permission: "billing:write", SessionId: "sid-bob",
				ResourceType: "http_api", TenantId: "tenant-a",
				Attributes: map[string]string{"method": "POST", "path": "/not-cataloged"},
			},
		},
		{
			name:  "wildcard flat fallback",
			roles: []string{"operator"},
			input: &authzv1.CheckRequest{
				SubjectId: "alice", ClientId: "web", Permission: "billing:delete", SessionId: "sid-alice",
				ResourceType: "http_api", TenantId: "tenant-a",
				Attributes: map[string]string{"method": "POST", "path": "/not-cataloged"},
			},
		},
		{
			name:  "empty active set",
			roles: nil,
			input: &authzv1.CheckRequest{SubjectId: "empty", ClientId: "web", Permission: "billing:write", SessionId: "sid-empty"},
		},
		{
			name:  "public resource",
			roles: []string{"billing"},
			input: &authzv1.CheckRequest{SubjectId: "bob", ClientId: "web", Permission: "ignored", SessionId: "sid-bob", ResourceType: "http_api", TenantId: "tenant-a", Attributes: map[string]string{"method": "GET", "path": "/health"}},
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			live, err := service.Check(ctx, fixture.input)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			bundled, err := evalBundlePolicy(ctx, bundle, fixture.roles, fixture.input)
			if err != nil {
				t.Fatalf("OPA evaluation: %v", err)
			}
			if live.Allowed != bundled {
				t.Fatalf("server=%v bundle=%v request=%+v", live.Allowed, bundled, fixture.input)
			}
		})
	}
}

func evalBundlePolicy(ctx context.Context, bundle *permissions.PolicyBundle, roleCodes []string, request *authzv1.CheckRequest) (bool, error) {
	policyPath := filepath.Join(policySourceDir(), "docs", "examples", "opa-authz-policy.rego")
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		return false, fmt.Errorf("read reference policy: %w", err)
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return false, fmt.Errorf("marshal bundle: %w", err)
	}
	var bundleData map[string]any
	if err := json.Unmarshal(bundleJSON, &bundleData); err != nil {
		return false, fmt.Errorf("decode bundle: %w", err)
	}
	query, err := rego.New(
		rego.Query("data.authz.allow"),
		rego.Module("opa-authz-policy.rego", string(policy)),
		rego.Data(map[string]any{"bundle": bundleData}),
	).PrepareForEval(ctx)
	if err != nil {
		return false, fmt.Errorf("prepare policy: %w", err)
	}
	input := map[string]any{"roles": roleCodes, "want": request.Permission}
	if request.SessionId != "" {
		input["session_id"] = request.SessionId
	}
	if request.ResourceType != "" {
		input["resource"] = map[string]any{
			"type":       request.ResourceType,
			"tenant_id":  request.TenantId,
			"client_id":  request.ClientId,
			"attributes": request.Attributes,
		}
	}
	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, err
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return false, fmt.Errorf("unexpected OPA result: %+v", results)
	}
	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("OPA result is %T, want bool", results[0].Expressions[0].Value)
	}
	return allowed, nil
}

func policySourceDir() string {
	_, source, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}
