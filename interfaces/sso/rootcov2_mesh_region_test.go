package sso_test

// rootcov2_mesh_region_test.go drives the mesh ext_authz endpoint with a region
// resolver + an AllowedRegions backstop wired, so the synthetic-request region
// stashing path (mesh_authz.go stashMeshServingRegion + meshRegionAllowed) runs
// — which the first rootcov_* pass left at 0%. It also covers the residency
// read-gate decision on the mesh path.
//
// REUSES rcovNewServer / rcovDirectLogin from rootcov_flow_test.go.

import (
	"net/http"
	"testing"

	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/interfaces/sso"
)

// TestRcov2Mesh_RegionAllowed exercises the mesh ext_authz ALLOW path with a
// region resolver whose pinned region IS in the AllowedRegions set — so
// meshRegionAllowed returns true and the serving region is stashed.
func TestRcov2Mesh_RegionAllowed(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t,
		sso.WithMeshExtAuthz("/mesh/ext-authz"),
		sso.WithRegionMiddleware(
			region.ConfigPinnedResolver{Region: region.ID("us")},
			region.MiddlewareOptions{AllowedRegions: []region.ID{region.ID("us"), region.ID("eu")}},
		),
	)
	access, _ := rcovDirectLogin(t, s)

	req, _ := http.NewRequest(http.MethodGet, s.http.URL+"/mesh/ext-authz", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("mesh ext-authz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("mesh allow (region in allowlist) = %d, want 200", resp.StatusCode)
	}
}

// TestRcov2Mesh_RegionNotAllowed exercises the OTHER meshRegionAllowed branch:
// the resolver's pinned region is NOT in AllowedRegions, so the serving region
// is cleared to "" before the (no-residency-policy) decision proceeds. Without a
// tenant residency policy wired the request still ALLOWs — the goal here is to
// drive the not-allowed branch, not to assert a deny.
func TestRcov2Mesh_RegionNotAllowed(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t,
		sso.WithMeshExtAuthz("/mesh/ext-authz"),
		sso.WithRegionMiddleware(
			region.ConfigPinnedResolver{Region: region.ID("ap")},
			region.MiddlewareOptions{AllowedRegions: []region.ID{region.ID("us"), region.ID("eu")}},
		),
	)
	access, _ := rcovDirectLogin(t, s)

	req, _ := http.NewRequest(http.MethodGet, s.http.URL+"/mesh/ext-authz", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("mesh ext-authz: %v", err)
	}
	_ = resp.Body.Close()
	// No residency policy => still ALLOW even though the serving region was
	// cleared; the branch under test is the AllowedRegions filter, not a deny.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("mesh (region not in allowlist, no residency) = %d, want 200", resp.StatusCode)
	}
}
