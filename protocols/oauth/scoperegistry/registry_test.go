package scoperegistry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/shared/core"
)

// The nine-scope matrix literal mirrors interfaces/scopecontract.Matrix (a
// scoperegistry test must not import interfaces — upward edge). The structural
// alias pin lives in interfaces/scopecontract/consts_test.go.
var matrixLiteral = []string{
	"admin:read",
	"admin:write",
	"billing:payment:order:read",
	"billing:payment:write",
	"billing:checkout:create",
	"metering:write",
	"billing:entitlement:read",
	"audit:event:write",
	"admin:*",
}

// A-8e: the pre-seeded protocol set is exactly the seven OIDC/Native-SSO
// constants from shared/core — imported, so a future bypass constant added to
// oauthvalidate.GrantedScopes is compile-time visible and the registry cannot
// silently diverge from it.
func TestMemoryProtocolScopesMatchCoreConstants(t *testing.T) {
	want := []string{
		core.ScopeOpenID, core.ScopeDeviceSSO,
		core.ScopeProfile, core.ScopeEmail, core.ScopeAddress,
		core.ScopePhone, core.ScopeOfflineAccess,
	}
	got := ProtocolScopes()
	if len(got) != len(want) {
		t.Fatalf("ProtocolScopes() = %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ProtocolScopes()[%d] = %q, want %q (full set %v)", i, got[i], want[i], got)
		}
	}
}

// FM-5: registry pattern semantics must agree with permissions.Matches for the
// exact-or-":*" grammar (mint/enforce drift guard).
func TestMemoryRegisteredMatchesPermissionsSemantics(t *testing.T) {
	reg, err := NewMemory(matrixLiteral, nil)
	if err != nil {
		t.Fatal(err)
	}
	have := make([]permissions.Permission, 0, len(matrixLiteral))
	for _, code := range matrixLiteral {
		have = append(have, permissions.Permission{Code: code})
	}
	cases := []struct {
		scope string
		want  bool
	}{
		{"admin:read", true},        // exact matrix member
		{"admin:write", true},       // exact matrix member
		{"admin:list", true},        // admin:* prefix (matches permissions.Matches)
		{"audit:event:write", true}, // exact
		{"metering:write", true},    // exact
		{"profile", true},           // pre-seeded protocol scope
		{"offline_access", true},    // pre-seeded protocol scope
		{"billing:payment:order:read", true},
		{"billing:checkout:create", true}, // exact matrix member
		{"anything", false},               // unregistered
		{"api:read", false},               // unregistered
		{"admin", false},                  // bare domain is NOT the wildcard
		{"", false},                       // empty never registered
	}
	for _, tc := range cases {
		got := reg.Registered(tc.scope)
		if got != tc.want {
			t.Errorf("Registered(%q) = %v, want %v", tc.scope, got, tc.want)
		}
	}
	// Cross-check against permissions.Matches for the MATRIX rows only
	// (protocol scopes are deliberately pre-seeded protocol constants, not
	// permission codes): every matrix scope the registry registers must be
	// granted by the same pattern set the enforcement side uses —
	// mint/enforce must agree in both directions.
	matrixOnly := []string{
		"admin:read", "admin:write", "admin:list", "audit:event:write",
		"metering:write", "billing:payment:order:read", "anything",
		"api:read", "admin",
	}
	for _, scope := range matrixOnly {
		want := reg.Registered(scope)
		if got := permissions.Matches(have, scope); got != want {
			t.Errorf("Registered(%q) = %v but permissions.Matches = %v — mint/enforce drift", scope, want, got)
		}
	}
}

// FM-3: fail-closed validation — a bare "*" would make the gate a no-op and
// a non-":*" wildcard diverges from permissions.Matches; both are construction
// errors, never runtime fail-open.
func TestMemoryRejectsFailOpenPatterns(t *testing.T) {
	for _, bad := range []string{"*", "admin*", "admin:*:read", "billing:payment:*:read"} {
		if _, err := NewMemory(matrixLiteral, []string{bad}); err == nil {
			t.Errorf("NewMemory with extra %q: want construction error", bad)
		}
	}
	if _, err := NewMemory([]string{"*"}, nil); err == nil {
		t.Error("NewMemory with matrix [\"*\"]: want construction error")
	}
	if _, err := NewMemory(matrixLiteral, []string{""}); err == nil {
		t.Error("NewMemory with empty extra scope: want construction error")
	}
}

// FM-7: build-once discipline — construction is the only mutation; a frozen
// flag makes any post-build Register an error so concurrent mint-path reads
// can never race a writer.
func TestMemoryFrozenAfterBuild(t *testing.T) {
	reg, err := NewMemory(matrixLiteral, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register("anything"); err == nil {
		t.Fatal("Register on a built registry must error (frozen)")
	}
	if reg.Registered("anything") {
		t.Fatal("unregistered scope reported registered")
	}
}

// Duplicates are set semantics: listing a built-in in extra_scopes is a
// harmless idempotent no-op (task-2 §1) and never shadows the built-in.
func TestMemoryExtraDuplicatesAreNoOp(t *testing.T) {
	reg, err := NewMemory(matrixLiteral, []string{"openid", "profile", "admin:read"})
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Registered("openid") || !reg.Registered("profile") || !reg.Registered("admin:read") {
		t.Fatal("duplicate entries must not remove the scope")
	}
}

// RejectUnregistered: nil registry and empty scope set are no-ops (the
// byte-compat baseline); a rejected scope writes the plain invalid_scope body
// with status 400 and no trace_id.
func TestRejectUnregistered(t *testing.T) {
	reg, err := NewMemory(matrixLiteral, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("nil registry no-op", func(t *testing.T) {
		ctx := newTestCtx()
		if RejectUnregistered(ctx, nil, []string{"anything"}) {
			t.Fatal("nil registry must not reject")
		}
		if ctx.wrote {
			t.Fatal("nil registry must not write a response")
		}
	})
	t.Run("empty scopes no-op", func(t *testing.T) {
		ctx := newTestCtx()
		if RejectUnregistered(ctx, reg, nil) {
			t.Fatal("empty scopes must not reject")
		}
		if ctx.wrote {
			t.Fatal("empty scopes must not write a response")
		}
	})
	t.Run("registered passes", func(t *testing.T) {
		ctx := newTestCtx()
		if RejectUnregistered(ctx, reg, []string{"admin:read", "profile"}) {
			t.Fatal("registered scopes must pass")
		}
		if ctx.wrote {
			t.Fatal("registered scopes must not write a response")
		}
	})
	t.Run("unregistered rejects with plain body", func(t *testing.T) {
		ctx := newTestCtx()
		if !RejectUnregistered(ctx, reg, []string{"profile", "billing:typo"}) {
			t.Fatal("unregistered scope must reject")
		}
		if ctx.status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", ctx.status)
		}
		if got := string(ctx.body); got != `{"error":"invalid_scope"}` {
			t.Fatalf("body = %s, want byte-identical plain invalid_scope (no trace_id)", got)
		}
	})
}

// FilterRegistered drops unregistered scopes, preserves order; nil registry
// returns the input unchanged (registry-off byte-identical).
func TestFilterRegistered(t *testing.T) {
	reg, err := NewMemory(matrixLiteral, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := []string{"anything", "openid", "profile", "admin:read", "typo"}
	got := FilterRegistered(reg, in)
	want := []string{"openid", "profile", "admin:read"}
	if len(got) != len(want) {
		t.Fatalf("FilterRegistered = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("FilterRegistered = %v, want %v", got, want)
		}
	}
	if out := FilterRegistered(nil, in); len(out) != len(in) {
		t.Fatalf("nil registry must pass input through unchanged, got %v", out)
	}
}

// testCtx is a minimal core.HandlerContext recording the written response.
type testCtx struct {
	status int
	body   []byte
	wrote  bool
}

func newTestCtx() *testCtx { return &testCtx{} }

func (c *testCtx) Request() *http.Request { return httptest.NewRequest(http.MethodPost, "/token", nil) }
func (c *testCtx) ResponseWriter() http.ResponseWriter {
	return httptest.NewRecorder()
}
func (c *testCtx) Param(string) string { return "" }
func (c *testCtx) Query(string) string { return "" }
func (c *testCtx) Bind(any) error      { return nil }
func (c *testCtx) JSON(status int, v any) {
	c.status = status
	c.wrote = true
	switch b := v.(type) {
	case map[string]string:
		c.body, _ = json.Marshal(b)
	case map[string]any:
		c.body, _ = json.Marshal(b)
	case string:
		c.body = []byte(b)
	}
}
func (c *testCtx) Redirect(int, string)                  {}
func (c *testCtx) Set(string, any)                       {}
func (c *testCtx) Get(string) any                        { return nil }
func (c *testCtx) Abort()                                {}
func (c *testCtx) Aborted() bool                         { return false }
func (c *testCtx) Written() bool                         { return c.wrote }
func (c *testCtx) SetResponseWriter(http.ResponseWriter) {}

var _ core.HandlerContext = (*testCtx)(nil)

// keep strings imported for the drift guard on wildcard-bearing patterns.
var _ = strings.Contains
