package defaultimpl

// tenant_roles_test.go pins the SnapLink tenant_id + roles access-token
// claims for EVERY signer (Ed25519/ECDSA/RSA share buildAccessPayload, but
// the three header/payload struct literals are per-issuer drift points, so
// T-2's per-issuer discipline applies), plus the ext-collision strip rule
// (AC-8a..f) and the tag-vs-const coupling guard (AC-7).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

// tenantRolesIssuer is the minimal surface the tests need across signers.
type tenantRolesIssuer interface {
	Issue(context.Context, *sso.Subject, []string) (*sso.Token, error)
}

// tenantRolesIssuers returns one issuer per signer so the new claims are
// pinned for all three (mirrors servingRegionIssuers in serving_region_test.go).
func tenantRolesIssuers(t *testing.T) map[string]tenantRolesIssuer {
	t.Helper()
	clock := fixedClockTime{}
	return map[string]tenantRolesIssuer{
		"ed25519": NewEd25519JWTIssuer(WithEd25519Issuer("test-iss"),
			WithEd25519TokenTTL(5*time.Minute), WithEd25519Clock(clock)),
		"ecdsa": NewECDSAJWTIssuer(WithECDSAIssuer("test-iss"),
			WithECDSATokenTTL(5*time.Minute), WithECDSAClock(clock)),
		"rsa": NewRSAJWTIssuer(WithRSAIssuer("test-iss"),
			WithRSATokenTTL(5*time.Minute), WithRSAClock(clock)),
	}
}

type fixedClockTime struct{}

func (fixedClockTime) Now() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}

// trDecodeSegments returns (header, payload) JSON maps of a compact JWS.
func trDecodeSegments(t *testing.T, token string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-segment JWS: %q", token)
	}
	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header decode: %v", err)
	}
	praw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	header := map[string]any{}
	payload := map[string]any{}
	if err := json.Unmarshal(hraw, &header); err != nil {
		t.Fatalf("header parse: %v", err)
	}
	if err := json.Unmarshal(praw, &payload); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	return header, payload
}

// TestTenantRoles_ClaimsPerIssuer is AC-1..AC-3: for each signer, a Subject
// with TenantID + Roles mints a token whose payload carries top-level
// tenant_id == the binding value and roles == the set value.
func TestTenantRoles_ClaimsPerIssuer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, iss := range tenantRolesIssuers(t) {
		t.Run(name, func(t *testing.T) {
			tok, err := iss.Issue(ctx, &sso.Subject{
				ID: "user-1", ClientID: "client-1",
				TenantID: "tenant-acme", Roles: []string{"member", "admin"},
			}, []string{"read"})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			_, payload := trDecodeSegments(t, tok.AccessToken)
			if got := payload["tenant_id"]; got != "tenant-acme" {
				t.Errorf("tenant_id = %v, want tenant-acme", got)
			}
			roles, ok := payload["roles"].([]any)
			if !ok || len(roles) != 2 || roles[0] != "member" || roles[1] != "admin" {
				t.Errorf("roles = %v, want [member admin]", payload["roles"])
			}
		})
	}
}

// TestTenantRoles_KidExactlyOnce is AC-4/AC-5: the `kid` header member is
// emitted exactly once per issuer (the header structs are per-issuer drift
// points — a duplicated/misspelled field would surface here).
func TestTenantRoles_KidExactlyOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, iss := range tenantRolesIssuers(t) {
		t.Run(name, func(t *testing.T) {
			tok, err := iss.Issue(ctx, &sso.Subject{
				ID: "user-1", ClientID: "client-1", TenantID: "t", Roles: []string{"member"},
			}, []string{"read"})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			headerRaw := trRawSegment(t, tok.AccessToken, 0)
			if got := strings.Count(headerRaw, "kid"); got != 1 {
				t.Errorf("kid appears %d times in header %q, want exactly 1", got, headerRaw)
			}
		})
	}
}

func trRawSegment(t *testing.T, token string, idx int) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-segment JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[idx])
	if err != nil {
		t.Fatalf("segment %d decode: %v", idx, err)
	}
	return string(raw)
}

// TestTenantRoles_EmptyCaseByteIdentity is T-2's backward-compatibility pin:
// a single-tenant (TenantID == "") subject with no roles mints a payload
// whose claim set is EXACTLY the pre-change set — no tenant_id, no roles —
// and whose remaining claims are byte-identical (json.Marshal sorts map
// keys, so the sorted key set + values pins the bytes modulo the random
// jti; the fixed clock pins iat/nbf/exp).
func TestTenantRoles_EmptyCaseByteIdentity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	wantKeys := []string{"client_id", "exp", "iat", "iss", "jti", "nbf", "scope", "sub"}
	for name, iss := range tenantRolesIssuers(t) {
		t.Run(name, func(t *testing.T) {
			tok, err := iss.Issue(ctx, &sso.Subject{ID: "user-1", ClientID: "client-1"}, []string{"read"})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			_, payload := trDecodeSegments(t, tok.AccessToken)
			if _, present := payload["tenant_id"]; present {
				t.Error("tenant_id present despite empty Subject.TenantID")
			}
			if _, present := payload["roles"]; present {
				t.Error("roles present despite nil Subject.Roles")
			}
			keys := make([]string, 0, len(payload))
			for k := range payload {
				keys = append(keys, k)
			}
			trSortStrings(keys)
			if !trEqualStrings(keys, wantKeys) {
				t.Errorf("payload keys = %v, want exactly %v (byte-identity: nothing added, nothing dropped)", keys, wantKeys)
			}
			if got := payload["iss"]; got != "test-iss" {
				t.Errorf("iss = %v", got)
			}
			if got := int64(payload["iat"].(float64)); got != 1_700_000_000 {
				t.Errorf("iat = %d, want fixed clock 1700000000", got)
			}
			if got := int64(payload["exp"].(float64)); got != 1_700_000_000+300 {
				t.Errorf("exp = %d, want fixed clock + TTL 1700000300", got)
			}
			if got := payload["scope"]; got != "read" {
				t.Errorf("scope = %v", got)
			}
		})
	}
}

// TestTenantRoles_TagConstCoupling is AC-7: the payload struct tags MUST
// stay coupled to the shared wire consts — a tag/const drift would silently
// rename the claim on the wire.
func TestTenantRoles_TagConstCoupling(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeOf(ed25519Payload{})
	for _, tc := range []struct {
		field, want string
	}{
		{"TenantID", core.KeyTenantID + ",omitempty"},
		{"Roles", core.KeyRoles + ",omitempty"},
	} {
		f, ok := typ.FieldByName(tc.field)
		if !ok {
			t.Fatalf("ed25519Payload has no %s field", tc.field)
		}
		if got := f.Tag.Get("json"); got != tc.want {
			t.Errorf("%s json tag = %q, want %q (claim name must track the wire const)", tc.field, got, tc.want)
		}
	}
}

// TestClaimsWithoutEmittedKeys_StripRule is AC-8a..8f: the precedence-or-
// strip rule on the ext map.
func TestClaimsWithoutEmittedKeys_StripRule(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	iss := NewEd25519JWTIssuer(WithEd25519Issuer("test-iss"), WithEd25519TokenTTL(time.Minute))

	// AC-8a: tenant-bound client, ext.tenant_id differs -> top-level wins,
	// ext entry stripped. AC-8b: equal value -> STILL stripped (deterministic
	// rule; the wire shape never depends on attribute coincidence).
	for _, attrValue := range []string{"other-tenant", "tenant-acme"} {
		claims := map[string]string{core.KeyTenantID: attrValue, "email": "a@example.com"}
		tok, err := iss.Issue(ctx, &sso.Subject{
			ID: "user-1", ClientID: "client-1", TenantID: "tenant-acme",
			Claims: claims,
		}, []string{"read"})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		_, payload := trDecodeSegments(t, tok.AccessToken)
		if got := payload["tenant_id"]; got != "tenant-acme" {
			t.Errorf("top-level tenant_id = %v, want tenant-acme", got)
		}
		ext, ok := payload["ext"].(map[string]any)
		if !ok {
			t.Fatalf("no ext map on token: %v", payload)
		}
		if _, present := ext[core.KeyTenantID]; present {
			t.Errorf("ext still carries tenant_id=%q after strip (attribute value %q)", attrValue, attrValue)
		}
		if ext["email"] != "a@example.com" {
			t.Errorf("unrelated ext entries must survive: %v", ext)
		}
		// AC-8d: the caller-owned map was never mutated.
		if claims[core.KeyTenantID] != attrValue {
			t.Errorf("subject.Claims mutated by issuance: %v", claims)
		}
	}

	// AC-8c: single-tenant (TenantID == "") -> no top-level claim, ext
	// preserved byte-for-byte (the admin write-quota hint survives).
	claims := map[string]string{core.KeyTenantID: "quota-hint", "email": "a@example.com"}
	tok, err := iss.Issue(ctx, &sso.Subject{ID: "user-1", ClientID: "client-1", Claims: claims}, []string{"read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, payload := trDecodeSegments(t, tok.AccessToken)
	if _, present := payload["tenant_id"]; present {
		t.Error("top-level tenant_id present despite empty binding")
	}
	ext, ok := payload["ext"].(map[string]any)
	if !ok {
		t.Fatalf("no ext map: %v", payload)
	}
	if ext[core.KeyTenantID] != "quota-hint" {
		t.Errorf("ext.tenant_id = %v, want quota-hint (passthrough preserved)", ext[core.KeyTenantID])
	}

	// AC-8e: roles variant — membership roles + ext.roles attribute -> top
	// level wins, ext stripped; empty membership + ext.roles -> preserved.
	tok, err = iss.Issue(ctx, &sso.Subject{
		ID: "user-1", ClientID: "client-1", Roles: []string{"member"},
		Claims: map[string]string{core.KeyRoles: "scim-role", "email": "a@example.com"},
	}, []string{"read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, payload = trDecodeSegments(t, tok.AccessToken)
	if got, _ := payload["roles"].([]any); len(got) != 1 || got[0] != "member" {
		t.Errorf("top-level roles = %v, want [member]", payload["roles"])
	}
	ext, ok = payload["ext"].(map[string]any)
	if !ok {
		t.Fatalf("no ext map: %v", payload)
	}
	if _, present := ext[core.KeyRoles]; present {
		t.Error("ext still carries roles after strip")
	}
	tok, err = iss.Issue(ctx, &sso.Subject{
		ID: "user-1", ClientID: "client-1",
		Claims: map[string]string{core.KeyRoles: "scim-role"},
	}, []string{"read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, payload = trDecodeSegments(t, tok.AccessToken)
	if _, present := payload["roles"]; present {
		t.Error("top-level roles present despite empty Subject.Roles")
	}
	ext, ok = payload["ext"].(map[string]any)
	if !ok {
		t.Fatalf("no ext map: %v", payload)
	}
	if ext[core.KeyRoles] != "scim-role" {
		t.Errorf("ext.roles = %v, want scim-role (passthrough)", ext[core.KeyRoles])
	}
}

// TestClaimsWithoutEmittedKeys_IdentityNoOp is AC-8f: when no top-level
// claim is emitted (or nothing needs removing), the ORIGINAL map identity
// comes back — zero allocation on the single-tenant hot path; the strip
// path returns a copy that leaves the caller's map untouched.
func TestClaimsWithoutEmittedKeys_IdentityNoOp(t *testing.T) {
	t.Parallel()
	// No top-level claims -> original identity.
	claims := map[string]string{"email": "a@example.com"}
	if got := claimsWithoutEmittedKeys(&sso.Subject{Claims: claims}); !trSameMap(got, claims) {
		t.Error("no-emission passthrough must return the original map instance")
	}
	// Tenant bound + key ABSENT -> original identity (no allocation).
	claims2 := map[string]string{"email": "a@example.com"}
	sub2 := &sso.Subject{Claims: claims2, TenantID: "t"}
	if got := claimsWithoutEmittedKeys(sub2); !trSameMap(got, claims2) {
		t.Error("tenant-bound subject with no ext.tenant_id must return the original map")
	}
	// Strip path returns a copy, original untouched.
	claims3 := map[string]string{core.KeyTenantID: "u", "email": "a@example.com"}
	got := claimsWithoutEmittedKeys(&sso.Subject{Claims: claims3, TenantID: "t"})
	if trSameMap(got, claims3) {
		t.Error("strip path must return a copy, not the original map")
	}
	if _, present := got[core.KeyTenantID]; present {
		t.Error("copy still carries tenant_id")
	}
	if got["email"] != "a@example.com" {
		t.Errorf("copy lost unrelated entry: %v", got)
	}
	if claims3[core.KeyTenantID] != "u" {
		t.Error("original map mutated by strip")
	}
}

// trSameMap reports whether a and b are the SAME map instance (identity,
// not equality — the passthrough contract is zero-allocation identity).
func trSameMap(a, b map[string]string) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

func trSortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func trEqualStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
