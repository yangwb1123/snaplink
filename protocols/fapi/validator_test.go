package fapi_test

import (
	"sort"
	"testing"

	"github.com/yangwb1123/snaplink/protocols/fapi"
)

// compliantAuth is a fully FAPI-2.0-compliant authorization context;
// individual tests degrade one field to prove the matching rule fires.
func compliantAuth() fapi.AuthorizationContext {
	return fapi.AuthorizationContext{
		ClientID:            "c1",
		ResponseType:        "code",
		UsedPAR:             true,
		SignedRequest:       true,
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}
}

func ruleIDs(vs []fapi.Violation) []string {
	ids := make([]string, len(vs))
	for i, v := range vs {
		ids[i] = v.RuleID
	}
	sort.Strings(ids)
	return ids
}

func TestCheckAuthorization_CompliantHasNoViolations(t *testing.T) {
	t.Parallel()
	for _, m := range []fapi.Mode{fapi.ModeInspection, fapi.ModeEnforce} {
		v := fapi.New(m)
		if got := v.CheckAuthorization(compliantAuth()); len(got) != 0 {
			t.Errorf("mode=%s: compliant request reported %d violations: %v", m, len(got), got)
		}
	}
}

func TestCheckAuthorization_EachRuleFires(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*fapi.AuthorizationContext)
		want   string
	}{
		{"no PAR", func(a *fapi.AuthorizationContext) { a.UsedPAR = false }, fapi.RulePARRequired},
		{"unsigned request", func(a *fapi.AuthorizationContext) { a.SignedRequest = false }, fapi.RuleSignedRequest},
		{"implicit response_type", func(a *fapi.AuthorizationContext) { a.ResponseType = "token" }, fapi.RuleNoImplicit},
		{"missing PKCE", func(a *fapi.AuthorizationContext) { a.CodeChallenge = "" }, fapi.RulePKCES256},
		{"plain PKCE method", func(a *fapi.AuthorizationContext) { a.CodeChallengeMethod = "plain" }, fapi.RulePKCES256},
	}
	v := fapi.New(fapi.ModeEnforce)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ac := compliantAuth()
			tc.mutate(&ac)
			got := v.CheckAuthorization(ac)
			found := false
			for _, viol := range got {
				if viol.RuleID == tc.want {
					found = true
					if viol.ClientID != ac.ClientID {
						t.Errorf("violation ClientID = %q, want %q", viol.ClientID, ac.ClientID)
					}
					if viol.Detail == "" {
						t.Error("violation Detail must be non-empty (audit/error_description context)")
					}
				}
			}
			if !found {
				t.Errorf("expected rule %q, got %v", tc.want, ruleIDs(got))
			}
		})
	}
}

// TestCheckAuthorization_S256CaseInsensitive guards against an RP
// sending "s256" — the method comparison must be case-insensitive so a
// compliant-but-lowercased request isn't flagged.
func TestCheckAuthorization_S256CaseInsensitive(t *testing.T) {
	t.Parallel()
	ac := compliantAuth()
	ac.CodeChallengeMethod = "s256"
	if got := fapi.New(fapi.ModeEnforce).CheckAuthorization(ac); len(got) != 0 {
		t.Errorf("lowercase s256 should be compliant, got %v", ruleIDs(got))
	}
}

func TestCheckToken_SenderConstraint(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeEnforce)
	if got := v.CheckToken(fapi.TokenContext{ClientID: "c1", SenderConstrained: true}); len(got) != 0 {
		t.Errorf("sender-constrained token should be compliant, got %v", got)
	}
	got := v.CheckToken(fapi.TokenContext{ClientID: "c1", SenderConstrained: false})
	if len(got) != 1 || got[0].RuleID != fapi.RuleSenderConstrained {
		t.Errorf("bearer token must violate %q, got %v", fapi.RuleSenderConstrained, ruleIDs(got))
	}
}

func TestCheckToken_ClientAuth(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeEnforce)
	cases := []struct {
		method   string
		violates bool
	}{
		{fapi.ClientAuthPrivateKeyJWT, false},
		{fapi.ClientAuthTLS, false},
		{fapi.ClientAuthSelfSignedTLS, false},
		{"", false}, // unclassified — skipped
		{fapi.ClientAuthSecretBasic, true},
		{fapi.ClientAuthSecretPost, true},
		{fapi.ClientAuthNone, true},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			// SenderConstrained=true isolates the client-auth rule.
			got := v.CheckToken(fapi.TokenContext{ClientID: "c1", SenderConstrained: true, ClientAuthMethod: tc.method})
			has := false
			for _, viol := range got {
				if viol.RuleID == fapi.RuleClientAuth {
					has = true
					if viol.ClientID != "c1" {
						t.Errorf("ClientID = %q, want c1", viol.ClientID)
					}
					if viol.Detail == "" {
						t.Error("Detail must be non-empty")
					}
				}
			}
			if has != tc.violates {
				t.Errorf("method=%q: client-auth violation = %v, want %v (got %v)", tc.method, has, tc.violates, ruleIDs(got))
			}
		})
	}
}

func TestCheckClientAuth_Standalone(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeEnforce)
	if got := v.CheckClientAuth("c1", fapi.ClientAuthPrivateKeyJWT); len(got) != 0 {
		t.Errorf("private_key_jwt compliant, got %v", ruleIDs(got))
	}
	got := v.CheckClientAuth("c1", fapi.ClientAuthSecretBasic)
	if len(got) != 1 || got[0].RuleID != fapi.RuleClientAuth {
		t.Errorf("secret_basic must violate %q, got %v", fapi.RuleClientAuth, ruleIDs(got))
	}
	var nilV *fapi.Validator
	if got := nilV.CheckClientAuth("c1", fapi.ClientAuthSecretBasic); got != nil {
		t.Errorf("nil validator CheckClientAuth = %v, want nil", got)
	}
}

// TestNilAndOff_NoChecks proves the nil-safe / ModeOff contract the
// integration points rely on to call unconditionally.
func TestNilAndOff_NoChecks(t *testing.T) {
	t.Parallel()
	var nilV *fapi.Validator
	off := fapi.New(fapi.ModeOff)
	for _, v := range []*fapi.Validator{nilV, off} {
		if v.Active() {
			t.Error("nil/off validator must report Active()=false")
		}
		if v.Enforcing() {
			t.Error("nil/off validator must report Enforcing()=false")
		}
		// Degraded context — must still yield nothing.
		if got := v.CheckAuthorization(fapi.AuthorizationContext{}); got != nil {
			t.Errorf("nil/off CheckAuthorization = %v, want nil", got)
		}
		if got := v.CheckToken(fapi.TokenContext{}); got != nil {
			t.Errorf("nil/off CheckToken = %v, want nil", got)
		}
		if v.Mode() != fapi.ModeOff {
			t.Errorf("Mode() = %v, want ModeOff", v.Mode())
		}
	}
}

func TestEnforcing(t *testing.T) {
	t.Parallel()
	if !fapi.New(fapi.ModeEnforce).Enforcing() {
		t.Error("ModeEnforce must report Enforcing()=true")
	}
	if fapi.New(fapi.ModeInspection).Enforcing() {
		t.Error("ModeInspection must report Enforcing()=false")
	}
	if !fapi.New(fapi.ModeInspection).Active() {
		t.Error("ModeInspection must report Active()=true")
	}
}

func TestModeString(t *testing.T) {
	t.Parallel()
	for m, want := range map[fapi.Mode]string{
		fapi.ModeOff:        "off",
		fapi.ModeInspection: "inspection",
		fapi.ModeEnforce:    "enforce",
	} {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", m, got, want)
		}
	}
}

func TestCheckSigningAlg_EnforceMode_RejectsRSA(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeEnforce)

	tests := []struct {
		name string
		alg  string
		want int // expected violation count
	}{
		{"ES256 is allowed", "ES256", 0},
		{"ES384 is allowed", "ES384", 0},
		{"ES512 is allowed", "ES512", 0},
		{"EdDSA is allowed", "EdDSA", 0},
		{"RS256 is rejected", "RS256", 1},
		{"RS384 is rejected", "RS384", 1},
		{"RS512 is rejected", "RS512", 1},
		{"PS256 is rejected", "PS256", 1},
		{"PS384 is rejected", "PS384", 1},
		{"PS512 is rejected", "PS512", 1},
		{"HS256 is rejected", "HS256", 1},
		{"empty alg (no signing) skipped", "", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vs := v.CheckSigningAlg(fapi.SigningAlgContext{
				ClientID:         "test-client",
				RequestObjectAlg: tc.alg,
			})
			if len(vs) != tc.want {
				t.Errorf("CheckSigningAlg(%q) = %d violations, want %d: %+v", tc.alg, len(vs), tc.want, vs)
			}
			if tc.want > 0 && len(vs) > 0 {
				if vs[0].RuleID != fapi.RuleSigningAlg {
					t.Errorf("violation RuleID = %q, want %q", vs[0].RuleID, fapi.RuleSigningAlg)
				}
				if vs[0].ClientID != "test-client" {
					t.Errorf("violation ClientID = %q, want %q", vs[0].ClientID, "test-client")
				}
			}
		})
	}
}

func TestCheckSigningAlg_InspectionMode_Reports(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeInspection)
	vs := v.CheckSigningAlg(fapi.SigningAlgContext{
		ClientID:         "test-client",
		RequestObjectAlg: "RS256",
	})
	if len(vs) != 1 {
		t.Errorf("inspection mode must report RS256 violation, got %d violations", len(vs))
	}
}

func TestCheckSigningAlg_OffMode_Skips(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeOff)
	vs := v.CheckSigningAlg(fapi.SigningAlgContext{
		ClientID:         "test-client",
		RequestObjectAlg: "RS256",
	})
	if len(vs) != 0 {
		t.Errorf("off mode must skip alg checking, got %d violations", len(vs))
	}
}

func TestCheckSigningAlg_NilValidator_Skips(t *testing.T) {
	t.Parallel()
	var v *fapi.Validator
	vs := v.CheckSigningAlg(fapi.SigningAlgContext{
		ClientID:         "test-client",
		RequestObjectAlg: "RS256",
	})
	if len(vs) != 0 {
		t.Errorf("nil validator must skip alg checking, got %d violations", len(vs))
	}
}

func TestCheckSigningAlg_MultipleAlgs(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeEnforce)
	// When multiple alg fields are non-compliant, each should be reported.
	vs := v.CheckSigningAlg(fapi.SigningAlgContext{
		ClientID:           "multi-alg-client",
		RequestObjectAlg:   "RS256",
		IDTokenAlg:         "PS256",
		ClientAssertionAlg: "RS384",
	})
	if len(vs) != 3 {
		t.Errorf("expected 3 violations for 3 non-compliant algs, got %d: %+v", len(vs), vs)
	}
	// All violations should have the correct RuleID.
	for _, v := range vs {
		if v.RuleID != fapi.RuleSigningAlg {
			t.Errorf("violation RuleID = %q, want %q", v.RuleID, fapi.RuleSigningAlg)
		}
	}
}

func TestCheckCIBA_EnforceMode_RejectsNonPush(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeEnforce)

	tests := []struct {
		name   string
		mode   string
		wantVs int
	}{
		{"push mode is allowed", "push", 0},
		{"poll mode is rejected", "poll", 1},
		{"ping mode is rejected", "ping", 1},
		{"empty mode skipped", "", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vs := v.CheckCIBA(fapi.CIBAContext{
				ClientID:     "ciba-client",
				DeliveryMode: tc.mode,
			})
			if len(vs) != tc.wantVs {
				t.Errorf("CheckCIBA(mode=%q) = %d violations, want %d", tc.mode, len(vs), tc.wantVs)
			}
		})
	}
}

func TestFAPIAllowedAlgValues(t *testing.T) {
	t.Parallel()
	// Verify the FAPI allowlist excludes RSA-based algorithms.
	for _, alg := range fapi.FAPIAllowedAlgValues {
		if !fapi.IsFAPIAllowedAlg(alg) {
			t.Errorf("FAPIAllowedAlgValues contains %q but IsFAPIAllowedAlg(%q) = false", alg, alg)
		}
	}
	if fapi.IsFAPIAllowedAlg("RS256") {
		t.Error("RS256 must NOT be allowed in FAPI mode")
	}
	if fapi.IsFAPIAllowedAlg("PS256") {
		t.Error("PS256 must NOT be allowed in FAPI mode")
	}
	if fapi.IsFAPIAllowedAlg("HS256") {
		t.Error("HS256 must NOT be allowed in FAPI mode")
	}
}

func TestAllowedAlgValues_Filter(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeEnforce)
	all := []string{"ES256", "ES384", "RS256", "EdDSA", "PS256", "RS384", "ES512", "PS384", "PS512"}
	filtered := v.AllowedAlgValues(all)
	for _, a := range filtered {
		if !fapi.IsFAPIAllowedAlg(a) {
			t.Errorf("AllowedAlgValues returned non-compliant alg %q", a)
		}
	}
	if len(filtered) != 4 {
		t.Errorf("AllowedAlgValues = %v (len=%d), want exactly 4 FAPI-compliant algs", filtered, len(filtered))
	}
}

func TestAllowedAlgValues_Inspection_Passthrough(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeInspection)
	all := []string{"ES256", "RS256", "EdDSA"}
	got := v.AllowedAlgValues(all)
	if len(got) != len(all) {
		t.Errorf("inspection mode must pass through all algs unchanged; got %v", got)
	}
}

func TestAllowedClientAuthMethods_Enforce_Narrows(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeEnforce)
	all := []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth", "none"}
	filtered := v.AllowedClientAuthMethods(all)
	want := []string{"private_key_jwt", "tls_client_auth"}
	if len(filtered) != len(want) {
		t.Errorf("AllowedClientAuthMethods = %v, want %v", filtered, want)
	}
	for i := range want {
		if filtered[i] != want[i] {
			t.Errorf("AllowedClientAuthMethods[%d] = %q, want %q", i, filtered[i], want[i])
		}
	}
}

func TestAllowedClientAuthMethods_Inspection_Passthrough(t *testing.T) {
	t.Parallel()
	v := fapi.New(fapi.ModeInspection)
	all := []string{"client_secret_basic", "private_key_jwt"}
	got := v.AllowedClientAuthMethods(all)
	if len(got) != len(all) {
		t.Errorf("inspection mode must pass through all methods unchanged; got %v", got)
	}
}

func TestExtractJWTAlg(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		compact string
		wantAlg string
	}{
		{"ES256 JWT", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", "ES256"},
		{"RS256 JWT", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", "RS256"},
		{"EdDSA JWT", "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", "EdDSA"},
		{"empty string", "", ""},
		{"not a JWS", "not-a-jws", ""},
		{"starts with dot", ".header.payload.sig", ""},
		{"no alg header", "eyJ0eXAiOiJKV1QifQ.payload.sig", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fapi.ExtractJWTAlg(tc.compact)
			if got != tc.wantAlg {
				t.Errorf("ExtractJWTAlg(%q) = %q, want %q", tc.compact, got, tc.wantAlg)
			}
		})
	}
}

func TestExtractJWTAlg_PS384(t *testing.T) {
	t.Parallel()
	// PS384: base64url of {"alg":"PS384","typ":"JWT"}
	compact := "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.payload.sig"
	if got := fapi.ExtractJWTAlg(compact); got != "PS384" {
		t.Errorf("ExtractJWTAlg(PS384) = %q, want PS384", got)
	}
}

func TestExtractJWTAlg_HS256Ignored(t *testing.T) {
	t.Parallel()
	// HS256: should still extract correctly even though it's not FAPI-compliant.
	compact := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
	if got := fapi.ExtractJWTAlg(compact); got != "HS256" {
		t.Errorf("ExtractJWTAlg(HS256) = %q, want HS256", got)
	}
}
