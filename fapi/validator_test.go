package fapi_test

import (
	"sort"
	"testing"

	"github.com/snaplink/sso/fapi"
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
	for _, m := range []fapi.Mode{fapi.ModeInspection, fapi.ModeEnforce} {
		v := fapi.New(m)
		if got := v.CheckAuthorization(compliantAuth()); len(got) != 0 {
			t.Errorf("mode=%s: compliant request reported %d violations: %v", m, len(got), got)
		}
	}
}

func TestCheckAuthorization_EachRuleFires(t *testing.T) {
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
	ac := compliantAuth()
	ac.CodeChallengeMethod = "s256"
	if got := fapi.New(fapi.ModeEnforce).CheckAuthorization(ac); len(got) != 0 {
		t.Errorf("lowercase s256 should be compliant, got %v", ruleIDs(got))
	}
}

func TestCheckToken_SenderConstraint(t *testing.T) {
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
