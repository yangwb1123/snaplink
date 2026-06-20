package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestJoinScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"openid"}, "openid"},
		{[]string{"openid", "profile", "email"}, "openid profile email"},
	}
	for _, tc := range tests {
		if got := JoinScope(tc.in); got != tc.want {
			t.Errorf("JoinScope(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSplitScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"openid", []string{"openid"}},
		{"openid profile email", []string{"openid", "profile", "email"}},
	}
	for _, tc := range tests {
		got := SplitScope(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("SplitScope(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestSplitJoinRoundTrip confirms split→join is the identity on a clean,
// space-delimited scope string (the wire round-trip the handlers rely on).
func TestSplitJoinRoundTrip(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"openid", "openid profile", "a b c d"} {
		if got := JoinScope(SplitScope(s)); got != s {
			t.Errorf("round trip %q -> %q", s, got)
		}
	}
}

func TestEntityIsExpired(t *testing.T) {
	t.Parallel()
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	tests := []struct {
		name    string
		expired func() bool
		want    bool
	}{
		{"authcode past", func() bool { return (&AuthCode{ExpiresAt: past}).IsExpired() }, true},
		{"authcode future", func() bool { return (&AuthCode{ExpiresAt: future}).IsExpired() }, false},
		{"par past", func() bool { return (&PARRequest{ExpiresAt: past}).IsExpired() }, true},
		{"par future", func() bool { return (&PARRequest{ExpiresAt: future}).IsExpired() }, false},
		{"refresh past", func() bool { return (&RefreshToken{ExpiresAt: past}).IsExpired() }, true},
		{"refresh future", func() bool { return (&RefreshToken{ExpiresAt: future}).IsExpired() }, false},
		{"device past", func() bool { return (&DeviceCode{ExpiresAt: past}).IsExpired() }, true},
		{"device future", func() bool { return (&DeviceCode{ExpiresAt: future}).IsExpired() }, false},
		{"ciba past", func() bool { return (&CIBARequest{ExpiresAt: past}).IsExpired() }, true},
		{"ciba future", func() bool { return (&CIBARequest{ExpiresAt: future}).IsExpired() }, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.expired(); got != tc.want {
				t.Errorf("%s IsExpired() = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestValidateClaimsParameter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"empty", ``, false},
		{"valid null entries", `{"userinfo":{"email":null},"id_token":{"sub":null}}`, false},
		{"valid essential bool", `{"id_token":{"acr":{"essential":true}}}`, false},
		{"valid values array", `{"id_token":{"acr":{"values":["a","b"]}}}`, false},
		{"valid value primitive", `{"userinfo":{"name":{"value":"Alice"}}}`, false},
		{"extension members ignored", `{"userinfo":{"email":{"x_custom":42}}}`, false},
		{"not an object", `["nope"]`, true},
		{"section not object", `{"userinfo":["x"]}`, true},
		{"entry not null or object", `{"userinfo":{"email":"bad"}}`, true},
		{"essential wrong type", `{"id_token":{"acr":{"essential":"yes"}}}`, true},
		{"values wrong type", `{"id_token":{"acr":{"values":"notarray"}}}`, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateClaimsParameter(json.RawMessage(tc.raw))
			if tc.wantErr && err == nil {
				t.Errorf("ValidateClaimsParameter(%s) want error, got nil", tc.raw)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateClaimsParameter(%s) unexpected error: %v", tc.raw, err)
			}
		})
	}
}

func TestRequestedACRFromClaims(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", ``, nil},
		{"no acr entry", `{"id_token":{"sub":null}}`, nil},
		{"acr null entry", `{"id_token":{"acr":null}}`, nil},
		{"single value", `{"id_token":{"acr":{"value":"urn:1"}}}`, []string{"urn:1"}},
		{"values array", `{"id_token":{"acr":{"values":["urn:1","urn:2"]}}}`, []string{"urn:1", "urn:2"}},
		{"value plus values union", `{"id_token":{"acr":{"value":"urn:0","values":["urn:1"]}}}`, []string{"urn:0", "urn:1"}},
		{"empty string skipped", `{"id_token":{"acr":{"value":""}}}`, nil},
		{"non-string value skipped", `{"id_token":{"acr":{"value":42}}}`, nil},
		{"malformed fails open to nil", `{not json`, nil},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := RequestedACRFromClaims(json.RawMessage(tc.raw))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("RequestedACRFromClaims(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestParseRequestedClaimsErrors exercises the error branches not covered by
// the happy-path tests in claims_param_test.go.
func TestParseRequestedClaimsErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
	}{
		{"top not object", `42`},
		{"section not object", `{"id_token":42}`},
		{"entry neither null nor object", `{"id_token":{"sub":"oops"}}`},
		{"essential bad type", `{"id_token":{"acr":{"essential":"yes"}}}`},
		{"values bad type", `{"id_token":{"acr":{"values":"x"}}}`},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ParseRequestedClaims(json.RawMessage(tc.raw)); err == nil {
				t.Errorf("ParseRequestedClaims(%s) want error, got nil", tc.raw)
			}
		})
	}
}

func TestParseRequestedClaimsEmptySection(t *testing.T) {
	t.Parallel()
	// An explicitly-empty section ({}) yields a nil map, not an empty one.
	id, ui, err := ParseRequestedClaims(json.RawMessage(`{"id_token":{},"userinfo":{}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != nil || ui != nil {
		t.Errorf("empty sections should map to nil, got id=%v ui=%v", id, ui)
	}
}

// TestCIBAPingNotifierFunc confirms the function adapter forwards its args.
func TestCIBAPingNotifierFunc(t *testing.T) {
	t.Parallel()
	var gotClient, gotID, gotTok string
	sentinel := errors.New("notify failed")
	f := CIBAPingNotifierFunc(func(_ context.Context, clientID, authReqID, tok string) error {
		gotClient, gotID, gotTok = clientID, authReqID, tok
		return sentinel
	})
	err := f.Notify(context.Background(), "client-1", "ciba_42", "tok-x")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
	if gotClient != "client-1" || gotID != "ciba_42" || gotTok != "tok-x" {
		t.Errorf("forwarded args = %q/%q/%q", gotClient, gotID, gotTok)
	}
}

// TestCIBATransportFunc confirms the function adapter forwards its args.
func TestCIBATransportFunc(t *testing.T) {
	t.Parallel()
	var gotID, gotSub string
	var gotMeta map[string]string
	f := CIBATransportFunc(func(_ context.Context, authReqID, subjectID string, meta map[string]string) error {
		gotID, gotSub, gotMeta = authReqID, subjectID, meta
		return nil
	})
	if err := f.Send(context.Background(), "ciba_9", "user-7", map[string]string{"binding_message": "1234"}); err != nil {
		t.Fatalf("Send err = %v", err)
	}
	if gotID != "ciba_9" || gotSub != "user-7" || gotMeta["binding_message"] != "1234" {
		t.Errorf("forwarded args = %q/%q/%v", gotID, gotSub, gotMeta)
	}
}

func TestGenerateClientIDAndSecret(t *testing.T) {
	t.Parallel()
	id1, err := GenerateClientID()
	if err != nil || id1 == "" {
		t.Fatalf("GenerateClientID() = %q, %v", id1, err)
	}
	id2, _ := GenerateClientID()
	if id1 == id2 {
		t.Error("GenerateClientID() returned duplicate values")
	}
	s1, err := GenerateClientSecret()
	if err != nil || s1 == "" {
		t.Fatalf("GenerateClientSecret() = %q, %v", s1, err)
	}
	s2, _ := GenerateClientSecret()
	if s1 == s2 {
		t.Error("GenerateClientSecret() returned duplicate values")
	}
}

// TestConstants pins the protocol constants the handlers branch on so a
// silent edit surfaces as a test failure.
func TestProtocolConstants(t *testing.T) {
	t.Parallel()
	if GrantCIBA != "urn:openid:params:grant-type:ciba" {
		t.Errorf("GrantCIBA = %q", GrantCIBA)
	}
	if ClientAssertionTypeJWTBearer != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("ClientAssertionTypeJWTBearer = %q", ClientAssertionTypeJWTBearer)
	}
	if PARURIPrefix != "urn:ietf:params:oauth:request_uri:" {
		t.Errorf("PARURIPrefix = %q", PARURIPrefix)
	}
	if AuthReqIDPrefix != "ciba_" {
		t.Errorf("AuthReqIDPrefix = %q", AuthReqIDPrefix)
	}
}
